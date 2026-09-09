"""UPnP / SSDP / SOAP exploit simulation (localhost only)."""

from __future__ import annotations

import re
import socket
import struct
import threading
import xml.etree.ElementTree as ET
from typing import Any

from .common import LAB_HOST, assert_lab_target, random_mac, random_ip_lab, utcnow_iso

# ---- SSDP constants ----
SSDP_MULTICAST = "239.255.255.250"
SSDP_PORT = 1900
NOTIFY_ALIVE = "ssdp:alive"
NOTIFY_BYEBYE = "ssdp:byebye"

# ---- Device description template (XML) ----
DEVICE_DESCRIPTION_XML = """\
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:IoTGateway:1</deviceType>
    <friendlyName>{friendly_name}</friendlyName>
    <manufacturer>LabRouter Inc.</manufacturer>
    <modelName>IoT-GW-1000</modelName>
    <modelNumber>v2.1-lab</modelNumber>
    <serialNumber>{serial}</serialNumber>
    <MACAddress>{mac}</MACAddress>
    <presentationURL>http://{ip}:{port}/</presentationURL>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <SCPDURL>/WANIPConn.xml</SCPDURL>
        <controlURL>/ctrl</controlURL>
        <eventSubURL>/event</eventSubURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:HNAP:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:HNAP1</serviceId>
        <SCPDURL>/HNAP.xml</SCPDURL>
        <controlURL>/hnap</controlURL>
        <eventSubURL>/event</eventSubURL>
      </service>
    </serviceList>
  </device>
</root>"""

# ---- HNAP-style SOAP exploit payload (routersploit iodine-style demo) ----
HNAP_SOAP_INJECT = """\
<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
  s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:ApplyDDNSSettings xmlns:u="urn:schemas-upnp-org:service:HNAP:1">
      <HNAPAuth>admin</HNAPAuth>
      <URLType>dns</URLType>
      <HostDomain>192.0.2.50</HostDomain>
      <Username>admin</Username>
      <Password>`id`</Password>
    </u:ApplyDDNSSettings>
  </s:Body>
</s:Envelope>"""

SOAP_RESPONSE_TEMPLATE = """\
<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:{action}Response xmlns:u="urn:schemas-upnp-org:service:HNAP:1">
      <Result>OK</Result>
    </u:{action}Response>
  </s:Body>
</s:Envelope>"""


# ============================================================================
# SSDP helpers
# ============================================================================

def build_ssdp_discover() -> bytes:
    """Build SSDP M-SEARCH request."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 3\r\n"
        "ST: urn:schemas-upnp-org:device:IoTGateway:1\r\n"
        "\r\n"
    )
    return msg.encode()


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    """Parse SSDP NOTIFY/M-SEARCH response headers."""
    text = data.decode("utf-8", errors="replace")
    lines = text.strip().split("\r\n")
    result: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            result[key.strip().upper()] = val.strip()
    if lines:
        result["_STATUS_LINE"] = lines[0]
    return result


def build_ssdp_notify(
    usn: str, location: str, server: str = "LabRouter/1.0 UPnP/1.1",
    nt: str = "urn:schemas-upnp-org:device:IoTGateway:1",
    mx: int = 1800,
) -> bytes:
    """Build SSDP NOTIFY ALIVE."""
    msg = (
        "NOTIFY * HTTP/1.1\r\n"
        f"HOST: {SSDP_MULTICAST}:{SSDP_PORT}\r\n"
        f"CACHE-CONTROL: max-age={mx}\r\n"
        f"LOCATION: {location}\r\n"
        f"NT: {nt}\r\n"
        f"NTS: {NOTIFY_ALIVE}\r\n"
        f"SERVER: {server}\r\n"
        f"USN: {usn}\r\n"
        "\r\n"
    )
    return msg.encode()


# ============================================================================
# Device Description parser
# ============================================================================

def parse_device_description(xml_text: str) -> dict[str, Any]:
    """Parse UPnP device description XML into flat dict."""
    result: dict[str, Any] = {}
    try:
        root = ET.fromstring(xml_text)
        ns = {"d": "urn:schemas-upnp-org:device-1-0"}
        for tag in ["friendlyName", "manufacturer", "modelName", "modelNumber",
                     "serialNumber", "MACAddress", "presentationURL"]:
            el = root.find(f".//d:{tag}", ns)
            if el is None:
                el = root.find(f".//{tag}")
            result[tag] = el.text if el is not None else None
        # Services
        services = []
        for svc in root.findall(".//d:service", ns):
            if svc is None:
                svc_list = root.findall(".//service")
                if not svc_list:
                    break
                svc = svc_list[0] if svc_list else None
            if svc is not None:
                s = {}
                for child in svc:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    s[tag] = child.text
                services.append(s)
        result["services"] = services
    except ET.ParseError:
        result["parse_error"] = True
    return result


# ============================================================================
# SOAP Command Injection parser
# ============================================================================

def parse_soap_request(xml_text: str) -> dict[str, Any]:
    """Parse SOAP request, extract action + parameters (detect injection)."""
    result: dict[str, Any] = {"injection_detected": False, "injections": []}
    try:
        root = ET.fromstring(xml_text)
        body = root.find(".//{http://schemas.xmlsoap.org/soap/envelope/}Body")
        if body is None:
            body = root.find(".//Body")
        if body is None:
            return result
        for child in body:
            tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            result["action"] = tag
            for param in child:
                ptag = param.tag.split("}")[-1] if "}" in param.tag else param.tag
                pval = param.text or ""
                result[ptag] = pval
                # Detect backtick command injection
                if "`" in pval or "$(" in pval or ";" in pval:
                    result["injection_detected"] = True
                    result["injections"].append({"param": ptag, "value": pval})
    except ET.ParseError:
        result["parse_error"] = True
    return result


def build_soap_response(action: str) -> bytes:
    return SOAP_RESPONSE_TEMPLATE.format(action=action).encode()


# ============================================================================
# UPnP / HNAP Simulator (localhost TCP)
# ============================================================================

class UPnPSim:
    """
    Simulates a UPnP device with SSDP + device description + HNAP SOAP endpoint.
    The HNAP endpoint is deliberately vulnerable to command injection (lab demo).
    """

    def __init__(self, host: str = LAB_HOST, tcp_port: int = 11900,
                 ssdp_port: int = 11901):
        assert_lab_target(host)
        self.host = host
        self.tcp_port = tcp_port
        self.ssdp_port = ssdp_port
        self._tcp_sock: socket.socket | None = None
        self._udp_sock: socket.socket | None = None
        self._running = False
        self._threads: list[threading.Thread] = []
        self._mac = random_mac()
        self._serial = "LAB-SERIAL-0001"
        self._soap_log: list[dict] = []
        self.injection_triggered = False

    def start(self) -> None:
        # TCP server for device description + SOAP
        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.settimeout(0.5)
        self._tcp_sock.bind((self.host, self.tcp_port))
        self.tcp_port = self._tcp_sock.getsockname()[1]
        self._tcp_sock.listen(5)
        self._running = True

        t1 = threading.Thread(target=self._run_tcp, daemon=True)
        t1.start()
        self._threads.append(t1)

        # UDP SSDP responder
        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_sock.settimeout(0.5)
        self._udp_sock.bind(("", self.ssdp_port))
        self.ssdp_port = self._udp_sock.getsockname()[1]
        t2 = threading.Thread(target=self._run_ssdp, daemon=True)
        t2.start()
        self._threads.append(t2)

    def stop(self) -> None:
        self._running = False
        for t in self._threads:
            t.join(timeout=3)
        if self._tcp_sock:
            self._tcp_sock.close()
        if self._udp_sock:
            self._udp_sock.close()

    def _run_ssdp(self) -> None:
        while self._running:
            try:
                data, addr = self._udp_sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if b"M-SEARCH" in data:
                location = f"http://{self.host}:{self.tcp_port}/device.xml"
                usn = f"uuid:lab-{self._mac.replace(':', '')}::urn:schemas-upnp-org:device:IoTGateway:1"
                resp = build_ssdp_notify(usn, location)
                try:
                    self._udp_sock.sendto(resp, addr)
                except OSError:
                    break

    def _run_tcp(self) -> None:
        while self._running:
            try:
                conn, addr = self._tcp_sock.accept()
                conn.settimeout(2)
                t = threading.Thread(target=self._handle_tcp, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            data = conn.recv(4096)
            if not data:
                return
            request = data.decode("utf-8", errors="replace")
            lines = request.split("\r\n")
            if not lines:
                return
            req_line = lines[0]
            parts = req_line.split()
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else ""

            if method == "GET" and "/device.xml" in path:
                xml = self._get_device_description()
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/xml\r\n"
                    f"Content-Length: {len(xml)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode() + xml
                conn.sendall(resp)

            elif method == "POST" and "/hnap" in path:
                body_start = data.find(b"\r\n\r\n")
                body = data[body_start + 4 :].decode("utf-8", errors="replace") if body_start >= 0 else ""
                parsed = parse_soap_request(body)
                self._soap_log.append(parsed)
                if parsed.get("injection_detected"):
                    self.injection_triggered = True
                action = parsed.get("action", "Unknown")
                resp_body = build_soap_response(action)
                resp = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/xml\r\n"
                    f"Content-Length: {len(resp_body)}\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode() + resp_body
                conn.sendall(resp)
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            conn.close()

    def _get_device_description(self) -> bytes:
        return DEVICE_DESCRIPTION_XML.format(
            friendly_name="Lab IoT Gateway",
            serial=self._serial,
            mac=self._mac,
            ip=self.host,
            port=self.tcp_port,
        ).encode()


# ============================================================================
# Client helpers
# ============================================================================

def upnp_discover(host: str = LAB_HOST, ssdp_port: int = 11901,
                  timeout: float = 2.0) -> dict[str, str]:
    """Send SSDP M-SEARCH and parse response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    msearch = build_ssdp_discover()
    sock.sendto(msearch, (SSDP_MULTICAST, ssdp_port))
    try:
        data, _ = sock.recvfrom(4096)
        return parse_ssdp_response(data)
    except socket.timeout:
        return {}
    finally:
        sock.close()


def upnp_get_description(host: str, port: int) -> dict[str, Any]:
    """GET /device.xml and parse."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    sock.sendall(f"GET /device.xml HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.close()
    body_start = data.find(b"\r\n\r\n")
    body = data[body_start + 4 :].decode("utf-8", errors="replace") if body_start >= 0 else ""
    return parse_device_description(body)


def upnp_hnap_inject(host: str, port: int) -> dict[str, Any]:
    """Send SOAP command injection payload to HNAP endpoint."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    body = HNAP_SOAP_INJECT
    req = (
        f"POST /hnap HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: text/xml\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
        f"{body}"
    )
    sock.sendall(req.encode())
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.close()
    return {"response": data.decode("utf-8", errors="replace"), "status": "sent"}
