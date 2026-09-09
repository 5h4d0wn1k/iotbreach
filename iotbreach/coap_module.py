"""CoAP (RFC 7252) packet builder, parser, and UDP simulator (localhost only)."""

from __future__ import annotations

import hashlib
import json
import secrets
import socket
import struct
import threading
from typing import Any

from .common import LAB_HOST, assert_lab_target, sha256, utcnow_iso

# ---- CoAP message types ----
CON = 0  # Confirmable
NON = 1  # Non-confirmable
ACK = 2  # Acknowledgement
RST = 3  # Reset

TYPE_NAMES = {CON: "CON", NON: "NON", ACK: "ACK", RST: "RST"}

# ---- CoAP methods ----
GET = 1
POST = 2
PUT = 3
DELETE = 4

METHOD_NAMES = {GET: "GET", POST: "POST", PUT: "PUT", DELETE: "DELETE"}

# ---- CoAP response codes ----
CODE_2_01 = 0x41  # 2.01 Created
CODE_2_02 = 0x42  # 2.02 Deleted
CODE_2_03 = 0x43  # 2.03 Valid
CODE_2_04 = 0x44  # 2.04 Changed
CODE_2_05 = 0x45  # 2.05 Content
CODE_4_00 = 0x80  # 4.00 Bad Request
CODE_4_04 = 0x84  # 4.04 Not Found
CODE_4_05 = 0x85  # 4.05 Method Not Allowed
CODE_5_00 = 0xA0  # 5.00 Internal Server Error

# ---- Option numbers ----
OPT_IF_MATCH = 1      # If-Match
OPT_URI_HOST = 3      # Uri-Host
OPT_ETAG = 4          # ETag
OPT_IF_NONE_MATCH = 5 # If-None-Match
OPT_URI_PORT = 7      # Uri-Port
OPT_LOCATION_PATH = 8 # Location-Path
OPT_URI_PATH = 11     # Uri-Path
OPT_CONTENT_FORMAT = 12  # Content-Format
OPT_MAX_AGE = 14      # Max-Age
OPT_URI_QUERY = 15    # Uri-Query
OPT_ACCEPT = 17       # Accept
OPT_LOCATION_QUERY = 20  # Location-Query
OPT_SIZE2 = 28        # Size2

# Content formats
CF_TEXT = 0
CF_JSON = 50
CF_OCTET = 42
CF_CBOR = 60


# ============================================================================
# Codec helpers
# ============================================================================

def _encode_uint(value: int, nbytes: int) -> bytes:
    """Encode unsigned integer to big-endian bytes of given length."""
    return value.to_bytes(nbytes, "big")


def _decode_uint(data: bytes) -> int:
    """Decode big-endian bytes to unsigned integer."""
    return int.from_bytes(data, "big")


def _extended_nibble(value: int) -> tuple[int, bytes]:
    """Return (nibble_value, extra_bytes) for an option delta/length field."""
    if value <= 12:
        return value, b""
    elif value <= 255:
        return 13, bytes([value - 13])
    elif value <= 65535:
        return 14, struct.pack("!H", value - 269)
    else:
        return 15, struct.pack("!I", value - 65805)


def _build_option_header(delta: int, length: int) -> bytes:
    d, d_bytes = _extended_nibble(delta)
    l, l_bytes = _extended_nibble(length)
    return bytes([(d << 4) | l]) + d_bytes + l_bytes


def _decode_option_header(byte: int, extra: bytes) -> tuple[int, int, int]:
    """Decode (delta, length, consumed) from first header byte + extra bytes."""
    d = (byte >> 4) & 0x0F
    l = byte & 0x0F
    pos = 0
    if d == 13:
        d = 13 + extra[0]
        pos += 1
    elif d == 14:
        d = 269 + struct.unpack("!H", extra[pos : pos + 2])[0]
        pos += 2
    elif d == 15:
        d = 65805 + struct.unpack("!I", extra[pos : pos + 4])[0]
        pos += 4
    if l == 13:
        l = 13 + extra[pos]
        pos += 1
    elif l == 14:
        l = 269 + struct.unpack("!H", extra[pos : pos + 2])[0]
        pos += 2
    elif l == 15:
        l = 65805 + struct.unpack("!I", extra[pos : pos + 4])[0]
        pos += 4
    return d, l, pos


# ============================================================================
# Packet builder
# ============================================================================

def build_message(
    msg_type: int,
    code: int,
    msg_id: int,
    token: bytes | None = None,
    options: list[tuple[int, bytes]] | None = None,
    payload: bytes = b"",
    version: int = 1,
) -> bytes:
    """Build a CoAP message per RFC 7252."""
    # Byte 0: Ver(2) | Type(2) | TKL(4)
    tkl = len(token) if token else 0
    byte0 = (version << 6) | (msg_type << 4) | (tkl & 0x0F)

    # Byte 1: Code
    header = bytes([byte0, code, msg_id >> 8, msg_id & 0xFF])
    if token:
        header += token

    # Options (sorted by option number, delta-encoded)
    opt_data = b""
    if options:
        sorted_opts = sorted(options, key=lambda x: x[0])
        prev = 0
        for num, val in sorted_opts:
            delta = num - prev
            opt_data += _build_option_header(delta, len(val))
            opt_data += val
            prev = num

    # Payload marker (0xFF) + payload
    if payload:
        opt_data += b"\xff" + payload

    return header + opt_data


# ============================================================================
# Packet parser
# ============================================================================

def parse_message(data: bytes) -> dict[str, Any]:
    """Parse a CoAP message into a dict."""
    if len(data) < 4:
        raise ValueError("CoAP message too short")

    byte0 = data[0]
    version = (byte0 >> 6) & 0x03
    msg_type = (byte0 >> 4) & 0x03
    tkl = byte0 & 0x0F
    code = data[1]
    msg_id = (data[2] << 8) | data[3]

    offset = 4
    token = None
    if tkl > 0:
        token = data[offset : offset + tkl]
        offset += tkl

    # Parse options
    options = []
    prev_num = 0
    while offset < len(data):
        if data[offset] == 0xFF:
            offset += 1
            break
        header_byte = data[offset]
        offset += 1
        delta_val, length_val, consumed = _decode_option_header(header_byte, data[offset:])
        offset += consumed
        opt_val = data[offset : offset + length_val]
        offset += length_val
        opt_num = prev_num + delta_val
        options.append((opt_num, opt_val))
        prev_num = opt_num

    payload = data[offset:] if offset < len(data) else b""

    # Decode helper fields
    code_major = code >> 5
    code_minor = code & 0x1F
    code_str = f"{code_major}.{code_minor:02d}"

    uri_path = b""
    content_format = None
    opt_list = []
    for num, val in options:
        opt_list.append({"number": num, "value": val.hex()})
        if num == OPT_URI_PATH:
            uri_path += val + b"/"
        elif num == OPT_CONTENT_FORMAT and len(val) <= 2:
            cf = _decode_uint(val) if val else 0
            content_format = cf

    return {
        "version": version,
        "type": msg_type,
        "type_name": TYPE_NAMES.get(msg_type, f"UNK({msg_type})"),
        "tkl": tkl,
        "token": token.hex() if token else None,
        "code": code,
        "code_str": code_str,
        "method": METHOD_NAMES.get(code) if code in METHOD_NAMES else None,
        "msg_id": msg_id,
        "uri_path": uri_path.rstrip(b"/").decode("utf-8", errors="replace"),
        "content_format": content_format,
        "options": opt_list,
        "payload": payload,
        "payload_hex": payload.hex(),
        "raw": data.hex(),
    }


# ============================================================================
# Convenience builders
# ============================================================================

def build_get(path: str, msg_id: int = 1, token: bytes | None = None) -> bytes:
    opts = [(OPT_URI_PATH, p.encode()) for p in path.strip("/").split("/")]
    return build_message(CON, GET, msg_id, token=token, options=opts)


def build_post(path: str, payload: bytes, msg_id: int = 1, token: bytes | None = None) -> bytes:
    opts = [(OPT_URI_PATH, p.encode()) for p in path.strip("/").split("/")]
    return build_message(CON, POST, msg_id, token=token, options=opts, payload=payload)


def build_put(path: str, payload: bytes, msg_id: int = 1, token: bytes | None = None,
              content_format: int = CF_OCTET) -> bytes:
    opts = [
        *[(OPT_URI_PATH, p.encode()) for p in path.strip("/").split("/")],
        (OPT_CONTENT_FORMAT, _encode_uint(content_format, 1)),
    ]
    return build_message(CON, PUT, msg_id, token=token, options=opts, payload=payload)


def build_well_known_core() -> bytes:
    """Build .well-known/core discovery response."""
    resources = (
        "</sensor/temperature>;ct=0,"
        "</sensor/humidity>;ct=0,"
        "</firmware/current>;ct=42,"
        "</firmware/update>;ct=42,"
        "</admin/config>;ct=50"
    )
    return resources.encode()


# ============================================================================
# CoAP Simulator  (localhost UDP)
# ============================================================================

class CoAPSim:
    """
    Minimal CoAP server sim on localhost UDP.
    Provides resource discovery + firmware update endpoint.
    Demonstrates firmware binary swap + hash change acceptance.
    """

    def __init__(self, host: str = LAB_HOST, port: int = 15683):
        assert_lab_target(host)
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        # Firmware state
        self.firmware_binary = b"\x89PNG" + secrets.token_bytes(64)  # fake fw image
        self.firmware_hash = sha256(self.firmware_binary)
        self.firmware_accepted = False
        # Resources
        self.resources: dict[str, bytes] = {
            "sensor/temperature": b"\x1a\x2b\x3c",
            "sensor/humidity": b"\x55\x66",
            "firmware/current": b"v1.0.0-lab",
            "admin/config": json.dumps({"admin": "lab-admin-123"}).encode(),
        }
        self.telemetry_log: list[dict] = []

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(0.5)
        self._sock.bind((self.host, self.port))
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            self._sock.close()

    def _run(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                response = self._handle(data)
                self._sock.sendto(response, addr)
            except Exception:
                pass

    def _handle(self, data: bytes) -> bytes:
        msg = parse_message(data)
        path = msg["uri_path"]
        code = msg["code"]

        # .well-known/core
        if path == ".well-known/core" and code == GET:
            return self._respond(msg, CODE_2_05, build_well_known_core())

        # GET resources
        if code == GET:
            if path == "firmware/verify":
                result = json.dumps({
                    "hash": self.firmware_hash,
                    "accepted": self.firmware_accepted,
                    "binary_len": len(self.firmware_binary),
                }).encode()
                return self._respond(msg, CODE_2_05, result)
            if path in self.resources:
                return self._respond(msg, CODE_2_05, self.resources[path])
            return self._respond(msg, CODE_4_04, b"Not Found")

        # Firmware update (PUT)
        if code == PUT and path == "firmware/update":
            new_binary = msg["payload"]
            new_hash = sha256(new_binary)
            self.firmware_binary = new_binary
            old_hash = self.firmware_hash
            self.firmware_hash = new_hash
            self.firmware_accepted = True
            self.telemetry_log.append({
                "event": "firmware_update_accepted",
                "old_hash": old_hash,
                "new_hash": new_hash,
                "timestamp": utcnow_iso(),
            })
            return self._respond(msg, CODE_2_04, b"")

        # POST to firmware/verify
        if code == POST and path == "firmware/verify":
            result = json.dumps({
                "hash": self.firmware_hash,
                "accepted": self.firmware_accepted,
                "binary_len": len(self.firmware_binary),
            }).encode()
            return self._respond(msg, CODE_2_05, result)

        return self._respond(msg, CODE_4_05, b"Method Not Allowed")

    def _respond(self, req: dict, code: int, payload: bytes) -> bytes:
        token = bytes.fromhex(req["token"]) if req.get("token") else None
        return build_message(
            ACK, code, req["msg_id"],
            token=token,
            payload=payload,
        )


# ============================================================================
# Client helpers
# ============================================================================

def coap_get(host: str, port: int, path: str, msg_id: int = 1) -> dict:
    """Send a CoAP GET, return parsed response."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    req = build_get(path, msg_id)
    sock.sendto(req, (host, port))
    data, _ = sock.recvfrom(4096)
    sock.close()
    return parse_message(data)


def coap_put(host: str, port: int, path: str, payload: bytes, msg_id: int = 1) -> dict:
    """Send a CoAP PUT, return parsed response."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    req = build_put(path, payload, msg_id)
    sock.sendto(req, (host, port))
    data, _ = sock.recvfrom(4096)
    sock.close()
    return parse_message(data)
