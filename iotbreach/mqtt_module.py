"""MQTT 3.1.1 packet builder, parser, and broker simulator (localhost only)."""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from typing import Any

from .common import LAB_HOST, assert_lab_target, hexdump, sha256, utcnow_iso

# ---- MQTT 3.1.1 constants ----
CONNECT = 1
CONNACK = 2
PUBLISH = 3
PUBACK = 4
SUBSCRIBE = 8
SUBACK = 9
PINGREQ = 12
PINGRESP = 13
DISCONNECT = 14

QOS_LEVELS = {0: "At most once", 1: "At least once", 2: "Exactly once"}

# ============================================================================
# Remaining-length codec  (MSB-encoded variable-length, 1-4 bytes)
# ============================================================================

def encode_remaining_length(length: int) -> bytes:
    """Encode remaining length per MQTT 3.1.1 §2.2.3."""
    out = bytearray()
    while True:
        byte = length % 128
        length = length // 128
        if length > 0:
            byte |= 0x80
        out.append(byte)
        if length == 0:
            break
    return bytes(out)


def decode_remaining_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode remaining length, return (value, new_offset)."""
    multiplier = 1
    value = 0
    idx = offset
    while idx < len(data):
        byte = data[idx]
        value += (byte & 0x7F) * multiplier
        if (byte & 0x80) == 0:
            return value, idx + 1
        multiplier *= 128
        idx += 1
    raise ValueError("Malformed remaining length")


# ============================================================================
# Packet builders
# ============================================================================

def build_connect(
    client_id: str,
    username: str | None = None,
    password: bytes | None = None,
    will_topic: str | None = None,
    will_payload: bytes | None = None,
    clean_session: bool = True,
    keep_alive: int = 60,
) -> bytes:
    """Build MQTT CONNECT packet."""
    # Variable header
    var_header = bytearray()
    # Protocol name
    var_header += struct.pack("!H", 4)  # protocol name length
    var_header += b"MQTT"
    var_header.append(4)  # protocol level (3.1.1)
    # Connect flags
    flags = 0
    if clean_session:
        flags |= 0x02
    if will_topic:
        flags |= 0x04
        if will_payload:
            flags |= 0x18  # will QoS 1 + will retain
    if password:
        flags |= 0x80
    if username:
        flags |= 0x40
    var_header.append(flags)
    var_header += struct.pack("!H", keep_alive)

    # Payload
    payload = bytearray()
    payload += _utf8_pair(client_id)
    if will_topic:
        payload += _utf8_pair(will_topic)
        if will_payload:
            payload += struct.pack("!H", len(will_payload))
            payload += will_payload
    if username:
        payload += _utf8_pair(username)
    if password:
        payload += struct.pack("!H", len(password))
        payload += password

    # Fixed header
    remaining = bytes(var_header) + bytes(payload)
    return bytes([CONNECT << 4]) + encode_remaining_length(len(remaining)) + remaining


def build_connack(session_present: bool = False, return_code: int = 0) -> bytes:
    flags = 0x01 if session_present else 0x00
    return bytes([CONNACK << 4, 2, flags, return_code])


def build_publish(
    topic: str,
    payload: bytes,
    qos: int = 0,
    retain: bool = False,
    packet_id: int | None = None,
) -> bytes:
    """Build MQTT PUBLISH packet."""
    byte0 = (PUBLISH << 4) | (qos << 1)
    if retain:
        byte0 |= 0x01
    var_header = bytearray()
    var_header += _utf8_pair(topic)
    if qos > 0:
        if packet_id is None:
            packet_id = 1
        var_header += struct.pack("!H", packet_id)

    remaining = bytes(var_header) + payload
    return bytes([byte0]) + encode_remaining_length(len(remaining)) + remaining


def build_puback(packet_id: int) -> bytes:
    return bytes([PUBACK << 4, 2]) + struct.pack("!H", packet_id)


def build_subscribe(packet_id: int, topic: str, qos: int = 0) -> bytes:
    var_header = struct.pack("!H", packet_id)
    payload = _utf8_pair(topic) + bytes([qos])
    remaining = var_header + payload
    return bytes([SUBSCRIBE << 4 | 0x02]) + encode_remaining_length(len(remaining)) + remaining


def build_suback(packet_id: int, return_codes: list[int]) -> bytes:
    remaining = struct.pack("!H", packet_id) + bytes(return_codes)
    return bytes([SUBACK << 4]) + encode_remaining_length(len(remaining)) + remaining


def build_pingreq() -> bytes:
    return bytes([PINGREQ << 4, 0])


def build_pingresp() -> bytes:
    return bytes([PINGRESP << 4, 0])


def build_disconnect() -> bytes:
    return bytes([DISCONNECT << 4, 0])


# ============================================================================
# Packet parser
# ============================================================================

def parse_packet(data: bytes) -> dict[str, Any]:
    """Parse a single MQTT packet from raw bytes. Returns dict with fields."""
    if len(data) < 2:
        raise ValueError("Packet too short")
    byte0 = data[0]
    pkt_type = (byte0 >> 4) & 0x0F
    flags = byte0 & 0x0F
    remaining_len, offset = decode_remaining_length(data, 1)
    body = data[offset : offset + remaining_len]

    result: dict[str, Any] = {"type": pkt_type, "type_name": _type_name(pkt_type), "flags": flags}

    if pkt_type == CONNACK:
        result["session_present"] = bool(body[0] & 0x01)
        result["return_code"] = body[1] if len(body) > 1 else -1

    elif pkt_type == PUBLISH:
        topic_len = struct.unpack("!H", body[:2])[0]
        result["topic"] = body[2 : 2 + topic_len].decode("utf-8", errors="replace")
        pos = 2 + topic_len
        qos = (byte0 >> 1) & 0x03
        result["qos"] = qos
        if qos > 0 and pos + 2 <= len(body):
            result["packet_id"] = struct.unpack("!H", body[pos : pos + 2])[0]
            pos += 2
        result["payload"] = body[pos:]

    elif pkt_type == SUBSCRIBE:
        result["packet_id"] = struct.unpack("!H", body[:2])[0]
        pos = 2
        topics = []
        while pos < len(body):
            tlen = struct.unpack("!H", body[pos : pos + 2])[0]
            pos += 2
            topic = body[pos : pos + tlen].decode("utf-8", errors="replace")
            pos += tlen
            qos = body[pos] if pos < len(body) else 0
            pos += 1
            topics.append({"topic": topic, "qos": qos})
        result["topics"] = topics

    elif pkt_type == SUBACK:
        result["packet_id"] = struct.unpack("!H", body[:2])[0]
        result["return_codes"] = list(body[2:])

    elif pkt_type == PUBACK:
        result["packet_id"] = struct.unpack("!H", body[:2])[0]

    elif pkt_type in (PINGREQ, PINGRESP, DISCONNECT):
        pass  # no payload

    else:
        result["raw_body"] = body

    return result


def _type_name(t: int) -> str:
    names = {
        CONNECT: "CONNECT", CONNACK: "CONNACK", PUBLISH: "PUBLISH",
        PUBACK: "PUBACK", SUBSCRIBE: "SUBSCRIBE", SUBACK: "SUBACK",
        PINGREQ: "PINGREQ", PINGRESP: "PINGRESP", DISCONNECT: "DISCONNECT",
    }
    return names.get(t, f"UNKNOWN({t})")


def _utf8_pair(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return struct.pack("!H", len(encoded)) + encoded


def _topic_match(subscription: str, topic: str) -> bool:
    """MQTT topic wildcard matching (# multi-level, + single-level)."""
    sub_parts = subscription.split("/")
    topic_parts = topic.split("/")
    if subscription == "#":
        return True
    for i, sub_part in enumerate(sub_parts):
        if sub_part == "#":
            return True
        if i >= len(topic_parts):
            return False
        if sub_part == "+":
            continue
        if sub_part != topic_parts[i]:
            return False
    return len(sub_parts) == len(topic_parts)


def recv_packet(sock: socket.socket, timeout: float = 3.0) -> bytes | None:
    """Read exactly one MQTT packet from a socket (handles TCP coalescing)."""
    sock.settimeout(timeout)
    try:
        first = sock.recv(1)
    except (socket.timeout, TimeoutError):
        return None
    if not first:
        return None
    header = bytearray(first)
    multiplier = 1
    value = 0
    while True:
        try:
            byte = sock.recv(1)
        except (socket.timeout, TimeoutError):
            return b""
        if not byte:
            return None
        header.append(byte[0])
        value += (byte[0] & 0x7F) * multiplier
        multiplier *= 128
        if (byte[0] & 0x80) == 0:
            break
    body = b""
    while len(body) < value:
        chunk = sock.recv(value - len(body))
        if not chunk:
            break
        body += chunk
    return bytes(header) + body


# ============================================================================
# Broker Simulator  (localhost TCP)
# ============================================================================

class MQTTBrokerSim:
    """
    Minimal MQTT 3.1.1 broker simulator for lab use.
    Runs on localhost. Accepts connects, subscribes, publishes.
    Deliberately allows unauthenticated subscribe to demonstrate the vuln.
    """

    def __init__(self, host: str = LAB_HOST, port: int = 11883):
        assert_lab_target(host)
        self.host = host
        self.port = port
        self.topics: dict[str, list[bytes]] = {}  # topic -> [payloads]
        self._server: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None
        self._clients: dict[socket.socket, dict] = {}
        # Pre-populate some "IoT" topics with sensitive data
        self._seed_topics()

    def _seed_topics(self) -> None:
        self.topics["admin/config"] = [json.dumps({"admin_pass": "lab-admin-123"}).encode()]
        self.topics["sensor/temperature"] = [b"\x1a\x2b"]
        self.topics["sensor/humidity"] = [b"\x55\x66"]
        self.topics["device/firmware_version"] = [b"1.0.0-lab"]
        self.topics["ota/commands"] = [json.dumps({"cmd": "update", "url": "https://lab-fake.example/fw.bin"}).encode()]

    def start(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.settimeout(0.5)
        self._server.bind((self.host, self.port))
        self._server.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._server:
            self._server.close()

    def _run(self) -> None:
        while self._running:
            try:
                conn, addr = self._server.accept()
                conn.settimeout(0.5)
                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn: socket.socket) -> None:
        subscriptions: list[str] = []
        self._clients[conn] = {"subscriptions": subscriptions}
        try:
            while self._running:
                data = recv_packet(conn, timeout=0.5) if self._running else None
                if data is None:
                    if self._running:
                        continue
                    break
                if data == b"":
                    break
                pkt = parse_packet(data)
                ptype = pkt["type"]

                if ptype == CONNECT:
                    conn.sendall(build_connack())

                elif ptype == SUBSCRIBE:
                    for t in pkt.get("topics", []):
                        topic = t["topic"]
                        subscriptions.append(topic)
                    codes = [0] * len(pkt.get("topics", []))
                    conn.sendall(build_suback(pkt.get("packet_id", 0), codes))
                    # Send existing retained messages for matched topics (wildcard-aware)
                    for sub in subscriptions:
                        for topic in list(self.topics):
                            if _topic_match(sub, topic):
                                for payload in self.topics[topic]:
                                    conn.sendall(build_publish(topic, payload, qos=0, retain=True))

                elif ptype == PUBLISH:
                    topic = pkt.get("topic", "")
                    payload = pkt.get("payload", b"")
                    if topic not in self.topics:
                        self.topics[topic] = []
                    self.topics[topic].append(payload)
                    # Forward to all subscribed clients (live delivery)
                    for cli_sock, cli_info in list(self._clients.items()):
                        if cli_sock is conn:
                            continue
                        if any(_topic_match(sub, topic) for sub in cli_info.get("subscriptions", [])):
                            try:
                                cli_sock.sendall(build_publish(topic, payload, qos=0))
                            except (ConnectionResetError, BrokenPipeError, OSError):
                                pass
                    if pkt.get("qos", 0) == 1:
                        conn.sendall(build_puback(pkt.get("packet_id", 1)))

                elif ptype == PINGREQ:
                    conn.sendall(build_pingresp())

                elif ptype == DISCONNECT:
                    break
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            self._clients.pop(conn, None)
            conn.close()


# ============================================================================
# Client helper for demos / tests
# ============================================================================

def connect_and_subscribe(
    host: str, port: int, topic: str, client_id: str = "lab-client"
) -> tuple[socket.socket, list[dict]]:
    """Connect to broker, subscribe, collect retained messages."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    # CONNECT
    sock.sendall(build_connect(client_id))
    data = recv_packet(sock)
    connack = parse_packet(data)
    # SUBSCRIBE
    sock.sendall(build_subscribe(1, topic))
    data = recv_packet(sock)
    suback = parse_packet(data)
    # Collect messages
    messages = []
    while True:
        try:
            data = recv_packet(sock, timeout=1)
        except socket.timeout:
            break
        if data is None:
            break
        try:
            msg = parse_packet(data)
        except ValueError:
            break
        messages.append(msg)
    sock.sendall(build_disconnect())
    sock.close()
    return sock, messages
