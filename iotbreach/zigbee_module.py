"""Zigbee ZLL beacon parse + 433 MHz OOK packetcraft (bytes-only simulation)."""

from __future__ import annotations

import secrets
import struct
from typing import Any

from .common import utcnow_iso

# ---- Zigbee constants ----
ZIGBEE_PAN_ID_DEFAULT = 0x1A62  # lab placeholder
ZIGBEE_CHANNEL_DEFAULT = 11
ZLL_BEACON_COMMAND_ID = 0x00

# ---- 433 MHz OOK protocol patterns ----
OOK_HEADER_LEN = 4
OOK_SYNC_PATTERN = bytes([0xAA, 0x55])  # common sync word


# ============================================================================
# Zigbee ZLL Beacon
# ============================================================================

def build_zigbee_beacon(
    pan_id: int = ZIGBEE_PAN_ID_DEFAULT,
    source_addr: int = 0x0000,
    channel: int = ZIGBEE_CHANNEL_DEFAULT,
   permit_join: bool = False,
    device_type: int = 0,
) -> bytes:
    """
    Build a Zigbee ZLL beacon frame (simplified).
    Layout: [Sync(4)] [Frame Control(2)] [Sequence(1)] [Src PanID(2)] [Src Addr(2)] [ZLL Beacon payload]
    """
    sync = bytes([0x00, 0x00, 0x00, 0x00])  # simplified sync
    frame_control = 0x0800  # Beacon request
    seq = secrets.randbits(8) & 0xFF
    payload = struct.pack("<BB", channel & 0x7F, (1 if permit_join else 0) | (device_type << 1))
    frame = struct.pack("<HBBHH", frame_control, seq, 0, pan_id & 0xFFFF, source_addr & 0xFFFF)
    return sync + frame + payload


def parse_zigbee_beacon(data: bytes) -> dict[str, Any]:
    """Parse a simplified Zigbee ZLL beacon."""
    if len(data) < 11:
        return {"error": "Beacon too short", "raw_hex": data.hex()}

    sync = data[:4]
    frame_ctrl = struct.unpack("<H", data[4:6])[0]
    seq = data[6]
    # frame layout (after sync): frame_ctrl(2) seq(1) 0x00(1) pan_id(2) src_addr(2)
    src_pan = struct.unpack("<H", data[8:10])[0]
    src_addr = struct.unpack("<H", data[10:12])[0]
    beacon_payload = data[12:]

    result: dict[str, Any] = {
        "frame_control": f"0x{frame_ctrl:04X}",
        "sequence": seq,
        "pan_id": f"0x{src_pan:04X}",
        "source_address": f"0x{src_addr:04X}",
        "is_beacon_request": bool(frame_ctrl & 0x0800),
    }

    if len(beacon_payload) >= 2:
        result["channel"] = beacon_payload[0] & 0x7F
        result["permit_join"] = bool(beacon_payload[1] & 0x01)
        result["device_type"] = (beacon_payload[1] >> 1) & 0x07

    return result


# ============================================================================
# Zigbee network key / trust center attack (simulated)
# ============================================================================

def build_zigbee_network_key_transport(
    network_key: bytes,
    source_addr: int = 0x0000,
    dest_addr: int = 0xFFFC,
) -> bytes:
    """
    Simulate Zigbee trust center network key transport frame (attack scenario).
    """
    frame_ctrl = 0x0008  # security enabled
    seq = secrets.randbits(8) & 0xFF
    key_header = bytes([0x11]) + network_key  # 0x11 = network key descriptor
    frame = struct.pack("<HBBHH", frame_ctrl, seq, 0, ZIGBEE_PAN_ID_DEFAULT, dest_addr)
    frame += struct.pack("<H", source_addr)
    frame += key_header
    return frame


# ============================================================================
# 433 MHz OOK Packet Builder / Parser
# ============================================================================

def build_ook_packet(
    protocol_id: int,
    command: int,
    payload: bytes,
    rolling_code: int = 0,
    sync: bytes = OOK_SYNC_PATTERN,
) -> bytes:
    """
    Build a 433 MHz OOK packet.
    Layout: [Sync(2)] [Protocol ID(1)] [Command(1)] [Rolling Code(2)] [Payload(N)] [CRC(2)]
    """
    header = sync + bytes([protocol_id, command])
    header += struct.pack("<H", rolling_code & 0xFFFF)
    body = header + payload
    crc = _crc16(body)
    return body + struct.pack("<H", crc)


def parse_ook_packet(data: bytes) -> dict[str, Any]:
    """Parse a 433 MHz OOK packet."""
    if len(data) < 8:
        return {"error": "Packet too short", "raw_hex": data.hex()}

    # Find sync word
    idx = data.find(OOK_SYNC_PATTERN)
    if idx == -1:
        return {"error": "No sync pattern found", "raw_hex": data.hex()}

    body = data[idx + 2:]
    if len(body) < 6:
        return {"error": "Body too short"}

    protocol_id = body[0]
    command = body[1]
    rolling_code = struct.unpack("<H", body[2:4])[0]
    payload = body[4:-2]
    crc_received = struct.unpack("<H", body[-2:])[0]
    crc_computed = _crc16(data[idx : idx + 2] + body[:-2])

    return {
        "offset": idx,
        "protocol_id": protocol_id,
        "command": command,
        "rolling_code": rolling_code,
        "payload_hex": payload.hex(),
        "payload": list(payload),
        "crc_valid": crc_received == crc_computed,
        "crc": f"0x{crc_received:04X}",
    }


def _crc16(data: bytes) -> int:
    """CRC-16/MODBUS (common in 433 MHz devices)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


# ============================================================================
# Zigbee/433 Sim (TCP localhost)
# ============================================================================

class Zigbee433Sim:
    """
    Simulates Zigbee beacons and 433 MHz OOK traffic on localhost TCP.
    Demonstrates replay detection and packet analysis.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 17002):
        import socket
        self.host = host
        self.port = port
        self._sock = None
        self._running = False
        self._thread = None
        self.beacon_count = 0
        self.ook_packets: list[dict] = []
        self.replay_detected = False
        self.seen_ook: list[bytes] = []
        self.log: list[dict] = []

    def start(self) -> None:
        import socket
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(0.5)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
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
        import socket
        while self._running:
            try:
                conn, addr = self._sock.accept()
                conn.settimeout(2)
                t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn) -> None:
        try:
            while self._running:
                try:
                    data = conn.recv(2048)
                except socket.timeout:
                    continue
                if not data:
                    break
                # Try parsing as Zigbee beacon
                if data[4:6] == b"\x00\x08" or data[4:6] == bytes([0x00, 0x08]):
                    parsed = parse_zigbee_beacon(data)
                    self.beacon_count += 1
                    conn.sendall(b"\x01")  # ACK
                # Try parsing as OOK
                elif OOK_SYNC_PATTERN in data:
                    parsed = parse_ook_packet(data)
                    self.ook_packets.append(parsed)
                    # Replay detection
                    if data in self.seen_ook:
                        self.replay_detected = True
                        self.log.append({"event": "replay_detected", "timestamp": utcnow_iso()})
                    else:
                        self.seen_ook.append(data)
                    conn.sendall(b"\x01")  # ACK
                else:
                    conn.sendall(b"\x00")  # NAK
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            conn.close()

    def get_status(self) -> dict:
        return {
            "beacon_count": self.beacon_count,
            "ook_packet_count": len(self.ook_packets),
            "replay_detected": self.replay_detected,
        }


import threading  # needed by Zigbee433Sim
