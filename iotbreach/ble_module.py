"""BLE ADV PDU + GATT ATT PDU builder/parser, CRC-24, smart-lock spoof sim."""

from __future__ import annotations

import secrets
import socket
import struct
import threading
from typing import Any

from .common import LAB_HOST, assert_lab_target, utcnow_iso

# ---- BLE PDU types ----
ADV_IND = 0x00           # Connectable undirected
ADV_DIRECT_IND = 0x01    # Connectable directed
ADV_NONCONN_IND = 0x02   # Non-connectable undirected
ADV_SCAN_IND = 0x06      # Scannable undirected
SCAN_REQ = 0x03
SCAN_RSP = 0x04
CONNECT_IND = 0x05
AUX_ADV_IND = 0x07

PDU_TYPE_NAMES = {
    0x00: "ADV_IND", 0x01: "ADV_DIRECT_IND", 0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ", 0x04: "SCAN_RSP", 0x05: "CONNECT_IND",
    0x06: "ADV_SCAN_IND", 0x07: "AUX_ADV_IND",
}

# ---- BLE ATT opcodes ----
ATT_OP_ERROR = 0x01
ATT_OP_READ_REQ = 0x0A
ATT_OP_READ_RSP = 0x0B
ATT_OP_WRITE_REQ = 0x12
ATT_OP_WRITE_RSP = 0x13
ATT_OP_WRITE_CMD = 0x52
ATT_OP_FIND_INFO_REQ = 0x04
ATT_OP_FIND_INFO_RSP = 0x05
ATT_OP_READ_BY_GROUP_REQ = 0x10
ATT_OP_READ_BY_GROUP_RSP = 0x11

# ---- GATT UUIDs ----
UUID_BATT_LEVEL = 0x2A19
UUID_LOCK_STATE = 0xFF01   # custom lock characteristic
UUID_LOCK_CMD = 0xFF02     # custom lock command

ATT_NAMES = {
    0x01: "ERROR", 0x04: "FIND_INFO_REQ", 0x05: "FIND_INFO_RSP",
    0x0A: "READ_REQ", 0x0B: "READ_RSP", 0x10: "READ_BY_GROUP_REQ",
    0x11: "READ_BY_GROUP_RSP", 0x12: "WRITE_REQ", 0x13: "WRITE_RSP",
    0x52: "WRITE_CMD",
}


# ============================================================================
# CRC-24 (BLE CRC)
# ============================================================================

def crc24(data: bytes) -> int:
    """BLE CRC-24 (polynomial 0x5B6B51)."""
    crc = 0x555555
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x5B6B51
            else:
                crc >>= 1
    return crc & 0xFFFFFF


# ============================================================================
# ADV PDU builder / parser
# ============================================================================

def build_adv_pdu(
    pdu_type: int,
    adv_addr: str = "00:11:22:33:44:55",
    adv_data: bytes = b"",
    rx_add: int = 0,
    tx_add: int = 0,
    channel: int = 37,
) -> bytes:
    """Build BLE advertising PDU."""
    # Parse address (BLE transmits LSO first, so reverse for wire format)
    addr_bytes = bytes(reversed(bytes.fromhex(adv_addr.replace(":", ""))))
    # PDU header: PDU type(4) | RFU(2) | TxAdd(1) | RxAdd(1)
    header = bytes([(pdu_type & 0x0F) | (tx_add << 6) | (rx_add << 7)])
    header += addr_bytes  # AdvA (6 bytes)
    header += adv_data   # AdvData (0-31 bytes)
    # Prepend preamble + access address for air interface
    preamble = bytes([0xAA] * 1)  # 1-byte preamble
    access_addr = struct.pack("<I", 0x8E89BED6)  # Advertising access address
    # CRC computed over PDU body (header + AdvA + AdvData) per BLE spec
    crc = crc24(header)
    crc_bytes = struct.pack("<I", crc)[0:3]
    return preamble + access_addr + header + crc_bytes


def parse_adv_pdu(data: bytes) -> dict[str, Any]:
    """Parse BLE ADV PDU."""
    if len(data) < 10:
        return {"error": "PDU too short", "raw_hex": data.hex()}
    # Find access address (0x8E89BED6 for advertising)
    idx = data.find(struct.pack("<I", 0x8E89BED6))
    if idx == -1:
        return {"error": "No advertising access address found", "raw_hex": data.hex()}
    payload = data[idx + 4:]  # after access address (skip preamble + AA)
    if len(payload) < 2:
        return {"error": "Payload too short"}

    header_byte = payload[0]
    pdu_type = header_byte & 0x0F
    tx_add = (header_byte >> 6) & 1
    rx_add = (header_byte >> 7) & 1

    addr_bytes = payload[1:7]
    adv_addr = ":".join(f"{b:02x}" for b in reversed(addr_bytes))
    adv_data = payload[7:-3] if len(payload) > 10 else payload[7:]
    crc_received = int.from_bytes(payload[-3:], "little") if len(payload) >= 10 else 0
    crc_computed = crc24(data[idx + 4 : -3])  # compute over PDU body

    return {
        "pdu_type": pdu_type,
        "pdu_type_name": PDU_TYPE_NAMES.get(pdu_type, f"0x{pdu_type:02X}"),
        "tx_add": tx_add,
        "rx_add": rx_add,
        "adv_addr": adv_addr,
        "adv_data_hex": adv_data.hex(),
        "crc_valid": crc_received == crc_computed,
        "crc": hex(crc_received),
    }


# ============================================================================
# ATT PDU builder / parser (GATT operations)
# ============================================================================

def build_att_read_req(handle: int) -> bytes:
    return bytes([ATT_OP_READ_REQ]) + struct.pack("<H", handle)


def build_att_read_rsp(value: bytes) -> bytes:
    return bytes([ATT_OP_READ_RSP]) + value


def build_att_write_req(handle: int, value: bytes) -> bytes:
    return bytes([ATT_OP_WRITE_REQ]) + struct.pack("<H", handle) + value


def build_att_write_rsp() -> bytes:
    return bytes([ATT_OP_WRITE_RSP])


def build_att_write_cmd(handle: int, value: bytes) -> bytes:
    return bytes([ATT_OP_WRITE_CMD]) + struct.pack("<H", handle) + value


def build_att_error(opcode: int, handle: int, error_code: int) -> bytes:
    return bytes([ATT_OP_ERROR, opcode]) + struct.pack("<H", handle) + bytes([error_code])


def build_att_read_by_group_req(start_handle: int, end_handle: int,
                                 uuid: bytes | None = None) -> bytes:
    """ATT Read By Group Type Request."""
    data = bytes([ATT_OP_READ_BY_GROUP_REQ]) + struct.pack("<HH", start_handle, end_handle)
    if uuid:
        data += uuid
    return data


def parse_att(data: bytes) -> dict[str, Any]:
    """Parse ATT PDU."""
    if not data:
        return {"error": "empty"}
    opcode = data[0]
    result: dict[str, Any] = {
        "opcode": opcode,
        "opcode_name": ATT_NAMES.get(opcode, f"0x{opcode:02X}"),
    }

    if opcode == ATT_OP_ERROR:
        if len(data) >= 5:
            result["request_opcode"] = data[1]
            result["handle"] = struct.unpack("<H", data[2:4])[0]
            result["error_code"] = data[4]

    elif opcode in (ATT_OP_READ_REQ,):
        if len(data) >= 3:
            result["handle"] = struct.unpack("<H", data[1:3])[0]

    elif opcode in (ATT_OP_READ_RSP,):
        result["value"] = data[1:]

    elif opcode in (ATT_OP_WRITE_REQ, ATT_OP_WRITE_CMD):
        if len(data) >= 3:
            result["handle"] = struct.unpack("<H", data[1:3])[0]
            result["value"] = data[3:]

    elif opcode == ATT_OP_WRITE_RSP:
        result["status"] = "success"

    return result


# ============================================================================
# Smart Lock Simulator (TCP localhost)
# ============================================================================

class BLELockSim:
    """
    Simulates a BLE smart lock with GATT characteristics over TCP.
    Demonstrates unauthorized write to open lock (spoofed authenticated write).
    """

    def __init__(self, host: str = LAB_HOST, port: int = 17001):
        assert_lab_target(host)
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

        # GATT database (handle -> value)
        self.gatt_db: dict[int, dict] = {
            0x0001: {"name": "Battery Level", "uuid": UUID_BATT_LEVEL, "value": bytes([85])},
            0x0002: {"name": "Lock State", "uuid": UUID_LOCK_STATE, "value": bytes([0x00])},  # 0=locked
            0x0003: {"name": "Lock Command", "uuid": UUID_LOCK_CMD, "value": b"\x00"},
        }
        self.lock_opened = False
        self.write_log: list[dict] = []
        self.auth_token = secrets.token_hex(8)

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(0.5)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]
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

    def _handle(self, conn: socket.socket) -> None:
        try:
            while self._running:
                try:
                    data = conn.recv(512)
                except socket.timeout:
                    continue
                if not data:
                    break
                att = parse_att(data)
                opcode = att.get("opcode", 0)

                if opcode == ATT_OP_READ_REQ:
                    handle = att.get("handle", 0)
                    char = self.gatt_db.get(handle)
                    if char:
                        resp = build_att_read_rsp(char["value"])
                    else:
                        resp = build_att_error(ATT_OP_READ_REQ, handle, 0x0A)  # Attribute Not Found
                    conn.sendall(resp)

                elif opcode in (ATT_OP_WRITE_REQ, ATT_OP_WRITE_CMD):
                    handle = att.get("handle", 0)
                    value = att.get("value", b"")
                    if handle in self.gatt_db:
                        self.gatt_db[handle]["value"] = value
                        self.write_log.append({
                            "handle": f"0x{handle:04X}",
                            "name": self.gatt_db[handle]["name"],
                            "value_hex": value.hex(),
                            "timestamp": utcnow_iso(),
                        })
                        if handle == 0x0003 and value == bytes([0x01]):  # unlock command
                            self.lock_opened = True
                            self.gatt_db[0x0002]["value"] = bytes([0x01])  # update state
                        resp = build_att_write_rsp()
                    else:
                        resp = build_att_error(opcode, handle, 0x0A)
                    conn.sendall(resp)

                elif opcode == ATT_OP_READ_BY_GROUP_REQ:
                    # Return all characteristics
                    entries = []
                    for h in sorted(self.gatt_db.keys()):
                        char = self.gatt_db[h]
                        entries.append(struct.pack("<H", h) + struct.pack("<H", char["uuid"]) + char["value"])
                    resp = bytes([ATT_OP_READ_BY_GROUP_RSP, 6])  # attribute_data_length=6
                    for e in entries:
                        resp += e
                    conn.sendall(resp)

        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            conn.close()


# ============================================================================
# Client helpers
# ============================================================================

def ble_read_battery(host: str, port: int) -> dict:
    """Read battery level via GATT."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    req = build_att_read_req(0x0001)
    sock.sendall(req)
    data = sock.recv(256)
    sock.close()
    return parse_att(data)


def ble_read_lock_state(host: str, port: int) -> dict:
    """Read lock state via GATT."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    req = build_att_read_req(0x0002)
    sock.sendall(req)
    data = sock.recv(256)
    sock.close()
    return parse_att(data)


def ble_spoof_unlock(host: str, port: int) -> dict:
    """Spoof an authenticated write to open the lock."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    # Write 0x01 to Lock Command handle (0x0003) = unlock
    req = build_att_write_cmd(0x0003, bytes([0x01]))
    sock.sendall(req)
    data = sock.recv(256)
    sock.close()
    result = parse_att(data)
    result["command"] = "unlock"
    result["handle_written"] = "0xFF02"
    return result
