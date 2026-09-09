"""Modbus-TCP packet builder, parser, and slave simulator (localhost only)."""

from __future__ import annotations

import socket
import struct
import threading
from typing import Any

from .common import LAB_HOST, assert_lab_target, hexdump, utcnow_iso

# ---- Modbus function codes ----
FC_READ_COILS = 0x01
FC_READ_DISCRETE = 0x02
FC_READ_HOLDING = 0x03
FC_READ_INPUT = 0x04
FC_WRITE_COIL = 0x05
FC_WRITE_REGISTERS = 0x10

FC_NAMES = {
    FC_READ_COILS: "Read Coils (FC1)",
    FC_READ_DISCRETE: "Read Discrete Inputs (FC2)",
    FC_READ_HOLDING: "Read Holding Registers (FC3)",
    FC_READ_INPUT: "Read Input Registers (FC4)",
    FC_WRITE_COIL: "Write Single Coil (FC5)",
    FC_WRITE_REGISTERS: "Write Multiple Registers (FC16)",
}

# Exception codes
ERR_ILLEGAL_FUNCTION = 0x01
ERR_ILLEGAL_DATA = 0x02
ERR_SERVER_FAILURE = 0x03


# ============================================================================
# MBAP + PDU builders
# ============================================================================

def build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Build MBAP header + PDU for Modbus-TCP."""
    length = len(pdu) + 1  # unit_id + pdu
    header = struct.pack("!HH", transaction_id, 0)  # protocol ID = 0 (Modbus)
    header += struct.pack("!HB", length, unit_id)
    return header + pdu


def build_read_request(fc: int, start_addr: int, quantity: int,
                       transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Build Modbus read request (FC1-FC4)."""
    pdu = bytes([fc]) + struct.pack("!HH", start_addr, quantity)
    return build_mbap(transaction_id, unit_id, pdu)


def build_read_response(fc: int, data: bytes,
                        transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Build Modbus read response. Byte-count is clamped to 255."""
    bc = min(len(data), 255)
    pdu = bytes([fc, bc]) + data[:255]
    return build_mbap(transaction_id, unit_id, pdu)


def build_write_coil_request(addr: int, value: bool,
                             transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Build FC5 Write Single Coil request."""
    coil_val = 0xFF00 if value else 0x0000
    pdu = bytes([FC_WRITE_COIL]) + struct.pack("!HH", addr, coil_val)
    return build_mbap(transaction_id, unit_id, pdu)


def build_write_coil_response(addr: int, value: bool,
                              transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Build FC5 Write Single Coil response (echo)."""
    coil_val = 0xFF00 if value else 0x0000
    pdu = bytes([FC_WRITE_COIL]) + struct.pack("!HH", addr, coil_val)
    return build_mbap(transaction_id, unit_id, pdu)


def build_exception_response(fc: int, exception_code: int,
                             transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Build exception response."""
    pdu = bytes([fc | 0x80, exception_code])
    return build_mbap(transaction_id, unit_id, pdu)


# ============================================================================
# Parser
# ============================================================================

def parse_mbap(data: bytes) -> dict[str, Any]:
    """Parse MBAP header + PDU."""
    if len(data) < 7:
        raise ValueError("Modbus packet too short")
    transaction_id, protocol_id, length, unit_id = struct.unpack("!HHHB", data[:7])
    fc = data[7] if len(data) > 7 else 0
    pdu = data[7:]

    result: dict[str, Any] = {
        "transaction_id": transaction_id,
        "protocol_id": protocol_id,
        "mbap_length": length,
        "unit_id": unit_id,
        "function_code": fc,
        "function_name": FC_NAMES.get(fc & 0x7F, f"Unknown (0x{fc:02X})"),
        "is_exception": bool(fc & 0x80),
    }

    if fc & 0x80:
        result["exception_code"] = pdu[1] if len(pdu) > 1 else 0
        return result

    if fc in (FC_READ_COILS, FC_READ_DISCRETE, FC_READ_HOLDING, FC_READ_INPUT):
        if len(pdu) > 1:
            byte_count = pdu[1]
            result["byte_count"] = byte_count
            result["data"] = pdu[2 : 2 + byte_count]

    elif fc == FC_WRITE_COIL:
        if len(pdu) >= 5:
            result["address"] = struct.unpack("!H", pdu[1:3])[0]
            result["value"] = struct.unpack("!H", pdu[3:5])[0] == 0xFF00

    elif fc == FC_WRITE_REGISTERS:
        if len(pdu) >= 6:
            result["address"] = struct.unpack("!H", pdu[1:3])[0]
            result["quantity"] = struct.unpack("!H", pdu[3:5])[0]
            result["data"] = pdu[5:]

    return result


# ============================================================================
# Modbus Slave Simulator  (localhost TCP)
# ============================================================================

class ModbusSlaveSim:
    """
    Minimal Modbus-TCP slave on localhost.
    - NO authentication (demonstrates default-cred / unauth mode)
    - Holds coils (FC1/FC5) and holding registers (FC3/FC4)
    - Coil 0 controls a "heater" (ON/OFF)
    - Holding register 0 = temperature setpoint
    - Holding register 1 = humidity
    - Holding register 2 = firmware version (read-only)
    """

    def __init__(self, host: str = LAB_HOST, port: int = 15050):
        assert_lab_target(host)
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

        # State
        self.coils: dict[int, bool] = {
            0: False,   # heater OFF
            1: False,   # valve
            2: True,    # fan ON
            3: False,   # light
        }
        self.holding_registers: dict[int, int] = {
            0: 22,      # temperature setpoint (°C)
            1: 55,      # humidity (%)
            2: 0x0100,  # firmware version major.minor
            3: 0,       # error count
        }
        self.input_registers: dict[int, int] = {
            0: 23,      # current temperature
            1: 54,      # current humidity
            2: 1013,    # pressure hPa
        }
        self.state_log: list[dict] = []
        self.write_count = 0

    def start(self) -> None:
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
        """Handle a Modbus-TCP connection (one request per connection, simple)."""
        try:
            data = conn.recv(256)
            if len(data) < 7:
                return
            parsed = parse_mbap(data)
            fc = parsed["function_code"]
            unit_id = parsed["unit_id"]
            tid = parsed["transaction_id"]

            if fc == FC_READ_COILS:
                addr = struct.unpack("!H", data[8:10])[0]
                qty = struct.unpack("!H", data[10:12])[0]
                coil_bytes = bytearray((qty + 7) // 8)
                for i in range(qty):
                    if self.coils.get(addr + i, False):
                        coil_bytes[i // 8] |= 1 << (i % 8)
                resp = build_read_response(fc, bytes(coil_bytes), tid, unit_id)

            elif fc == FC_READ_DISCRETE:
                addr = struct.unpack("!H", data[8:10])[0]
                qty = struct.unpack("!H", data[10:12])[0]
                coil_bytes = bytearray((qty + 7) // 8)
                resp = build_read_response(fc, bytes(coil_bytes), tid, unit_id)

            elif fc == FC_READ_HOLDING:
                addr = struct.unpack("!H", data[8:10])[0]
                qty = struct.unpack("!H", data[10:12])[0]
                reg_data = bytearray()
                for i in range(qty):
                    val = self.holding_registers.get(addr + i, 0)
                    reg_data += struct.pack("!H", val)
                resp = build_read_response(fc, bytes(reg_data), tid, unit_id)

            elif fc == FC_READ_INPUT:
                addr = struct.unpack("!H", data[8:10])[0]
                qty = struct.unpack("!H", data[10:12])[0]
                reg_data = bytearray()
                for i in range(qty):
                    val = self.input_registers.get(addr + i, 0)
                    reg_data += struct.pack("!H", val)
                resp = build_read_response(fc, bytes(reg_data), tid, unit_id)

            elif fc == FC_WRITE_COIL:
                addr = struct.unpack("!H", data[8:10])[0]
                val_raw = struct.unpack("!H", data[10:12])[0]
                value = val_raw == 0xFF00
                self.coils[addr] = value
                self.write_count += 1
                self.state_log.append({
                    "action": "write_coil",
                    "address": addr,
                    "value": value,
                    "timestamp": utcnow_iso(),
                })
                resp = build_write_coil_response(addr, value, tid, unit_id)

            elif fc == FC_WRITE_REGISTERS:
                addr = struct.unpack("!H", data[8:10])[0]
                qty = struct.unpack("!H", data[10:12])[0]
                reg_data = data[12 : 12 + qty * 2]
                for i in range(qty):
                    val = struct.unpack("!H", reg_data[i * 2 : i * 2 + 2])[0]
                    self.holding_registers[addr + i] = val
                self.write_count += 1
                resp = build_read_response(fc, bytes([qty * 2]), tid, unit_id)

            else:
                resp = build_exception_response(fc, ERR_ILLEGAL_FUNCTION, tid, unit_id)

            conn.sendall(resp)
        except (ConnectionResetError, BrokenPipeError, OSError, struct.error, ValueError):
            try:
                resp = build_exception_response(fc, ERR_ILLEGAL_DATA, tid, unit_id)
                conn.sendall(resp)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
        finally:
            conn.close()


# ============================================================================
# Client helpers
# ============================================================================

def modbus_read(host: str, port: int, fc: int, addr: int, qty: int,
                unit_id: int = 1, tid: int = 1) -> dict:
    """Read coils/registers from Modbus slave."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    req = build_read_request(fc, addr, qty, tid, unit_id)
    sock.sendall(req)
    data = sock.recv(256)
    sock.close()
    return parse_mbap(data)


def modbus_write_coil(host: str, port: int, addr: int, value: bool,
                      unit_id: int = 1, tid: int = 1) -> dict:
    """Write a single coil."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    req = build_write_coil_request(addr, value, tid, unit_id)
    sock.sendall(req)
    data = sock.recv(256)
    sock.close()
    return parse_mbap(data)
