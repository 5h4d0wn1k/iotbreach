"""CAN bus frame builder, parser, simulator, DoS sim, OBD-II PIDs, replay detection."""

from __future__ import annotations

import json
import secrets
import socket
import struct
import threading
import time
from typing import Any

from .common import LAB_HOST, assert_lab_target, hexdump, utcnow_iso

# ---- OBD-II PIDs (subset for demo) ----
OBD_PIDS = {
    0x00: ("PIDs supported 00-20", "bitfield"),
    0x01: ("Monitor status since DTCs cleared", "bitfield"),
    0x02: ("Freeze DTC", "2 bytes"),
    0x04: ("Calculated engine load", "%", lambda v: v * 100 / 255),
    0x05: ("Engine coolant temperature", "°C", lambda v: v - 40),
    0x06: ("Short term fuel trim", "%", lambda v: (v - 128) * 100 / 128),
    0x07: ("Long term fuel trim", "%", lambda v: (v - 128) * 100 / 128),
    0x0C: ("Engine RPM", "rpm", lambda v: v * 256 / 4),
    0x0D: ("Vehicle speed", "km/h", lambda v: v),
    0x10: ("MAF air flow rate", "g/s", lambda v: v * 256 / 100),
    0x11: ("Throttle position", "%", lambda v: v * 100 / 255),
    0x14: ("O2 sensor voltage", "V", lambda v: v / 200),
    0x2F: ("Fuel tank level", "%", lambda v: v * 100 / 255),
}


# ============================================================================
# CAN frame builder / parser
# ============================================================================

def build_can_frame(arb_id: int, data: bytes, extended: bool = False) -> bytes:
    """
    Build a CAN 2.0 frame.
    Layout: [ID(4 bytes LE)] [DLC(1 byte)] [Data(0-8 bytes)]
    For 11-bit standard: ID in upper bits of 4 bytes.
    """
    dlc = len(data)
    if dlc > 8:
        dlc = 8
        data = data[:8]
    if extended:
        # Extended: 29-bit ID, marker bit 0 set. ID in bits 3-31.
        frame = struct.pack("<I", ((arb_id & 0x1FFFFFFF) << 3) | 0x01)
    else:
        # Standard: 11-bit ID, shifted to upper bits of 32-bit field
        frame = struct.pack("<I", (arb_id & 0x7FF) << 21)
    frame += bytes([dlc])
    frame += data
    frame += b"\x00" * (8 - len(data))  # pad to 8 bytes
    return frame


def parse_can_frame(frame: bytes) -> dict[str, Any]:
    """Parse CAN frame."""
    if len(frame) < 13:  # 4(id) + 1(dlc) + 8(data)
        raise ValueError(f"CAN frame too short: {len(frame)} bytes")
    id_raw = struct.unpack("<I", frame[:4])[0]
    is_extended = bool(id_raw & 0x01)
    if is_extended:
        arb_id = (id_raw >> 3) & 0x1FFFFFFF
    else:
        arb_id = (id_raw >> 21) & 0x7FF
    dlc = frame[4]
    data = frame[5:5 + dlc]
    return {
        "arb_id": arb_id,
        "arb_id_hex": f"0x{arb_id:03X}",
        "dlc": dlc,
        "data": data,
        "data_hex": data.hex(),
        "extended": is_extended,
    }


def build_obd_request(pid: int, arb_id: int = 0x7DF) -> bytes:
    """Build OBD-II request (ISO-TP single frame, CAN arbitration ID 0x7DF)."""
    data = bytes([0x02, 0x01, pid])  # PCI=0x02 (single frame, 2 data bytes), mode=01, PID
    return build_can_frame(arb_id, data)


def build_obd_response(pid: int, value: int, arb_id: int = 0x7E8) -> bytes:
    """Build OBD-II response."""
    data = bytes([0x04, 0x41, pid, value])  # PCI=4 bytes, mode=41 (response), PID, value
    return build_can_frame(arb_id, data)


# ============================================================================
# CAN Bus Simulator (TCP localhost)
# ============================================================================

class CANBusSim:
    """
    Simulates a CAN bus over TCP.
    - Accepts frames, tracks state
    - Simulates OBD-II responses
    - Detects replay attacks
    - DoS detection via fault counter
    """

    def __init__(self, host: str = LAB_HOST, port: int = 17000):
        assert_lab_target(host)
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False
        self._thread: threading.Thread | None = None

        # State
        self.frame_count = 0
        self.fault_counter = 0
        self.max_faults = 255
        self.dos_detected = False
        self.replay_detected = False
        self.seen_frames: list[bytes] = []
        self.replay_window = 100
        # Vehicle state
        self.vehicle_state = {
            "rpm": 850,
            "speed": 0,
            "coolant_temp": 85,
            "throttle": 12,
            "fuel_level": 75,
            "engine_load": 22,
        }
        self.bus_log: list[dict] = []

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
                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            while self._running:
                try:
                    data = conn.recv(13)
                except socket.timeout:
                    continue
                if not data:
                    break
                if len(data) < 13:
                    data = data.ljust(13, b"\x00")
                self.frame_count += 1
                parsed = parse_can_frame(data)
                arb_id = parsed["arb_id"]

                # Replay detection
                if data in self.seen_frames[-self.replay_window:]:
                    self.replay_detected = True
                    self.bus_log.append({
                        "event": "replay_detected",
                        "arb_id": parsed["arb_id_hex"],
                        "timestamp": utcnow_iso(),
                    })
                else:
                    self.seen_frames.append(data)
                    if len(self.seen_frames) > self.replay_window * 2:
                        self.seen_frames = self.seen_frames[-self.replay_window:]

                # DoS simulation: rapid frames increment fault counter
                if self.frame_count % 10 == 0:
                    self.fault_counter = min(self.fault_counter + 1, self.max_faults)
                    if self.fault_counter >= 15:
                        self.dos_detected = True

                # OBD-II response
                if arb_id == 0x7DF and len(parsed["data"]) >= 3:
                    mode = parsed["data"][1]
                    pid = parsed["data"][2]
                    if mode == 0x01 and pid in OBD_PIDS:
                        pinfo = OBD_PIDS[pid]
                        raw_val = self.vehicle_state.get(
                            pinfo[0].lower().replace(" ", "_").replace("(%)", "").replace("(°c)", "").replace("(rpm)", "").replace("(km/h)", "").replace("(g/s)", "").replace("(v)", ""),
                            42
                        )
                        resp = build_obd_response(pid, raw_val & 0xFF)
                        conn.sendall(resp)
                        self.bus_log.append({
                            "event": "obd_response",
                            "pid": f"0x{pid:02X}",
                            "description": pinfo[0],
                            "timestamp": utcnow_iso(),
                        })

                self.bus_log.append({
                    "event": "frame_received",
                    "arb_id": parsed["arb_id_hex"],
                    "dlc": parsed["dlc"],
                    "data": parsed["data_hex"],
                    "frame_num": self.frame_count,
                })
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            conn.close()

    def get_status(self) -> dict[str, Any]:
        return {
            "frame_count": self.frame_count,
            "fault_counter": self.fault_counter,
            "dos_detected": self.dos_detected,
            "replay_detected": self.replay_detected,
            "vehicle_state": self.vehicle_state,
        }


# ============================================================================
# DoS simulation helper
# ============================================================================

def simulate_can_dos(host: str, port: int, num_frames: int = 300) -> dict[str, Any]:
    """Send rapid CAN frames to trigger DoS detection."""
    assert_lab_target(host)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    sent = 0
    for i in range(num_frames):
        frame = build_can_frame(secrets.randbits(11), secrets.token_bytes(8))
        try:
            sock.sendall(frame)
            sent += 1
        except (BrokenPipeError, OSError):
            break
    sock.close()
    return {"frames_sent": sent, "dos_intended": True}
