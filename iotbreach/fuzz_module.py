"""Protocol fuzzer — mutate fixtures, run against sims, capture anomalies."""

from __future__ import annotations

import random
import secrets
import socket
import struct
import time
from typing import Any, Callable

from .common import LAB_HOST, assert_lab_target, utcnow_iso


# ============================================================================
# Mutation strategies
# ============================================================================

def mutate_byte_flip(data: bytes, count: int = 1) -> bytes:
    """Randomly flip bits."""
    buf = bytearray(data)
    for _ in range(count):
        if buf:
            idx = random.randint(0, len(buf) - 1)
            bit = 1 << random.randint(0, 7)
            buf[idx] ^= bit
    return bytes(buf)


def mutate_byte_replace(data: bytes, count: int = 1) -> bytes:
    """Replace random bytes with random values."""
    buf = bytearray(data)
    for _ in range(count):
        if buf:
            buf[random.randint(0, len(buf) - 1)] = random.randint(0, 255)
    return bytes(buf)


def mutate_truncate(data: bytes) -> bytes:
    """Truncate to random length."""
    if len(data) <= 1:
        return data
    return data[: random.randint(1, len(data) - 1)]


def mutate_grow(data: bytes, max_extra: int = 32) -> bytes:
    """Append random bytes."""
    return data + secrets.token_bytes(random.randint(1, max_extra))


def mutate_insert(data: bytes, max_extra: int = 16) -> bytes:
    """Insert random bytes at random position."""
    pos = random.randint(0, len(data))
    return data[:pos] + secrets.token_bytes(random.randint(1, max_extra)) + data[pos:]


def mutate_zero_fill(data: bytes) -> bytes:
    """Fill with zeros."""
    return b"\x00" * len(data)


def mutate_ones_fill(data: bytes) -> bytes:
    """Fill with 0xFF."""
    return b"\xff" * len(data)


def mutate_int_overflow(data: bytes) -> bytes:
    """Try integer overflow values in header."""
    buf = bytearray(data)
    if len(buf) >= 4:
        struct.pack_into("!I", buf, 0, 0xFFFFFFFF)
    return bytes(buf)


MUTATORS = [
    mutate_byte_flip,
    mutate_byte_replace,
    mutate_truncate,
    mutate_grow,
    mutate_insert,
    mutate_zero_fill,
    mutate_ones_fill,
    mutate_int_overflow,
]


# ============================================================================
# Fuzzer runner
# ============================================================================

class Anomaly:
    def __init__(self, category: str, detail: str, input_data: bytes,
                 response: bytes | None = None, mutator: str = ""):
        self.category = category
        self.detail = detail
        self.input_hex = input_data.hex()
        self.response_hex = response.hex() if response else None
        self.mutator = mutator
        self.timestamp = utcnow_iso()

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "detail": self.detail,
            "input_hex": self.input_hex,
            "response_hex": self.response_hex,
            "mutator": self.mutator,
            "timestamp": self.timestamp,
        }


class ProtocolFuzzer:
    """
    Generic protocol fuzzer.
    Takes a fixture (valid packet) and a send function, mutates, sends, detects anomalies.
    """

    def __init__(self, name: str, fixture: bytes, send_fn: Callable[[bytes], bytes | None],
                 iterations: int = 200, timeout: float = 5.0):
        self.name = name
        self.fixture = fixture
        self.send_fn = send_fn
        self.iterations = iterations
        self.timeout = timeout
        self.anomalies: list[Anomaly] = []
        self.cases_run = 0
        self.errors = 0

    def run(self) -> dict[str, Any]:
        """Run the fuzzer."""
        start_time = time.time()
        for i in range(self.iterations):
            mutator = random.choice(MUTATORS)
            mutator_name = mutator.__name__
            # Determine mutation count for byte-level mutators
            if mutator in (mutate_byte_flip, mutate_byte_replace):
                count = random.randint(1, min(8, len(self.fixture) or 1))
                mutated = mutator(self.fixture, count)
            else:
                mutated = mutator(self.fixture)
            self.cases_run += 1
            try:
                response = self.send_fn(mutated)
                if response is not None:
                    self._check_anomaly(mutated, response, mutator_name)
            except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as e:
                self.errors += 1
                if "connection reset" in str(e).lower() or "broken pipe" in str(e).lower():
                    self.anomalies.append(Anomaly(
                        "connection_error",
                        f"Mutated packet caused connection error: {type(e).__name__}",
                        mutated, mutator=mutator_name,
                    ))
            except Exception as e:
                self.errors += 1

        elapsed = time.time() - start_time
        return {
            "name": self.name,
            "iterations": self.iterations,
            "cases_run": self.cases_run,
            "anomalies_found": len(self.anomalies),
            "errors": self.errors,
            "elapsed_seconds": round(elapsed, 3),
            "anomalies": [a.to_dict() for a in self.anomalies],
        }

    def _check_anomaly(self, input_data: bytes, response: bytes, mutator: str) -> None:
        """Heuristic anomaly detection."""
        # Very short response (might indicate server confusion)
        if len(response) == 1:
            self.anomalies.append(Anomaly(
                "short_response",
                f"Server responded with single byte: 0x{response[0]:02X}",
                input_data, response, mutator,
            ))
        # Response contains error-like patterns
        if len(response) >= 2:
            # Modbus exception: function code with 0x80 bit set
            if response[0] & 0x80:
                self.anomalies.append(Anomaly(
                    "exception_response",
                    f"Exception response detected: FC=0x{response[0]:02X}, code=0x{response[1]:02X}",
                    input_data, response, mutator,
                ))
        # Zero-length response
        if len(response) == 0:
            self.anomalies.append(Anomaly(
                "empty_response",
                "Server returned empty response to mutated input",
                input_data, response, mutator,
            ))
        # Response significantly larger than expected
        if len(response) > len(self.fixture) * 4:
            self.anomalies.append(Anomaly(
                "response_inflation",
                f"Response ({len(response)} bytes) >> fixture ({len(self.fixture)} bytes)",
                input_data, response, mutator,
            ))


# ============================================================================
# Pre-built fuzz fixtures (valid packets for each protocol)
# ============================================================================

def get_mqtt_connect_fixture() -> bytes:
    """Valid MQTT CONNECT packet."""
    from .mqtt_module import build_connect
    return build_connect("fuzz-client")


def get_mqtt_publish_fixture() -> bytes:
    from .mqtt_module import build_publish
    return build_publish("test/topic", b"hello", qos=0)


def get_modbus_read_fixture() -> bytes:
    from .modbus_module import build_read_request
    return build_read_request(0x03, 0, 10)


def get_modbus_write_fixture() -> bytes:
    from .modbus_module import build_write_coil_request
    return build_write_coil_request(0, True)


def get_can_frame_fixture() -> bytes:
    from .can_module import build_can_frame
    return build_can_frame(0x7DF, bytes([0x02, 0x01, 0x0C]))


def get_ble_write_fixture() -> bytes:
    from .ble_module import build_att_write_cmd
    return build_att_write_cmd(0x0003, bytes([0x01]))


# ============================================================================
# TCP send helpers
# ============================================================================

def tcp_send(host: str, port: int, data: bytes) -> bytes | None:
    """Send bytes over TCP, return response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        sock.connect((host, port))
        sock.sendall(data)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return b""
    except (ConnectionRefusedError, OSError):
        return None
    finally:
        sock.close()


def udp_send(host: str, port: int, data: bytes) -> bytes | None:
    """Send bytes over UDP, return response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(data, (host, port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return b""
    except (ConnectionRefusedError, OSError):
        return None
    finally:
        sock.close()


# ============================================================================
# High-level fuzzer
# ============================================================================

def fuzz_protocol(
    name: str,
    fixture: bytes,
    host: str = LAB_HOST,
    port: int = 0,
    protocol: str = "tcp",
    iterations: int = 200,
) -> dict[str, Any]:
    """Run fuzzer against a specific protocol sim."""
    assert_lab_target(host)

    def send_fn(data: bytes) -> bytes | None:
        if protocol == "tcp":
            return tcp_send(host, port, data)
        else:
            return udp_send(host, port, data)

    fuzzer = ProtocolFuzzer(name, fixture, send_fn, iterations)
    return fuzzer.run()
