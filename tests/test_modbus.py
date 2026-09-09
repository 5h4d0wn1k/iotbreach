"""Modbus module tests."""

import time
import unittest

from iotbreach.modbus_module import (
    build_mbap, build_read_request, build_read_response,
    build_write_coil_request, build_write_coil_response,
    build_exception_response, parse_mbap,
    ModbusSlaveSim, modbus_read, modbus_write_coil,
    FC_READ_COILS, FC_READ_DISCRETE, FC_READ_HOLDING, FC_READ_INPUT, FC_WRITE_COIL,
)
from iotbreach.common import LAB_HOST


class TestModbusPacketBuildParse(unittest.TestCase):
    def test_read_request(self):
        pkt = build_read_request(FC_READ_HOLDING, 0, 10, transaction_id=1)
        parsed = parse_mbap(pkt)
        self.assertEqual(parsed["transaction_id"], 1)
        self.assertEqual(parsed["function_code"], FC_READ_HOLDING)
        self.assertEqual(parsed["function_name"], "Read Holding Registers (FC3)")

    def test_write_coil_request(self):
        pkt = build_write_coil_request(0, True, transaction_id=2)
        parsed = parse_mbap(pkt)
        self.assertEqual(parsed["function_code"], FC_WRITE_COIL)
        self.assertTrue(parsed["value"])
        self.assertEqual(parsed["address"], 0)

    def test_exception_response(self):
        pkt = build_exception_response(FC_READ_HOLDING, 0x02, transaction_id=3)
        parsed = parse_mbap(pkt)
        self.assertTrue(parsed["is_exception"])
        self.assertEqual(parsed["exception_code"], 0x02)

    def test_read_response(self):
        data = bytes([0x00, 0x16, 0x00, 0x37])
        pkt = build_read_response(FC_READ_HOLDING, data)
        parsed = parse_mbap(pkt)
        self.assertEqual(parsed["byte_count"], 4)


class TestModbusSlaveSim(unittest.TestCase):
    def setUp(self):
        self.slave = ModbusSlaveSim()
        self.slave.start()
        time.sleep(0.3)

    def tearDown(self):
        self.slave.stop()

    def test_read_holding_registers(self):
        result = modbus_read(LAB_HOST, self.slave.port, FC_READ_HOLDING, 0, 4)
        data = result.get("data", b"")
        self.assertEqual(len(data), 8)  # 4 registers * 2 bytes
        temp = int.from_bytes(data[0:2], "big")
        self.assertEqual(temp, 22)  # default temp setpoint

    def test_read_coils(self):
        result = modbus_read(LAB_HOST, self.slave.port, FC_READ_COILS, 0, 4)
        data = result.get("data", b"")
        self.assertGreater(len(data), 0)

    def test_write_coil_changes_state(self):
        # Read initial state
        before = modbus_read(LAB_HOST, self.slave.port, FC_READ_COILS, 0, 1)
        before_data = before.get("data", b"")
        before_state = bool(before_data[0] & 0x01) if before_data else False
        self.assertFalse(before_state)  # coil 0 starts OFF

        # Write
        result = modbus_write_coil(LAB_HOST, self.slave.port, 0, True)
        self.assertEqual(result["function_code"], FC_WRITE_COIL)

        # Verify changed
        after = modbus_read(LAB_HOST, self.slave.port, FC_READ_COILS, 0, 1)
        after_data = after.get("data", b"")
        after_state = bool(after_data[0] & 0x01) if after_data else False
        self.assertTrue(after_state)  # coil 0 now ON

    def test_write_count_increments(self):
        self.assertEqual(self.slave.write_count, 0)
        modbus_write_coil(LAB_HOST, self.slave.port, 0, True)
        self.assertEqual(self.slave.write_count, 1)
        modbus_write_coil(LAB_HOST, self.slave.port, 0, False)
        self.assertEqual(self.slave.write_count, 2)

    def test_no_auth_required(self):
        """Demonstrate that no authentication is needed (default-cred vuln)."""
        result = modbus_read(LAB_HOST, self.slave.port, FC_READ_HOLDING, 0, 2)
        self.assertIn("data", result)
        # No login, no auth token, just raw Modbus — this IS the vulnerability


if __name__ == "__main__":
    unittest.main()
