"""BLE module tests."""

import time
import unittest
from iotbreach.ble_module import (
    build_adv_pdu, parse_adv_pdu, crc24,
    build_att_read_req, build_att_read_rsp, build_att_write_cmd, build_att_write_rsp,
    build_att_error, parse_att,
    BLELockSim, ble_read_battery, ble_read_lock_state, ble_spoof_unlock,
    ATT_OP_READ_REQ, ATT_OP_WRITE_CMD, ATT_OP_WRITE_RSP,
)
from iotbreach.common import LAB_HOST


class TestCRC24(unittest.TestCase):
    def test_known_value(self):
        # CRC-24 should be deterministic
        crc = crc24(b"\x01\x02\x03")
        self.assertIsInstance(crc, int)
        self.assertTrue(0 <= crc <= 0xFFFFFF)

    def test_empty(self):
        crc = crc24(b"")
        self.assertIsInstance(crc, int)


class TestADV(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        adv = build_adv_pdu(0x00, adv_addr="00:11:22:33:44:55", adv_data=b"\x02\x01\x06")
        parsed = parse_adv_pdu(adv)
        self.assertEqual(parsed["pdu_type_name"], "ADV_IND")
        self.assertEqual(parsed["adv_addr"], "00:11:22:33:44:55")
        self.assertTrue(parsed["crc_valid"])


class TestATT(unittest.TestCase):
    def test_read_req(self):
        pkt = build_att_read_req(0x0001)
        parsed = parse_att(pkt)
        self.assertEqual(parsed["opcode_name"], "READ_REQ")
        self.assertEqual(parsed["handle"], 0x0001)

    def test_read_rsp(self):
        pkt = build_att_read_rsp(b"\x55")
        parsed = parse_att(pkt)
        self.assertEqual(parsed["opcode_name"], "READ_RSP")
        self.assertEqual(parsed["value"], b"\x55")

    def test_write_cmd(self):
        pkt = build_att_write_cmd(0x0003, bytes([0x01]))
        parsed = parse_att(pkt)
        self.assertEqual(parsed["opcode_name"], "WRITE_CMD")
        self.assertEqual(parsed["handle"], 0x0003)
        self.assertEqual(parsed["value"], bytes([0x01]))

    def test_write_rsp(self):
        pkt = build_att_write_rsp()
        parsed = parse_att(pkt)
        self.assertEqual(parsed["opcode_name"], "WRITE_RSP")

    def test_error(self):
        pkt = build_att_error(ATT_OP_READ_REQ, 0x0001, 0x0A)
        parsed = parse_att(pkt)
        self.assertEqual(parsed["opcode_name"], "ERROR")
        self.assertEqual(parsed["error_code"], 0x0A)


class TestBLELockSim(unittest.TestCase):
    def setUp(self):
        self.lock = BLELockSim()
        self.lock.start()
        time.sleep(0.3)

    def tearDown(self):
        self.lock.stop()

    def test_read_battery(self):
        result = ble_read_battery(LAB_HOST, self.lock.port)
        self.assertEqual(result["opcode_name"], "READ_RSP")
        self.assertEqual(result["value"], bytes([85]))

    def test_read_lock_state(self):
        result = ble_read_lock_state(LAB_HOST, self.lock.port)
        self.assertEqual(result["opcode_name"], "READ_RSP")
        self.assertEqual(result["value"], bytes([0x00]))  # locked

    def test_spoof_unlock_opens_lock(self):
        result = ble_spoof_unlock(LAB_HOST, self.lock.port)
        self.assertTrue(self.lock.lock_opened)
        # Verify lock state updated
        lock_state = self.lock.gatt_db[0x0002]["value"]
        self.assertEqual(lock_state, bytes([0x01]))  # unlocked


if __name__ == "__main__":
    unittest.main()
