"""Zigbee/433 module tests."""

import unittest
from iotbreach.zigbee_module import (
    build_zigbee_beacon, parse_zigbee_beacon,
    build_ook_packet, parse_ook_packet, _crc16,
    OOK_SYNC_PATTERN,
)


class TestZigbeeBeacon(unittest.TestCase):
    def test_build_parse(self):
        beacon = build_zigbee_beacon(pan_id=0x1A62, source_addr=0x0001,
                                      channel=15, permit_join=True)
        parsed = parse_zigbee_beacon(beacon)
        self.assertEqual(parsed["pan_id"], "0x1A62")
        self.assertEqual(parsed["source_address"], "0x0001")
        self.assertEqual(parsed["channel"], 15)
        self.assertTrue(parsed["permit_join"])

    def test_default_values(self):
        beacon = build_zigbee_beacon()
        parsed = parse_zigbee_beacon(beacon)
        self.assertEqual(parsed["channel"], 11)
        self.assertFalse(parsed["permit_join"])


class TestOOKPacket(unittest.TestCase):
    def test_build_parse_roundtrip(self):
        pkt = build_ook_packet(protocol_id=0x42, command=0x01,
                                payload=bytes([0x10, 0x20, 0x30]),
                                rolling_code=12345)
        parsed = parse_ook_packet(pkt)
        self.assertEqual(parsed["protocol_id"], 0x42)
        self.assertEqual(parsed["command"], 0x01)
        self.assertEqual(parsed["rolling_code"], 12345)
        self.assertTrue(parsed["crc_valid"])

    def test_tampered_packet_fails_crc(self):
        pkt = build_ook_packet(0x42, 0x01, b"\x10\x20\x30")
        # Tamper with a byte
        tampered = bytearray(pkt)
        tampered[4] ^= 0xFF
        parsed = parse_ook_packet(bytes(tampered))
        self.assertFalse(parsed["crc_valid"])

    def test_sync_word_found(self):
        pkt = build_ook_packet(0x01, 0x02, b"\x00")
        self.assertIn(OOK_SYNC_PATTERN, pkt)


class TestCRC16(unittest.TestCase):
    def test_deterministic(self):
        crc1 = _crc16(b"test")
        crc2 = _crc16(b"test")
        self.assertEqual(crc1, crc2)

    def test_different_inputs(self):
        crc1 = _crc16(b"test1")
        crc2 = _crc16(b"test2")
        self.assertNotEqual(crc1, crc2)


if __name__ == "__main__":
    unittest.main()
