"""CoAP module tests."""

import time
import unittest
from iotbreach.coap_module import (
    build_message, parse_message, build_get, build_post, build_put,
    CoAPSim, coap_get, coap_put, build_well_known_core,
    CON, ACK, GET, PUT, POST, CODE_2_04, CODE_2_05, CODE_4_04,
)
from iotbreach.common import LAB_HOST, sha256


class TestCoAPPacketBuildParse(unittest.TestCase):
    def test_build_get_parse(self):
        pkt = build_get("sensor/temperature", msg_id=1)
        parsed = parse_message(pkt)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual(parsed["type_name"], "CON")
        self.assertEqual(parsed["method"], "GET")
        self.assertEqual(parsed["uri_path"], "sensor/temperature")
        self.assertEqual(parsed["msg_id"], 1)

    def test_build_put_parse(self):
        payload = b"\x89PNG" + b"\x00" * 32
        pkt = build_put("firmware/update", payload, msg_id=42)
        parsed = parse_message(pkt)
        self.assertEqual(parsed["method"], "PUT")
        self.assertEqual(parsed["uri_path"], "firmware/update")
        self.assertEqual(parsed["payload"], payload)

    def test_well_known_core(self):
        resp = build_well_known_core()
        self.assertIn(b"sensor/temperature", resp)
        self.assertIn(b"firmware/update", resp)

    def test_roundtrip(self):
        original = build_message(CON, GET, 99, token=bytes([0xAB, 0xCD]),
                                  options=[(11, b"test"), (12, b"\x00")], payload=b"")
        parsed = parse_message(original)
        self.assertEqual(parsed["version"], 1)
        self.assertEqual(parsed["msg_id"], 99)


class TestCoAPSim(unittest.TestCase):
    def setUp(self):
        self.sim = CoAPSim()
        self.sim.start()
        time.sleep(0.3)

    def tearDown(self):
        self.sim.stop()

    def test_resource_discovery(self):
        resp = coap_get(LAB_HOST, self.sim.port, ".well-known/core")
        self.assertIn(b"sensor/temperature", resp["payload"])

    def test_get_resource(self):
        resp = coap_get(LAB_HOST, self.sim.port, "sensor/temperature")
        self.assertEqual(resp["code_str"], "2.05")
        self.assertEqual(resp["payload"], b"\x1a\x2b\x3c")

    def test_get_404(self):
        resp = coap_get(LAB_HOST, self.sim.port, "nonexistent")
        self.assertEqual(resp["code"], 0x84)  # 4.04

    def test_firmware_tamper_accepted(self):
        old_hash = self.sim.firmware_hash
        new_fw = b"\x89PNG" + b"\xff" * 64
        resp = coap_put(LAB_HOST, self.sim.port, "firmware/update", new_fw)
        new_hash = self.sim.firmware_hash
        self.assertEqual(resp["code"], 0x44)  # 2.04 Changed
        self.assertNotEqual(old_hash, new_hash)
        self.assertTrue(self.sim.firmware_accepted)

    def test_firmware_verify(self):
        resp = coap_get(LAB_HOST, self.sim.port, "firmware/verify")
        self.assertEqual(resp["code_str"], "2.05")


if __name__ == "__main__":
    unittest.main()
