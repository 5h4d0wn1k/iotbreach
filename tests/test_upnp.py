"""UPnP module tests."""

import time
import unittest

from iotbreach.upnp_module import (
    build_ssdp_discover, parse_ssdp_response, parse_device_description,
    parse_soap_request, build_ssdp_notify, UPnPSim,
    upnp_get_description, upnp_hnap_inject,
)
from iotbreach.common import LAB_HOST


class TestSSDP(unittest.TestCase):
    def test_discover_format(self):
        msg = build_ssdp_discover()
        text = msg.decode()
        self.assertIn("M-SEARCH", text)
        self.assertIn("ssdp:discover", text)

    def test_notify_format(self):
        msg = build_ssdp_notify("uuid:test", "http://127.0.0.1:80/desc.xml")
        text = msg.decode()
        self.assertIn("NOTIFY", text)
        self.assertIn("ssdp:alive", text)


class TestDeviceDescription(unittest.TestCase):
    def test_parse(self):
        xml = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <friendlyName>Test Device</friendlyName>
    <modelName>TestModel</modelName>
    <serialNumber>SN123</serialNumber>
    <MACAddress>aa:bb:cc:dd:ee:ff</MACAddress>
  </device>
</root>"""
        result = parse_device_description(xml)
        self.assertEqual(result["friendlyName"], "Test Device")
        self.assertEqual(result["modelName"], "TestModel")
        self.assertEqual(result["serialNumber"], "SN123")


class TestSOAP(unittest.TestCase):
    def test_parse_injection(self):
        soap = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:ApplyDDNSSettings xmlns:u="urn:test">
      <Password>`id`</Password>
    </u:ApplyDDNSSettings>
  </s:Body>
</s:Envelope>"""
        result = parse_soap_request(soap)
        self.assertTrue(result["injection_detected"])
        self.assertGreater(len(result["injections"]), 0)

    def test_no_injection(self):
        soap = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:Action xmlns:u="urn:test">
      <Password>normalpassword</Password>
    </u:Action>
  </s:Body>
</s:Envelope>"""
        result = parse_soap_request(soap)
        self.assertFalse(result["injection_detected"])


class TestUPnPSim(unittest.TestCase):
    def setUp(self):
        self.sim = UPnPSim()
        self.sim.start()
        time.sleep(0.5)

    def tearDown(self):
        self.sim.stop()

    def test_get_description(self):
        desc = upnp_get_description(LAB_HOST, self.sim.tcp_port)
        self.assertEqual(desc.get("modelName"), "IoT-GW-1000")
        self.assertIn("serialNumber", desc)
        self.assertIn("MACAddress", desc)

    def test_hnap_inject_triggers(self):
        upnp_hnap_inject(LAB_HOST, self.sim.tcp_port)
        self.assertTrue(self.sim.injection_triggered)

    def test_soap_log_captured(self):
        upnp_hnap_inject(LAB_HOST, self.sim.tcp_port)
        self.assertGreater(len(self.sim._soap_log), 0)
        last = self.sim._soap_log[-1]
        self.assertTrue(last.get("injection_detected"))


if __name__ == "__main__":
    unittest.main()
