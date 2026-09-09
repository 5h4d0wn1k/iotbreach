"""CLI tests."""

import io
import json
import sys
import time
import unittest
from contextlib import redirect_stdout

from iotbreach.cli import main
from iotbreach.mqtt_module import MQTTBrokerSim
from iotbreach.modbus_module import ModbusSlaveSim
from iotbreach.coap_module import CoAPSim
from iotbreach.can_module import CANBusSim
from iotbreach.ble_module import BLELockSim
from iotbreach.common import LAB_HOST


class TestCLIBasics(unittest.TestCase):
    def test_no_args(self):
        self.assertEqual(main([]), 0)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_help(self):
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(io.StringIO()):
                main(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class TestMQTTCli(unittest.TestCase):
    def setUp(self):
        self.broker = MQTTBrokerSim()
        self.broker.start()
        time.sleep(0.3)

    def tearDown(self):
        self.broker.stop()

    def test_subscribe_leak(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["mqtt", "subscribe", "--topic", "#", "--port", str(self.broker.port)])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("LEAKED", out)


class TestModbusCli(unittest.TestCase):
    def setUp(self):
        self.slave = ModbusSlaveSim()
        self.slave.start()
        time.sleep(0.3)

    def tearDown(self):
        self.slave.stop()

    def test_read_holding(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["modbus", "read", "--fc", "3", "--port", str(self.slave.port)])
        self.assertEqual(rc, 0)

    def test_write_coil(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["modbus", "write-coil", "--addr", "0", "--value", "1",
                       "--port", str(self.slave.port)])
        self.assertEqual(rc, 0)
        self.assertTrue(self.slave.coils[0])


class TestCoAPCli(unittest.TestCase):
    def setUp(self):
        self.sim = CoAPSim()
        self.sim.start()
        time.sleep(0.3)

    def tearDown(self):
        self.sim.stop()

    def test_get(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["coap", "get", "--path", ".well-known/core", "--port", str(self.sim.port)])
        self.assertEqual(rc, 0)

    def test_firmware_tamper(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["coap", "firmware-tamper", "--port", str(self.sim.port)])
        self.assertEqual(rc, 0)
        self.assertTrue(self.sim.firmware_accepted)


class TestParseCli(unittest.TestCase):
    def test_parse_mqtt(self):
        from iotbreach.mqtt_module import build_connect
        pkt = build_connect("test")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["parse", "mqtt", "--hex", pkt.hex()])
        self.assertEqual(rc, 0)
        self.assertIn("CONNECT", buf.getvalue())

    def test_parse_coap(self):
        from iotbreach.coap_module import build_get
        pkt = build_get("sensor/temp")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["parse", "coap", "--hex", pkt.hex()])
        self.assertEqual(rc, 0)

    def test_parse_modbus(self):
        from iotbreach.modbus_module import build_read_request
        pkt = build_read_request(3, 0, 10)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["parse", "modbus", "--hex", pkt.hex()])
        self.assertEqual(rc, 0)


class TestAttackCli(unittest.TestCase):
    def setUp(self):
        self.mqtt = MQTTBrokerSim()
        self.modbus = ModbusSlaveSim()
        self.mqtt.start()
        self.modbus.start()
        time.sleep(0.5)

    def tearDown(self):
        self.mqtt.stop()
        self.modbus.stop()

    def test_attack_run_dry(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main([
                "attack", "run", "--dry-run",
                "--mqtt-port", str(self.mqtt.port),
                "--modbus-port", str(self.modbus.port),
            ])
        self.assertEqual(rc, 0)
        # Coil should NOT be changed in dry-run
        self.assertFalse(self.modbus.coils[0])

    def test_token_scan_crypto(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["attack", "run", "--dry-run",
                       "--mqtt-port", str(self.mqtt.port),
                       "--modbus-port", str(self.modbus.port)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()