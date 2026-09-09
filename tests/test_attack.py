"""Attack module tests."""

import time
import unittest

from iotbreach.attack_module import run_kill_chain, run_demo
from iotbreach.mqtt_module import MQTTBrokerSim
from iotbreach.modbus_module import ModbusSlaveSim
from iotbreach.common import LAB_HOST


class TestKillChain(unittest.TestCase):
    def setUp(self):
        self.mqtt_broker = MQTTBrokerSim()
        self.modbus_slave = ModbusSlaveSim()
        self.mqtt_broker.start()
        self.modbus_slave.start()
        time.sleep(0.5)

    def tearDown(self):
        self.mqtt_broker.stop()
        self.modbus_slave.stop()

    def test_dry_run(self):
        result = run_kill_chain(
            mqtt_port=self.mqtt_broker.port,
            modbus_port=self.modbus_slave.port,
            host=LAB_HOST,
            dry_run=True,
        )
        self.assertTrue(result["success"])
        self.assertGreater(len(result["phases"]), 0)
        self.assertIn("mqtt_topics", result)
        # Dry run: coil should still be OFF
        coils = self.modbus_slave.coils
        self.assertFalse(coils[0])  # heater OFF

    def test_full_run(self):
        result = run_kill_chain(
            mqtt_port=self.mqtt_broker.port,
            modbus_port=self.modbus_slave.port,
            host=LAB_HOST,
            dry_run=False,
        )
        self.assertTrue(result["success"])
        # Full run: coil should be ON
        coils = self.modbus_slave.coils
        self.assertTrue(coils[0])  # heater ON

    def test_phases_have_details(self):
        result = run_kill_chain(
            mqtt_port=self.mqtt_broker.port,
            modbus_port=self.modbus_slave.port,
            host=LAB_HOST,
            dry_run=True,
        )
        for phase in result["phases"]:
            self.assertIn("name", phase)
            self.assertIn("status", phase)
            self.assertIn("detail", phase)


class TestDemo(unittest.TestCase):
    def test_demo_runs(self):
        result = run_demo()
        # run_demo returns the kill-chain results
        self.assertIn("mqtt_topics", result)
        self.assertIn("modbus_readings", result)
        self.assertTrue(result["success"])


if __name__ == "__main__":
    unittest.main()
