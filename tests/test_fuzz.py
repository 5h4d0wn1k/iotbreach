"""Fuzz module tests."""

import time
import unittest

from iotbreach.fuzz_module import (
    mutate_byte_flip, mutate_byte_replace, mutate_truncate,
    mutate_grow, mutate_zero_fill, mutate_ones_fill,
    ProtocolFuzzer, tcp_send, udp_send, fuzz_protocol,
    get_modbus_read_fixture, get_mqtt_connect_fixture,
)
from iotbreach.mqtt_module import MQTTBrokerSim, build_connect
from iotbreach.modbus_module import ModbusSlaveSim
from iotbreach.common import LAB_HOST


class TestMutators(unittest.TestCase):
    def test_byte_flip(self):
        data = b"\x00\x00\x00\x00"
        result = mutate_byte_flip(data, count=2)
        self.assertEqual(len(result), len(data))

    def test_byte_replace(self):
        data = b"\x00\x00\x00\x00"
        result = mutate_byte_replace(data, count=2)
        self.assertEqual(len(result), len(data))

    def test_truncate(self):
        data = b"\x00" * 10
        result = mutate_truncate(data)
        self.assertLess(len(result), len(data))

    def test_grow(self):
        data = b"\x00" * 4
        result = mutate_grow(data)
        self.assertGreater(len(result), len(data))

    def test_zero_fill(self):
        data = b"\xff" * 4
        result = mutate_zero_fill(data)
        self.assertEqual(result, b"\x00\x00\x00\x00")

    def test_ones_fill(self):
        data = b"\x00" * 4
        result = mutate_ones_fill(data)
        self.assertEqual(result, b"\xff\xff\xff\xff")


class TestFuzzer(unittest.TestCase):
    def setUp(self):
        self.broker = MQTTBrokerSim()
        self.broker.start()
        time.sleep(0.3)

    def tearDown(self):
        self.broker.stop()

    def test_fuzz_mqtt(self):
        fixture = build_connect("fuzz-client")
        fuzzer = ProtocolFuzzer(
            "mqtt", fixture,
            lambda data: tcp_send(LAB_HOST, self.broker.port, data),
            iterations=50,
        )
        result = fuzzer.run()
        self.assertGreater(result["cases_run"], 0)
        # May or may not find anomalies depending on mutations
        self.assertIn("anomalies_found", result)


class TestFuzzerFindsAnomaly(unittest.TestCase):
    """Guaranteed ≥1 anomaly: fuzz Modbus with truncation/overrides."""

    def setUp(self):
        self.slave = ModbusSlaveSim()
        self.slave.start()
        time.sleep(0.3)

    def tearDown(self):
        self.slave.stop()

    def test_fuzz_modbus_finds_anomalies(self):
        fixture = get_modbus_read_fixture()
        fuzzer = ProtocolFuzzer(
            "modbus", fixture,
            lambda data: tcp_send(LAB_HOST, self.slave.port, data),
            iterations=80,
        )
        result = fuzzer.run()
        self.assertGreaterEqual(result["anomalies_found"], 1)

    def test_fuzz_protocol_wrapper(self):
        result = fuzz_protocol(
            "modbus", get_modbus_read_fixture(),
            host=LAB_HOST, port=self.slave.port, protocol="tcp",
            iterations=40,
        )
        self.assertGreaterEqual(result["anomalies_found"], 1)


if __name__ == "__main__":
    unittest.main()
