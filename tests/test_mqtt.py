"""MQTT module tests."""

import socket
import time
import unittest

from iotbreach.mqtt_module import (
    build_connect, build_connack, build_publish, build_puback,
    build_subscribe, build_suback, build_pingreq, build_pingresp,
    build_disconnect, parse_packet, decode_remaining_length,
    encode_remaining_length, MQTTBrokerSim, build_connect, recv_packet,
)
from iotbreach.common import LAB_HOST


class TestRemainingLength(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(encode_remaining_length(0), b"\x00")

    def test_127(self):
        self.assertEqual(encode_remaining_length(127), b"\x7f")

    def test_128(self):
        encoded = encode_remaining_length(128)
        self.assertEqual(len(encoded), 2)

    def test_16383(self):
        encoded = encode_remaining_length(16383)
        self.assertEqual(len(encoded), 2)

    def test_16384(self):
        encoded = encode_remaining_length(16384)
        self.assertEqual(len(encoded), 3)

    def test_roundtrip(self):
        for val in [0, 1, 127, 128, 255, 16383, 16384, 2097151, 2097152]:
            encoded = encode_remaining_length(val)
            decoded, _ = decode_remaining_length(encoded)
            self.assertEqual(decoded, val, f"Failed roundtrip for {val}")


class TestPacketBuildParse(unittest.TestCase):
    def test_connect_roundtrip(self):
        pkt = build_connect("test-client", username="user", clean_session=True)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "CONNECT")

    def test_connack(self):
        pkt = build_connack(session_present=False, return_code=0)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "CONNACK")
        self.assertFalse(parsed["session_present"])
        self.assertEqual(parsed["return_code"], 0)

    def test_publish_roundtrip(self):
        pkt = build_publish("test/topic", b"hello world", qos=0)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "PUBLISH")
        self.assertEqual(parsed["topic"], "test/topic")
        self.assertEqual(parsed["payload"], b"hello world")

    def test_publish_qos1(self):
        pkt = build_publish("test/topic", b"data", qos=1, packet_id=42)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["qos"], 1)
        self.assertEqual(parsed["packet_id"], 42)

    def test_subscribe(self):
        pkt = build_subscribe(1, "test/#", qos=1)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "SUBSCRIBE")
        self.assertEqual(parsed["packet_id"], 1)
        self.assertEqual(parsed["topics"][0]["topic"], "test/#")

    def test_suback(self):
        pkt = build_suback(1, [0, 1, 2])
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "SUBACK")
        self.assertEqual(parsed["return_codes"], [0, 1, 2])

    def test_pingreq(self):
        pkt = build_pingreq()
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "PINGREQ")

    def test_pingresp(self):
        pkt = build_pingresp()
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "PINGRESP")

    def test_disconnect(self):
        pkt = build_disconnect()
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "DISCONNECT")

    def test_puback(self):
        pkt = build_puback(42)
        parsed = parse_packet(pkt)
        self.assertEqual(parsed["type_name"], "PUBACK")
        self.assertEqual(parsed["packet_id"], 42)


class TestBrokerSim(unittest.TestCase):
    def setUp(self):
        self.broker = MQTTBrokerSim()
        self.broker.start()
        time.sleep(0.3)

    def tearDown(self):
        self.broker.stop()

    def test_connect_connack(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((LAB_HOST, self.broker.port))
        s.sendall(build_connect("test"))
        data = recv_packet(s)
        parsed = parse_packet(data)
        self.assertEqual(parsed["type_name"], "CONNACK")
        s.close()

    def test_unauth_subscribe_returns_topics(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((LAB_HOST, self.broker.port))
        s.sendall(build_connect("test"))
        recv_packet(s)
        s.sendall(build_subscribe(1, "#"))
        recv_packet(s)
        topics = []
        while True:
            try:
                data = recv_packet(s, timeout=1)
            except socket.timeout:
                break
            if data is None:
                break
            msg = parse_packet(data)
            if msg.get("topic"):
                topics.append(msg["topic"])
        s.sendall(build_disconnect())
        s.close()
        self.assertGreater(len(topics), 0)
        self.assertIn("admin/config", topics)

    def test_publish_subscribe(self):
        # Subscriber
        sub_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sub_sock.settimeout(5)
        sub_sock.connect((LAB_HOST, self.broker.port))
        sub_sock.sendall(build_connect("sub"))
        recv_packet(sub_sock)
        sub_sock.sendall(build_subscribe(1, "test/#"))
        recv_packet(sub_sock)

        time.sleep(0.1)

        # Publisher
        pub_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pub_sock.settimeout(5)
        pub_sock.connect((LAB_HOST, self.broker.port))
        pub_sock.sendall(build_connect("pub"))
        recv_packet(pub_sock)
        pub_sock.sendall(build_publish("test/hello", b"world"))
        pub_sock.sendall(build_disconnect())
        pub_sock.close()

        time.sleep(0.3)
        # Collect
        messages = []
        while True:
            try:
                data = recv_packet(sub_sock, timeout=1)
            except socket.timeout:
                break
            if data is None:
                break
            msg = parse_packet(data)
            if msg.get("topic") == "test/hello":
                messages.append(msg)
        sub_sock.close()
        self.assertTrue(any(m.get("payload") == b"world" for m in messages))


if __name__ == "__main__":
    unittest.main()
