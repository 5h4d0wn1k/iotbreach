"""Common utilities tests."""

import unittest
from iotbreach.common import (
    assert_lab_target, scan_for_tokens, hexdump, sha256, md5,
    random_mac, random_ip_lab, random_label,
)


class TestAssertLabTarget(unittest.TestCase):
    def test_localhost_passes(self):
        assert_lab_target("127.0.0.1")

    def test_localhost_name_passes(self):
        assert_lab_target("localhost")

    def test_ipv6_loopback_passes(self):
        assert_lab_target("::1")

    def test_real_ip_rejected(self):
        with self.assertRaises(ValueError):
            assert_lab_target("10.0.0.1")

    def test_public_ip_rejected(self):
        with self.assertRaises(ValueError):
            assert_lab_target("8.8.8.8")


class TestTokenScan(unittest.TestCase):
    def test_detects_akia(self):
        sample = "AKIA" + "IOSFODNN7EXAMPLE"
        found = scan_for_tokens(sample)
        self.assertEqual(len(found), 1)

    def test_detects_ghp(self):
        sample = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        found = scan_for_tokens(sample)
        self.assertEqual(len(found), 1)

    def test_no_false_positive(self):
        found = scan_for_tokens("hello world 12345")
        self.assertEqual(len(found), 0)


class TestHexdump(unittest.TestCase):
    def test_basic(self):
        result = hexdump(b"\x00\x01\x02\x03")
        self.assertIn("00000000", result)


class TestHashing(unittest.TestCase):
    def test_sha256(self):
        self.assertEqual(sha256(b"test"), "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")

    def test_md5(self):
        self.assertEqual(md5(b"test"), "098f6bcd4621d373cade4e832627b4f6")


class TestRandomGen(unittest.TestCase):
    def test_mac_format(self):
        mac = random_mac()
        self.assertRegex(mac, r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
        # Should have LAA bit set
        first_octet = int(mac.split(":")[0], 16)
        self.assertTrue(first_octet & 0x02)

    def test_ip_format(self):
        ip = random_ip_lab()
        self.assertTrue(ip.startswith("192.0.2."))

    def test_label_format(self):
        label = random_label("test")
        self.assertTrue(label.startswith("test-"))


if __name__ == "__main__":
    unittest.main()
