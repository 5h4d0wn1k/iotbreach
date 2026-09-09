"""Firmware audit module tests."""

import unittest
from iotbreach.fwud_module import (
    parse_version, match_cves, verify_hash, detect_tamper,
    extract_version_from_binary, audit_firmware, CVE_ADVISORIES,
)
from iotbreach.common import sha256


class TestVersionParsing(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(parse_version("1.0.0"), (1, 0, 0))

    def test_with_prefix(self):
        self.assertEqual(parse_version("v1.2.3"), (1, 2, 3))


class TestCVEMatching(unittest.TestCase):
    def test_affected_version(self):
        cves = match_cves("1.0.0")
        self.assertGreater(len(cves), 0)

    def test_unaffected_version(self):
        cves = match_cves("2.0.0")
        self.assertEqual(len(cves), 0)

    def test_critical_found(self):
        cves = match_cves("1.0.0")
        severities = [c["severity"] for c in cves]
        self.assertIn("CRITICAL", severities)


class TestHashVerification(unittest.TestCase):
    def test_correct_hash(self):
        data = b"test firmware"
        h = sha256(data)
        result = verify_hash(data, h)
        self.assertTrue(result["match"])

    def test_incorrect_hash(self):
        data = b"test firmware"
        result = verify_hash(data, "0000000000000000000000000000000000000000000000000000000000000000")
        self.assertFalse(result["match"])


class TestTamperDetection(unittest.TestCase):
    def test_no_tamper(self):
        data = b"original firmware"
        h = sha256(data)
        result = detect_tamper(data, h)
        self.assertFalse(result["tampered"])

    def test_tamper_detected(self):
        data = b"original firmware"
        h = sha256(data)
        tampered = data + b" EXTRA"
        result = detect_tamper(tampered, h)
        self.assertTrue(result["tampered"])


class TestVersionExtraction(unittest.TestCase):
    def test_extract_version(self):
        data = b"firmware version 1.2.3 build 2024"
        ver = extract_version_from_binary(data)
        self.assertEqual(ver, "1.2.3")

    def test_no_version(self):
        data = b"random binary content"
        ver = extract_version_from_binary(data)
        self.assertIsNone(ver)


class TestAuditFirmware(unittest.TestCase):
    def test_full_audit(self):
        data = b"version = 1.0.0\x00/test/data\x00"
        h = sha256(data)
        result = audit_firmware(data, expected_hash=h, version_override="1.0.0")
        self.assertEqual(result["version"], "1.0.0")
        self.assertGreater(result["cve_count"], 0)
        self.assertTrue(result["hash_verification"]["match"])
        self.assertFalse(result["tamper_detection"]["tampered"])

    def test_audit_with_tamper(self):
        data = b"version = 1.0.0\x00"
        h = sha256(data)
        tampered = data + b"\xff"
        result = audit_firmware(tampered, expected_hash=h, version_override="1.0.0")
        self.assertTrue(result["tamper_detection"]["tampered"])


if __name__ == "__main__":
    unittest.main()
