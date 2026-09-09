"""Firmware extraction module tests."""

import unittest
from iotbreach.firmware_module import (
    extract_signatures, parse_elf_header, entropy_map, grep_embedded_config,
    list_filesystem_entries, analyze_firmware, _crc32,
)
from iotbreach.common import sha256


class TestSignatures(unittest.TestCase):
    def test_finds_elf(self):
        data = b"\x7fELF" + b"\x00" * 48
        sigs = extract_signatures(data)
        elf_sigs = [s for s in sigs if "ELF" in s["description"]]
        self.assertGreater(len(elf_sigs), 0)

    def test_finds_gzip(self):
        data = b"\x1f\x8b" + b"\x00" * 100
        sigs = extract_signatures(data)
        gzip_sigs = [s for s in sigs if "gzip" in s["description"]]
        self.assertGreater(len(gzip_sigs), 0)


class TestELF(unittest.TestCase):
    def test_parse_elf(self):
        # Minimal ELF header (32-bit, little-endian, executable)
        header = bytearray(52)
        header[0:4] = b"\x7fELF"
        header[4] = 1  # 32-bit
        header[5] = 1  # little-endian
        header[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
        header[18:20] = (40).to_bytes(2, "little")  # ARM
        header[24:28] = (0x8000).to_bytes(4, "little")  # entry
        result = parse_elf_header(bytes(header))
        self.assertEqual(result["class"], "32-bit")
        self.assertEqual(result["endian"], "Little-endian")
        self.assertEqual(result["entry_point"], 0x8000)


class TestEntropy(unittest.TestCase):
    def test_entropy_range(self):
        data = bytes(range(256)) * 4  # all byte values, high entropy
        result = entropy_map(data, block_size=256)
        self.assertGreater(len(result), 0)
        for block in result:
            self.assertGreater(block["entropy"], 0)
            self.assertLessEqual(block["entropy"], 8.0)


class TestEmbeddedConfig(unittest.TestCase):
    def test_finds_password(self):
        data = b"password = secret123\nadmin = root\n"
        findings = grep_embedded_config(data)
        categories = [f["category"] for f in findings]
        self.assertIn("password", categories)
        self.assertIn("admin credential", categories)

    def test_finds_ssid(self):
        data = b'ssid = "MyWiFiNetwork"\n'
        findings = grep_embedded_config(data)
        self.assertTrue(any(f["category"] == "SSID" for f in findings))


class TestFilesystemEntries(unittest.TestCase):
    def test_finds_paths(self):
        data = b"\x00" * 100 + b"/etc/passwd\x00" + b"/usr/bin/sh\x00" + b"\x00" * 100
        entries = list_filesystem_entries(data)
        paths = [e["path"] for e in entries]
        self.assertIn("/etc/passwd", paths)
        self.assertIn("/usr/bin/sh", paths)


class TestAnalyzeFirmware(unittest.TestCase):
    def test_full_analysis(self):
        data = b"\x7fELF" + b"\x00" * 48 + b"password = labpass123\x00" + b"/etc/config\x00"
        result = analyze_firmware(data)
        self.assertIn("checksums", result)
        self.assertIn("signatures", result)
        self.assertIn("entropy_summary", result)
        self.assertIn("embedded_config", result)
        self.assertEqual(result["checksums"]["sha256"], sha256(data))
        self.assertGreater(len(result["embedded_config"]), 0)


class TestCRC32(unittest.TestCase):
    def test_known_value(self):
        result = _crc32(b"123456789")
        self.assertEqual(result, "cbf43926")


if __name__ == "__main__":
    unittest.main()
