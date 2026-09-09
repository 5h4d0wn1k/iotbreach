"""Generate lab firmware fixtures for testing."""

import json
import random
import struct
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def build_fake_firmware(path: Path) -> None:
    """Build a fake firmware image with recognizable signatures and config strings."""
    data = bytearray()

    # 1. ELF header (fake, 0x100 bytes)
    elf = bytearray(0x200)
    elf[0:4] = b"\x7fELF"
    elf[4] = 1  # 32-bit
    elf[5] = 1  # little-endian
    elf[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    elf[18:20] = (40).to_bytes(2, "little")  # ARM
    elf[24:28] = (0x8000).to_bytes(4, "little")  # entry
    data += elf

    # 2. Random compressed-looking data (high entropy)
    rng = random.Random(42)
    data += bytes(rng.randrange(256) for _ in range(0x400))

    # 3. SquashFS header
    sqfs = bytearray(0x200)
    sqfs[0:4] = b"hsqs"
    sqfs[4:8] = (100).to_bytes(4, "little")  # inodes
    sqfs[8:12] = (1700000000).to_bytes(4, "little")  # mod time
    sqfs[28:32] = (4096).to_bytes(4, "little")  # block size
    sqfs[40:42] = (1).to_bytes(2, "little")  # gzip compressor
    data += sqfs

    # 4. Embedded config section
    configs = [
        b"password = labpass123",
        b'ssid = "LabWiFi-Secure"',
        b"url = https://192.0.2.50/firmware/update.bin",
        b"api_key = lab_api_test_1234",
        b"token = lab_token_fixture_v1",
        b"admin = lab-admin",
        b"version = 1.0.0",
    ]
    for cfg in configs:
        data += cfg + b"\x00"

    # 5. Filesystem paths
    paths = [
        b"/etc/passwd",
        b"/etc/config/wireless",
        b"/usr/bin/ubusd",
        b"/www/index.html",
        b"/cgi-bin/luci",
    ]
    for p in paths:
        data += p + b"\x00"

    # 6. Some padding + Network Magic strings
    data += b"\x00" * 0x100
    data += b"tcpdump" + b"\x00"
    data += b"\x00" * 0x200

    # 7. gzip magic near the end
    data += b"\x1f\x8b\x08\x00" + bytes(rng.randrange(256) for _ in range(32))

    # Write file
    path.write_bytes(bytes(data))
    print(f"Wrote fake firmware: {path} ({len(data)} bytes)")


def build_good_firmware(path: Path) -> None:
    """Build a 'patched' firmware (version 2.0.0) — good hash."""
    data = bytearray()
    data += b"\x7fELF" + b"\x00" * 48
    data += b"version = 2.0.0\x00"
    data += b"password = labpass456\x00"
    data += b"\x00" * 0x200
    path.write_bytes(bytes(data))
    print(f"Wrote patched firmware: {path} ({len(data)} bytes)")


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    build_fake_firmware(FIXTURES_DIR / "firmware_v1.bin")
    build_good_firmware(FIXTURES_DIR / "firmware_v2.bin")
    print("Fixtures generated.")


if __name__ == "__main__":
    main()