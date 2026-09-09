"""Firmware image extractor — binwalk-style signature/offset parsing, entropy map, embedded-config grep."""

from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Any

# ---- Known signatures (offset, magic bytes, description, handler) ----
SIGNATURES = [
    (b"\x89PNG", "PNG image header"),
    (b"\x7fELF", "ELF binary"),
    (b"hsqs", "SquashFS (little-endian)"),
    (b"sqsh", "SquashFS (big-endian)"),
    (b"UBI#", "UBI image"),
    (b"UBIFS", "UBIFS filesystem"),
    (b"\x1f\x8b", "gzip compressed"),
    (b"BZh", "bzip2 compressed"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"ustar", "tar archive"),
    (b"TRAIL!!!", "TRAIL marker (end-of-image)"),
    (b"\xfd7zXZ", "XZ compressed"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"LZMA", "LZMA compressed"),
    (b"\x02!L\x18", "uImage header"),
    (b"\x27\x05\x19\x56", "zImage (ARM Linux)"),
    (b"MZ", "PE/COFF / DOS MZ"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x00ASM", "WebAssembly"),
    (b"ID3", "MP3 ID3 tag"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"RIFF", "RIFF container"),
]

# ELF header parsing
ELF_MAGIC = b"\x7fELF"
ELF_CLASS = {1: "32-bit", 2: "64-bit"}
ELF_ENDIAN = {1: "Little-endian", 2: "Big-endian"}
ELF_TYPE = {1: "Relocatable", 2: "Executable", 3: "Shared object", 4: "Core"}

# SquashFS header (at magic offset)
SQFS_COMPRESSION = {1: "gzip", 2: "lzo", 3: "xz", 4: "lz4", 5: "zstd"}

# Embedded config patterns
CONFIG_PATTERNS = [
    (re.compile(rb"(?:password|passwd|pwd)\s*[=:]\s*(\S+)"), "password"),
    (re.compile(rb"(?:ssid|SSID)\s*[=:]\s*[\"']?(\S+)[\"']?"), "SSID"),
    (re.compile(rb"(?:url|URL)\s*[=:]\s*[\"']?(https?://\S+)[\"']?"), "URL"),
    (re.compile(rb"(?:key|KEY|secret|SECRET)\s*[=:]\s*[\"']?(\S+)[\"']?"), "API key/secret"),
    (re.compile(rb"(?:api[_-]?key|apikey|APIKEY)\s*[=:]\s*[\"']?(\S+)[\"']?"), "API key"),
    (re.compile(rb"(?:token|TOKEN)\s*[=:]\s*[\"']?(\S+)[\"']?"), "token"),
    (re.compile(rb"(?:admin|ADMIN)\s*[=:]\s*[\"']?(\S+)[\"']?"), "admin credential"),
]


def extract_signatures(data: bytes) -> list[dict[str, Any]]:
    """Find all known magic-byte signatures in firmware image."""
    found = []
    for magic, desc in SIGNATURES:
        offset = 0
        while True:
            idx = data.find(magic, offset)
            if idx == -1:
                break
            found.append({
                "offset": idx,
                "magic": magic.hex(),
                "description": desc,
                "size_hint": _estimate_size(data, idx, magic),
            })
            offset = idx + 1
    return found


def _estimate_size(data: bytes, offset: int, magic: bytes) -> str:
    """Heuristic size estimate from surrounding context."""
    if magic == b"\x7fELF":
        if offset + 20 <= len(data):
            phoff = int.from_bytes(data[offset + 28: offset + 32], "little")
            return f"ELF with phoff=0x{phoff:x}"
    return "unknown"


def parse_elf_header(data: bytes) -> dict[str, Any]:
    """Parse ELF header fields from offset 0."""
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        return {"error": "Not a valid ELF"}
    return {
        "class": ELF_CLASS.get(data[4], f"Unknown ({data[4]})"),
        "endian": ELF_ENDIAN.get(data[5], f"Unknown ({data[5]})"),
        "type": ELF_TYPE.get(int.from_bytes(data[16:18], "little"), "Unknown"),
        "machine": int.from_bytes(data[18:20], "little"),
        "entry_point": int.from_bytes(data[24:28], "little"),
    }


def parse_squashfs_header(data: bytes) -> dict[str, Any]:
    """Parse SquashFS header at the magic offset."""
    idx = data.find(b"hsqs")
    if idx == -1:
        idx = data.find(b"sqsh")
        if idx == -1:
            return {"error": "No SquashFS magic found"}
        big_endian = True
    else:
        big_endian = False
    endian = "big" if big_endian else "little"
    if idx + 64 > len(data):
        return {"error": "Truncated SquashFS header"}
    return {
        "offset": idx,
        "inodes": int.from_bytes(data[idx+4:idx+8], endian),
        "modification_time": int.from_bytes(data[idx+8:idx+12], endian),
        "block_size": int.from_bytes(data[idx+28:idx+32], endian),
        "fragments": int.from_bytes(data[idx+32:idx+36], endian),
        "compressor": SQFS_COMPRESSION.get(int.from_bytes(data[idx+40:idx+42], endian), "unknown"),
    }


def entropy_map(data: bytes, block_size: int = 256) -> list[dict[str, Any]]:
    """Compute Shannon entropy per block."""
    result = []
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if not block:
            continue
        freq = [0] * 256
        for b in block:
            freq[b] += 1
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / len(block)
                ent -= p * math.log2(p)
        result.append({
            "offset": i,
            "size": len(block),
            "entropy": round(ent, 4),
        })
    return result


def grep_embedded_config(data: bytes) -> list[dict[str, Any]]:
    """Search for embedded credentials, keys, URLs, SSIDs."""
    findings = []
    for pattern, category in CONFIG_PATTERNS:
        for match in pattern.finditer(data):
            val = match.group(1).decode("utf-8", errors="replace")
            # Trim at terminators a typical config value may carry
            for term in ("\x00", '"', "'", " "):
                idx = val.find(term)
                if idx != -1:
                    val = val[:idx]
            # Filter out obviously non-secret hex/filler
            if len(val) >= 3:
                findings.append({
                    "category": category,
                    "value": val,
                    "offset": match.start(),
                })
    return findings


def list_filesystem_entries(data: bytes) -> list[dict[str, Any]]:
    """
    Heuristic: scan for common filesystem paths in the raw image.
    (Lightweight binwalk-like approach — look for path strings.)
    """
    paths_found = set()
    # Common embedded Linux paths
    path_re = re.compile(rb"(/(?:etc|usr|var|tmp|proc|dev|bin|sbin|lib|opt|mnt|root|home|www|cgi-bin)/[\w./_-]{3,80})")
    for match in path_re.finditer(data):
        path = match.group(1).decode("utf-8", errors="replace")
        paths_found.add(path)
    return [{"path": p, "offset": data.find(p.encode())} for p in sorted(paths_found)]


# ============================================================================
# High-level extractor
# ============================================================================

def analyze_firmware(data: bytes) -> dict[str, Any]:
    """Full firmware analysis pipeline."""
    checksums = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "crc32": _crc32(data),
    }
    signatures = extract_signatures(data)
    entropy = entropy_map(data)
    config_findings = grep_embedded_config(data)
    fs_entries = list_filesystem_entries(data)

    # Check for ELF
    elf_header = None
    if data[:4] == ELF_MAGIC:
        elf_header = parse_elf_header(data)

    # Check for SquashFS
    squashfs = None
    if b"hsqs" in data or b"sqsh" in data:
        squashfs = parse_squashfs_header(data)

    return {
        "size": len(data),
        "checksums": checksums,
        "signatures": signatures,
        "elf_header": elf_header,
        "squashfs": squashfs,
        "entropy_summary": {
            "mean": round(sum(e["entropy"] for e in entropy) / len(entropy), 4) if entropy else 0,
            "max": round(max((e["entropy"] for e in entropy), default=0), 4),
            "min": round(min((e["entropy"] for e in entropy), default=0), 4),
            "blocks": len(entropy),
        },
        "entropy_map": entropy,
        "embedded_config": config_findings,
        "filesystem_entries": fs_entries,
    }


def _crc32(data: bytes) -> str:
    """CRC32 as hex string."""
    import zlib
    return format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
