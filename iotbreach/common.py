"""Shared constants, utilities, and safety checks for iotbreach."""

import hashlib
import os
import re
import secrets
import string
import struct
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Safety / legal
# ---------------------------------------------------------------------------
LAB_HOST = "127.0.0.1"
LAB_ONLY_RE = re.compile(r"^127\.\d+\.\d+\.\d+$|^localhost$|^::1$")

TOKEN_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[0-9]{10,}-[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),
    re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}"),
]


def assert_lab_target(target: str) -> None:
    """Raise if target is not localhost / lab."""
    if not LAB_ONLY_RE.match(target):
        raise ValueError(
            f"Target '{target}' is NOT a localhost/lab address. "
            "iotbreach only operates against 127.0.0.1/localhost targets. "
            "Refusing to proceed."
        )


def scan_for_tokens(text: str) -> list[str]:
    """Return any token-shaped literals found in text."""
    found = []
    for pat in TOKEN_PATTERNS:
        found.extend(pat.findall(text))
    return found


# ---------------------------------------------------------------------------
# Hex / byte helpers
# ---------------------------------------------------------------------------
def hexdump(data: bytes, width: int = 16) -> str:
    """Classic hexdump."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hexpart:<{width*3}}  {ascpart}")
    return "\n".join(lines)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------
def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Random lab identifiers
# ---------------------------------------------------------------------------
def random_mac() -> str:
    """Return a random locally-administered MAC (placeholder)."""
    b = secrets.token_bytes(6)
    b = bytes([b[0] | 0x02, b[1], b[2], b[3], b[4], b[5]])  # set LAA bit
    return ":".join(f"{x:02x}" for x in b)


def random_ip_lab() -> str:
    return f"192.0.2.{secrets.randbelow(254) + 1}"  # RFC 5737 TEST-NET


def random_label(prefix: str = "lab") -> str:
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    return f"{prefix}-{suffix}"
