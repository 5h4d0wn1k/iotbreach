"""Firmware audit — version parsing, CVE mapping, hash verification, tamper detection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .common import sha256, utcnow_iso

# ---- Offline CVE advisory table (fixtures) ----
CVE_ADVISORIES: list[dict[str, Any]] = [
    {
        "cve": "CVE-2024-10001",
        "affected_versions": ["1.0.0", "1.0.1", "1.0.2"],
        "severity": "CRITICAL",
        "description": "Remote command injection in UPnP HNAP endpoint via SOAP Password field",
        "fix_version": "1.0.3",
        "category": "command_injection",
    },
    {
        "cve": "CVE-2024-10002",
        "affected_versions": ["1.0.0"],
        "severity": "HIGH",
        "description": "MQTT broker allows unauthenticated subscribe to admin/config topic",
        "fix_version": "1.0.1",
        "category": "authentication_bypass",
    },
    {
        "cve": "CVE-2024-10003",
        "affected_versions": ["1.0.0", "1.0.1"],
        "severity": "HIGH",
        "description": "Modbus slave accepts write commands without authentication",
        "fix_version": "1.0.2",
        "category": "authentication_bypass",
    },
    {
        "cve": "CVE-2024-10004",
        "affected_versions": ["1.0.0"],
        "severity": "CRITICAL",
        "description": "CoAP firmware update endpoint accepts arbitrary binary without integrity check",
        "fix_version": "1.0.3",
        "category": "insecure_update",
    },
    {
        "cve": "CVE-2024-10005",
        "affected_versions": ["1.0.0", "1.0.1", "1.0.2"],
        "severity": "MEDIUM",
        "description": "CAN bus simulation allows DoS via rapid fault counter increment",
        "fix_version": "1.0.3",
        "category": "denial_of_service",
    },
    {
        "cve": "CVE-2024-10006",
        "affected_versions": ["1.0.0"],
        "severity": "HIGH",
        "description": "BLE GATT spoofed write accepted for smart lock unlock without authentication",
        "fix_version": "1.0.1",
        "category": "authentication_bypass",
    },
    {
        "cve": "CVE-2024-10007",
        "affected_versions": ["1.0.0", "1.0.1"],
        "severity": "MEDIUM",
        "description": "Zigbee/433 OOK packet replay not detected",
        "fix_version": "1.0.2",
        "category": "replay_attack",
    },
    {
        "cve": "CVE-2024-10008",
        "affected_versions": ["1.0.0"],
        "severity": "CRITICAL",
        "description": "UPnP SSDP exposes device serial number and MAC address without authentication",
        "fix_version": "1.0.1",
        "category": "information_disclosure",
    },
]


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse semver-like string into tuple of ints."""
    parts = version_str.strip().lstrip("v").split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def match_cves(version: str, advisories: list[dict] | None = None) -> list[dict[str, Any]]:
    """Find CVEs affecting the given firmware version."""
    if advisories is None:
        advisories = CVE_ADVISORIES
    matched = []
    for adv in advisories:
        if version in adv["affected_versions"]:
            matched.append({
                "cve": adv["cve"],
                "severity": adv["severity"],
                "description": adv["description"],
                "fix_version": adv["fix_version"],
                "category": adv["category"],
            })
    return matched


def verify_hash(data: bytes, expected_hash: str, algorithm: str = "sha256") -> dict[str, Any]:
    """Verify firmware binary hash."""
    actual = hashlib.new(algorithm, data).hexdigest()
    return {
        "algorithm": algorithm,
        "expected": expected_hash,
        "actual": actual,
        "match": actual == expected_hash,
    }


def detect_tamper(data: bytes, original_hash: str) -> dict[str, Any]:
    """Detect if firmware has been tampered with since original hash was computed."""
    current_hash = sha256(data)
    tampered = current_hash != original_hash
    return {
        "original_hash": original_hash,
        "current_hash": current_hash,
        "tampered": tampered,
        "detection_time": utcnow_iso(),
    }


def extract_version_from_binary(data: bytes) -> str | None:
    """Try to find version string in firmware binary."""
    import re
    # Common version patterns
    patterns = [
        rb"(?:version|ver|v)\s*[=:]\s*([0-9]+\.[0-9]+\.[0-9]+[a-zA-Z0-9.-]*)",
        rb"([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9]+)?)",
        rb"firmware[_-]?v?([0-9]+\.[0-9]+[a-zA-Z0-9.-]*)",
    ]
    for pat in patterns:
        match = re.search(pat, data, re.IGNORECASE)
        if match:
            return match.group(1).decode("utf-8", errors="replace")
    return None


# ============================================================================
# Full audit
# ============================================================================

def audit_firmware(data: bytes, expected_hash: str | None = None,
                   version_override: str | None = None) -> dict[str, Any]:
    """Run full firmware audit."""
    version = version_override or extract_version_from_binary(data)
    if not version:
        # Try to extract from config patterns
        import re
        ver_match = re.search(rb"([0-9]+\.[0-9]+\.[0-9]+)", data)
        version = ver_match.group(1).decode() if ver_match else "0.0.0"

    cves = match_cves(version)
    hash_result = verify_hash(data, expected_hash) if expected_hash else None
    tamper = detect_tamper(data, expected_hash) if expected_hash else None

    return {
        "version": version,
        "size": len(data),
        "sha256": sha256(data),
        "cves_matched": cves,
        "cve_count": len(cves),
        "hash_verification": hash_result,
        "tamper_detection": tamper,
        "audit_time": utcnow_iso(),
    }
