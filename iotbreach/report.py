"""Report generation — JSON + Markdown."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import utcnow_iso


class ReportBuilder:
    """Collect findings and emit JSON + Markdown reports."""

    def __init__(self, title: str, reports_dir: str = "reports"):
        self.title = title
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.findings: list[dict[str, Any]] = []
        self.phases: list[dict[str, Any]] = []
        self._start = utcnow_iso()

    # ---- collectors ----
    def add_finding(self, severity: str, category: str, detail: str, **kw: Any) -> None:
        self.findings.append({
            "severity": severity,
            "category": category,
            "detail": detail,
            "meta": kw,
            "timestamp": utcnow_iso(),
        })

    def add_phase(self, name: str, status: str, detail: str, **kw: Any) -> None:
        entry = {
            "name": name,
            "status": status,
            "detail": detail,
            "meta": kw,
            "timestamp": utcnow_iso(),
        }
        for i, existing in enumerate(self.phases):
            if existing["name"] == name:
                self.phases[i] = entry
                return
        self.phases.append(entry)

    # ---- emit ----
    def build(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "generated": self._start,
            "tool": "iotbreach",
            "version": "1.0.0",
            "phases": self.phases,
            "findings": self.findings,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": _count_by(self.findings, "severity"),
                "total_phases": len(self.phases),
            },
        }

    def save(self, stem: str = "report") -> tuple[Path, Path]:
        data = self.build()
        jp = self.reports_dir / f"{stem}.json"
        mp = self.reports_dir / f"{stem}.md"
        jp.write_text(json.dumps(data, indent=2))
        mp.write_text(_to_markdown(data))
        return jp, mp


# ---- helpers ----

def _count_by(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        v = item.get(key, "unknown")
        counts[v] = counts.get(v, 0) + 1
    return counts


def _to_markdown(data: dict) -> str:
    lines = [f"# {data['title']}", "", f"Generated: {data['generated']}", ""]
    lines.append("## Phases")
    for p in data["phases"]:
        lines.append(f"- **{p['name']}** [{p['status']}]: {p['detail']}")
    lines.append("")
    lines.append("## Findings")
    if not data["findings"]:
        lines.append("_No findings._")
    for f in data["findings"]:
        lines.append(f"- [{f['severity'].upper()}] **{f['category']}**: {f['detail']}")
    lines.append("")
    lines.append("## Summary")
    s = data["summary"]
    lines.append(f"- Total findings: {s['total_findings']}")
    lines.append(f"- By severity: {s['by_severity']}")
    return "\n".join(lines) + "\n"
