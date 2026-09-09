"""Configuration loader — YAML / JSON."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml


DEFAULTS: dict[str, Any] = {
    "general": {
        "lab_host": "127.0.0.1",
        "timeout": 10,
        "reports_dir": "reports",
    },
    "mqtt": {"port": 1883, "broker_sim_port": 11883},
    "coap": {"port": 5683, "sim_port": 15683},
    "modbus": {"port": 502, "sim_port": 15050},
    "upnp": {"ssdp_port": 1900, "sim_port": 11900},
    "can": {"sim_port": 17000},
    "ble": {"sim_port": 17001},
    "zigbee_433": {"sim_port": 17002},
    "fuzz": {"iterations": 200, "timeout": 5},
}


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load config from file, falling back to defaults."""
    cfg = dict(DEFAULTS)
    if path is None:
        path = Path("iotbreach.yaml")
    else:
        path = Path(path)
    if path.exists():
        with open(path) as f:
            if path.suffix in (".yaml", ".yml"):
                user = yaml.safe_load(f) or {}
            else:
                user = json.load(f)
        _deep_merge(cfg, user)
    return cfg


def _deep_merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
