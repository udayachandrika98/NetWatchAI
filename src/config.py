"""User-facing config stored as JSON (webhooks, SMTP, dedup, retention)."""
import json
import os
from copy import deepcopy
from typing import Any

from src.utils import DATA_DIR

CONFIG_PATH = os.path.join(DATA_DIR, "config.json")

DEFAULTS: dict[str, Any] = {
    "alerts": {
        "discord_webhook": "",
        "slack_webhook": "",
        "min_severity": "high",
        "email": {
            "smtp_host": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "to": "",
        },
    },
    "dedup": {
        "window_seconds": 300,
    },
    "retention_days": 30,
}


def _ensure_dir() -> None:
    os.makedirs(DATA_DIR, exist_ok=True)


def _deep_merge(base: dict, over: dict) -> dict:
    out = deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict[str, Any]:
    _ensure_dir()
    if not os.path.exists(CONFIG_PATH):
        save_config(DEFAULTS)
        return deepcopy(DEFAULTS)
    try:
        with open(CONFIG_PATH) as f:
            data = json.load(f)
        return _deep_merge(DEFAULTS, data)
    except (json.JSONDecodeError, OSError):
        return deepcopy(DEFAULTS)


def save_config(cfg: dict) -> None:
    _ensure_dir()
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
