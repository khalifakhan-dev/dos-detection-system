from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = Path(__file__).with_name("settings.yaml")


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path or os.getenv("DOS_CONFIG", DEFAULT_CONFIG))
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}
    config.setdefault("api", {})["token"] = os.getenv(
        "DOS_API_TOKEN", config.get("api", {}).get("token", "")
    )
    config["_config_path"] = str(config_path)
    return config


def resolve_path(config: dict[str, Any], value: str) -> Path:
    configured = Path(value)
    if configured.is_absolute():
        return configured
    config_path = Path(config.get("_config_path", Path.cwd() / "configuration/settings.yaml"))
    return config_path.parent.parent / configured
