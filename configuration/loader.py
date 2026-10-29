from __future__ import annotations

import ipaddress
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
    config["api"] = config.get("api") or {}
    config["api"]["token"] = os.getenv("DOS_API_TOKEN", config["api"].get("token", ""))
    config["_config_path"] = str(config_path)
    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    """Fail at startup with a readable message instead of crashing mid-detection."""
    problems: list[str] = []
    for key, value in (config.get("thresholds") or {}).items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            problems.append(f"thresholds.{key} must be a non-negative number (got {value!r})")
    mitigation, capture = config.get("mitigation") or {}, config.get("capture") or {}
    trusted_ips = list(mitigation.get("trusted_ips") or [])
    protected_ip = capture.get("protected_ip") or ""
    if mitigation.get("dry_run") is False and not protected_ip:
        problems.append("capture.protected_ip must be configured before real mitigation")
    if mitigation.get("dry_run") is False and not trusted_ips:
        problems.append("mitigation.trusted_ips must include trusted management addresses before real mitigation")
    for ip in trusted_ips + ([protected_ip] if protected_ip else []):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            problems.append(f"invalid IP address in configuration: {ip!r}")
    for port in capture.get("http_ports") or []:
        if not isinstance(port, int) or not 0 < port < 65536:
            problems.append(f"capture.http_ports contains an invalid port: {port!r}")
    if problems:
        raise ValueError("Invalid configuration:\n - " + "\n - ".join(problems))


def resolve_path(config: dict[str, Any], value: str) -> Path:
    configured = Path(value)
    if configured.is_absolute():
        return configured
    config_path = Path(config.get("_config_path", Path.cwd() / "configuration/settings.yaml"))
    return config_path.parent.parent / configured
