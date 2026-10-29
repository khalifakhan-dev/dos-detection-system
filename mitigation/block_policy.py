from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from detector.traffic_models import DetectionResult, utc_now_iso


class ProtectedAddressError(ValueError):
    """Raised when an action would block a trusted or protected address."""


class BlockPolicy:
    def __init__(self, config: dict[str, Any]):
        mitigation = config.get("mitigation", {})
        self.default_seconds = int(mitigation.get("default_quarantine_seconds", 300))
        self.escalation_seconds = int(mitigation.get("escalation_quarantine_seconds", 900))
        self.repeated_limit = int(mitigation.get("repeated_detection_limit", 2))
        self.trusted_ips = {str(ipaddress.ip_address(ip)) for ip in mitigation.get("trusted_ips", [])}
        protected_ip = config.get("capture", {}).get("protected_ip", "")
        if protected_ip:
            self.trusted_ips.add(str(ipaddress.ip_address(protected_ip)))

    def is_trusted(self, ip: str) -> bool:
        return str(ipaddress.ip_address(ip)) in self.trusted_ips

    def decide(self, result: DetectionResult, previous_count: int = 0, permanent: bool = False) -> dict[str, Any] | None:
        """previous_count = number of automatic blocks already applied to this source recently."""
        if not result.detected or not result.source_ip:
            return None
        source_ip = str(ipaddress.ip_address(result.source_ip))
        if source_ip in self.trusted_ips:
            return None
        now = datetime.now(timezone.utc)
        escalated = previous_count + 1 >= self.repeated_limit
        mode = "permanent" if permanent else "temporary"
        duration = self.escalation_seconds if escalated else self.default_seconds
        return {"ip": source_ip, "mode": mode, "status": "active", "reason": result.reason,
                "attack_type": result.attack_type, "created_at": utc_now_iso(),
                "expires_at": None if mode == "permanent" else (now + timedelta(seconds=duration)).isoformat(),
                "updated_at": utc_now_iso()}
