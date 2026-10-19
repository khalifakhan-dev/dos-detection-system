from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TrafficWindow:
    timestamp: str = field(default_factory=utc_now_iso)
    duration_seconds: float = 1.0
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    syn_packets: int = 0
    ack_packets: int = 0
    udp_packets: int = 0
    udp_bytes: int = 0
    icmp_packets: int = 0
    icmp_bytes: int = 0
    unique_source_ips: int = 0
    top_source_ip: str | None = None
    top_source_packets: int = 0
    http_active_connections: int = 0
    http_incomplete_connections: int = 0
    http_long_lived_connections: int = 0
    http_max_connection_age_seconds: float = 0.0
    source_packets_per_second: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionResult:
    detected: bool
    attack_type: str | None = None
    severity: str = "normal"
    source_ip: str | None = None
    reason: str = ""
    observed: dict[str, Any] = field(default_factory=dict)
    threshold: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
