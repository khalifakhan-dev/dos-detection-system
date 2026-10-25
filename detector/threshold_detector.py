from __future__ import annotations

from typing import Any

from .traffic_models import DetectionResult, TrafficWindow


class ThresholdDetector:
    def __init__(self, thresholds: dict[str, Any]):
        self.thresholds = thresholds

    def evaluate(self, window: TrafficWindow) -> DetectionResult:
        t = self.thresholds
        common = {"top_source_ip": window.top_source_ip,
                  "unique_source_ips": window.unique_source_ips}
        if (
            window.syn_packets >= t.get("syn_packets_per_second", 250)
            and self._completion_rate(window) <= t.get("syn_completion_rate_max", 0.20)
        ):
            return DetectionResult(
                True, "TCP SYN flood", "high", window.top_source_ip,
                "SYN rate exceeded while TCP completion proxy remained low",
                {"syn_packets": window.syn_packets,
                    "ack_packets": window.ack_packets, **common},
                {"syn_packets_per_second": t.get(
                    "syn_packets_per_second"), "completion_rate_max": t.get("syn_completion_rate_max")},
            )
        if (
            window.udp_packets >= t.get("udp_packets_per_second", 500)
            or window.udp_bytes >= t.get("udp_bytes_per_second", 500000)
        ):
            return DetectionResult(
                True, "UDP flood", "high", window.top_source_ip,
                "UDP packet or byte rate exceeded the configured threshold",
                {"udp_packets": window.udp_packets,
                    "udp_bytes": window.udp_bytes, **common},
                {"udp_packets_per_second": t.get(
                    "udp_packets_per_second"), "udp_bytes_per_second": t.get("udp_bytes_per_second")},
            )
        if window.icmp_packets >= t.get("icmp_packets_per_second", 250):
            return DetectionResult(
                True, "ICMP flood", "high", window.top_source_ip,
                "ICMP packet rate exceeded the configured threshold",
                {"icmp_packets": window.icmp_packets,
                    "icmp_bytes": window.icmp_bytes, **common},
                {"icmp_packets_per_second": t.get("icmp_packets_per_second")},
            )
        long_lived_threshold = t.get("http_long_lived_connections", 30)
        incomplete_threshold = t.get("http_incomplete_connections", 20)
        # Connection age by itself is not sufficient: normal Apache/browser
        # keep-alive connections can remain open for a long time. Require a
        # meaningful number of suspicious connections before classifying
        # Slowloris traffic.
        if (
            window.http_long_lived_connections >= long_lived_threshold
            or window.http_incomplete_connections >= incomplete_threshold
        ):
            return DetectionResult(
                True, "HTTP Slowloris", "medium", window.top_source_ip,
                "Long-lived or incomplete HTTP connection threshold exceeded",
                {"http_active_connections": window.http_active_connections, "http_incomplete_connections": window.http_incomplete_connections,
                    "http_long_lived_connections": window.http_long_lived_connections, "http_max_connection_age_seconds": window.http_max_connection_age_seconds, **common},
                {"http_long_lived_connections": long_lived_threshold, "http_incomplete_connections": incomplete_threshold,
                    "http_connection_age_seconds": t.get("http_connection_age_seconds")},
            )
        return DetectionResult(False, observed={"total_packets": window.total_packets, **common})

    @staticmethod
    def _completion_rate(window: TrafficWindow) -> float:
        if window.syn_packets == 0:
            return 1.0
        return min(1.0, window.ack_packets / window.syn_packets)
