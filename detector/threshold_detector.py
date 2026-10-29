from __future__ import annotations

from typing import Any, Iterable

from .traffic_models import DetectionResult, TrafficWindow

# Rule priority: protocol-specific rules win over the generic per-source rule.
_SYN, _UDP, _ICMP, _SOURCE, _HTTP = range(5)


class ThresholdDetector:
    def __init__(self, thresholds: dict[str, Any], generic_exempt: Iterable[str] = ()):
        """generic_exempt: sources (e.g. the protected server itself, whose responses
        look like a high-rate source) that are skipped by the generic packet-rate rule only."""
        self.thresholds = thresholds
        self.generic_exempt = set(generic_exempt)

    # ---- public API -------------------------------------------------------
    def evaluate(self, window: TrafficWindow) -> DetectionResult:
        """Highest-priority detection for the window (kept for backward compatibility)."""
        results = self.evaluate_all(window)
        return results[0] if results else self.normal_result(window)

    def normal_result(self, window: TrafficWindow) -> DetectionResult:
        return DetectionResult(False, observed={"total_packets": window.total_packets, **self._common(window)})

    def evaluate_all(self, window: TrafficWindow) -> list[DetectionResult]:
        """Every offending source in the window, strongest rule first (one detection per source)."""
        duration = max(float(window.duration_seconds), 1e-9)
        common = self._common(window)
        if not window.source_stats:
            return self._aggregate(window, duration, common)
        found: list[tuple[int, float, DetectionResult]] = []
        flagged: set[str] = set()
        for ip, stats in window.source_stats.items():
            hit = self._source_rule(ip, stats, duration, common)
            if hit:
                found.append(hit)
                flagged.add(ip)
        found.extend(self._http_rules(window, flagged, common))
        # Aggregate counters remain useful when traffic is distributed across many
        # sources, but no single source can be attributed reliably. Never fall back
        # to top_source_ip for these detections.
        aggregate_types = {item[2].attack_type for item in found}
        for aggregate in self._aggregate(window, duration, common):
            if aggregate.attack_type not in aggregate_types:
                found.append((self._priority(aggregate.attack_type), 0.0, aggregate))
                aggregate_types.add(aggregate.attack_type)
        found.sort(key=lambda item: (item[0], -item[1]))
        return [result for _, _, result in found]

    # ---- per-source rules -------------------------------------------------
    def _source_rule(self, ip: str, stats: dict[str, Any], duration: float, common: dict[str, Any]) -> tuple[int, float, DetectionResult] | None:
        t = self.thresholds
        syn, acks = int(stats.get("syn_packets", 0)), int(stats.get("ack_packets", 0))
        syn_rate = syn / duration
        if syn_rate >= float(t.get("syn_packets_per_second", 250)) and self._completion_rate(syn, acks) <= float(t.get("syn_completion_rate_max", 0.20)):
            return _SYN, syn_rate, DetectionResult(True, "TCP SYN flood", "high", ip,
                "SYN rate exceeded while TCP completion proxy remained low",
                {"syn_packets": syn, "ack_packets": acks, **common},
                {"syn_packets_per_second": t.get("syn_packets_per_second"), "completion_rate_max": t.get("syn_completion_rate_max")})

        udp, udp_bytes = int(stats.get("udp_packets", 0)), int(stats.get("udp_bytes", 0))
        if udp / duration >= float(t.get("udp_packets_per_second", 500)) or udp_bytes / duration >= float(t.get("udp_bytes_per_second", 500000)):
            return _UDP, udp / duration, DetectionResult(True, "UDP flood", "high", ip,
                "UDP packet or byte rate exceeded the configured threshold",
                {"udp_packets": udp, "udp_bytes": udp_bytes, **common},
                {"udp_packets_per_second": t.get("udp_packets_per_second"), "udp_bytes_per_second": t.get("udp_bytes_per_second")})

        icmp = int(stats.get("icmp_packets", 0))
        if icmp / duration >= float(t.get("icmp_packets_per_second", 250)):
            return _ICMP, icmp / duration, DetectionResult(True, "ICMP flood", "high", ip,
                "ICMP packet rate exceeded the configured threshold",
                {"icmp_packets": icmp, "icmp_bytes": int(stats.get("icmp_bytes", 0)), **common},
                {"icmp_packets_per_second": t.get("icmp_packets_per_second")})

        packets = int(stats.get("packets", 0))
        rate = packets / duration
        if ip not in self.generic_exempt and rate >= float(t.get("source_packets_per_second", 150)):
            return _SOURCE, rate, DetectionResult(True, "Source packet flood", "high", ip,
                "Per-source packet rate exceeded the configured threshold",
                {"source_packets": packets, "source_packets_per_second": rate, **common},
                {"source_packets_per_second": t.get("source_packets_per_second", 150)})
        return None

    def _http_rules(self, window: TrafficWindow, flagged: set[str], common: dict[str, Any]) -> list[tuple[int, float, DetectionResult]]:
        t = self.thresholds
        long_thr, inc_thr = int(t.get("http_long_lived_connections", 30)), int(t.get("http_incomplete_connections", 20))
        found: list[tuple[int, float, DetectionResult]] = []
        per_source_hit = False
        for ip, stats in window.source_stats.items():
            inc, lng = int(stats.get("http_incomplete_connections", 0)), int(stats.get("http_long_lived_connections", 0))
            if inc >= inc_thr or lng >= long_thr:
                per_source_hit = True
                if ip not in flagged:
                    found.append((_HTTP, float(inc + lng), self._http_result(window, ip, common, long_thr, inc_thr)))
        # Many sources each below the per-source limit: fall back to the window total,
        # attributing only when one source clearly dominates (ties -> unknown source).
        if not per_source_hit and (window.http_long_lived_connections >= long_thr or window.http_incomplete_connections >= inc_thr):
            found.append((_HTTP, float(window.http_incomplete_connections), self._http_result(window, self._http_source(window), common, long_thr, inc_thr)))
        return found

    def _http_result(self, window: TrafficWindow, source_ip: str | None, common: dict[str, Any], long_thr: int, inc_thr: int) -> DetectionResult:
        return DetectionResult(True, "HTTP Slowloris", "medium", source_ip,
            "Long-lived or incomplete HTTP connection threshold exceeded",
            {"http_active_connections": window.http_active_connections, "http_incomplete_connections": window.http_incomplete_connections, "http_long_lived_connections": window.http_long_lived_connections, "http_max_connection_age_seconds": window.http_max_connection_age_seconds, **common},
            {"http_long_lived_connections": long_thr, "http_incomplete_connections": inc_thr, "http_connection_age_seconds": self.thresholds.get("http_connection_age_seconds")})

    # ---- aggregate-only windows (no per-source data) ----------------------
    def _aggregate(self, window: TrafficWindow, duration: float, common: dict[str, Any]) -> list[DetectionResult]:
        t = self.thresholds
        if window.syn_packets / duration >= float(t.get("syn_packets_per_second", 250)) and self._completion_rate(window.syn_packets, window.ack_packets) <= float(t.get("syn_completion_rate_max", 0.20)):
            return [DetectionResult(True, "TCP SYN flood", "high", None, "SYN rate exceeded while TCP completion proxy remained low",
                {"syn_packets": window.syn_packets, "ack_packets": window.ack_packets, **common},
                {"syn_packets_per_second": t.get("syn_packets_per_second"), "completion_rate_max": t.get("syn_completion_rate_max")})]
        if window.udp_packets / duration >= float(t.get("udp_packets_per_second", 500)) or window.udp_bytes / duration >= float(t.get("udp_bytes_per_second", 500000)):
            return [DetectionResult(True, "UDP flood", "high", None, "UDP packet or byte rate exceeded the configured threshold",
                {"udp_packets": window.udp_packets, "udp_bytes": window.udp_bytes, **common},
                {"udp_packets_per_second": t.get("udp_packets_per_second"), "udp_bytes_per_second": t.get("udp_bytes_per_second")})]
        if window.icmp_packets / duration >= float(t.get("icmp_packets_per_second", 250)):
            return [DetectionResult(True, "ICMP flood", "high", None, "ICMP packet rate exceeded the configured threshold",
                {"icmp_packets": window.icmp_packets, "icmp_bytes": window.icmp_bytes, **common},
                {"icmp_packets_per_second": t.get("icmp_packets_per_second")})]
        long_thr, inc_thr = int(t.get("http_long_lived_connections", 30)), int(t.get("http_incomplete_connections", 20))
        if window.http_long_lived_connections >= long_thr or window.http_incomplete_connections >= inc_thr:
            return [self._http_result(window, None, common, long_thr, inc_thr)]
        return []

    # ---- helpers ------------------------------------------------------------
    @staticmethod
    def _priority(attack_type: str | None) -> int:
        return {"TCP SYN flood": _SYN, "UDP flood": _UDP, "ICMP flood": _ICMP, "Source packet flood": _SOURCE, "HTTP Slowloris": _HTTP}.get(attack_type, _HTTP)

    @staticmethod
    def _common(window: TrafficWindow) -> dict[str, Any]:
        return {"top_source_ip": window.top_source_ip, "unique_source_ips": window.unique_source_ips}

    @staticmethod
    def _completion_rate(syn_packets: int, ack_packets: int) -> float:
        if syn_packets == 0:
            return 1.0
        return min(1.0, ack_packets / syn_packets)

    @staticmethod
    def _http_source(window: TrafficWindow) -> str | None:
        candidates = [(ip, int(stats.get("http_incomplete_connections", 0)) + int(stats.get("http_long_lived_connections", 0)))
                      for ip, stats in window.source_stats.items()]
        candidates = [(ip, score) for ip, score in candidates if score > 0]
        if not candidates:
            return None
        best = max(score for _, score in candidates)
        winners = [ip for ip, score in candidates if score == best]
        return winners[0] if len(winners) == 1 else None
