from datetime import datetime
import json

from detector.detector_service import DetectorService
from detector.traffic_models import TrafficWindow
from storage.database import Database


def thresholds():
    return {
        "syn_packets_per_second": 10,
        "syn_completion_rate_max": 0.2,
        "udp_packets_per_second": 10,
        "udp_bytes_per_second": 1000,
        "icmp_packets_per_second": 1000,
        "source_packets_per_second": 1000,
        "http_long_lived_connections": 30,
        "http_incomplete_connections": 20,
    }


def syn(ts, source):
    return TrafficWindow(
        timestamp=ts, duration_seconds=1, syn_packets=12, top_source_ip=source,
        source_stats={source: {"packets": 12, "syn_packets": 12, "ack_packets": 0}},
    )


def udp(ts, source):
    return TrafficWindow(
        timestamp=ts, duration_seconds=1, udp_packets=20, top_source_ip=source,
        source_stats={source: {"packets": 20, "udp_packets": 20, "udp_bytes": 200}},
    )


def test_timeout_is_checked_on_detection_and_silent_source_expires(tmp_path):
    db = Database(tmp_path / "silent.sqlite3")
    service = DetectorService({"thresholds": thresholds(), "mitigation": {"dry_run": True, "incident_inactivity_timeout_seconds": 5}}, db)
    service.process_window(syn("2026-01-01T00:00:00+00:00", "192.0.2.10"))
    service.process_window(syn("2026-01-01T00:00:06+00:00", "192.0.2.11"))
    active = {(row["source_ip"], row["attack_type"]) for row in db.incidents(active_only=True)}
    assert ("192.0.2.10", "TCP SYN flood") not in active
    assert ("192.0.2.11", "TCP SYN flood") in active
    db.close()


def test_recent_unrelated_active_incident_survives_timeout_check(tmp_path):
    db = Database(tmp_path / "unrelated.sqlite3")
    service = DetectorService({"thresholds": thresholds(), "mitigation": {"dry_run": True, "incident_inactivity_timeout_seconds": 5}}, db)
    service.process_window(syn("2026-01-01T00:00:00+00:00", "192.0.2.10"))
    service.process_window(syn("2026-01-01T00:00:04+00:00", "192.0.2.11"))
    service.process_window(syn("2026-01-01T00:00:06+00:00", "192.0.2.10"))
    active_sources = {row["source_ip"] for row in db.incidents(active_only=True)}
    assert active_sources == {"192.0.2.10", "192.0.2.11"}
    db.close()


def test_new_incident_gets_new_mitigation_attempt_and_recurrence_escalates(tmp_path):
    db = Database(tmp_path / "recurrence.sqlite3")
    config = {"thresholds": thresholds(), "mitigation": {"dry_run": True, "incident_inactivity_timeout_seconds": 5, "default_quarantine_seconds": 30, "escalation_quarantine_seconds": 90, "repeated_detection_window_seconds": 600}}
    service = DetectorService(config, db)
    source = "192.0.2.20"
    calls = []
    original = service.nftables.block
    service.nftables.block = lambda ip, timeout: (calls.append(timeout) or original(ip, timeout))
    service.process_window(syn("2026-01-01T00:00:00+00:00", source))
    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:01+00:00", source_stats={source: {"packets": 1}}))
    service.process_window(syn("2026-01-01T00:00:02+00:00", source))
    assert len(calls) == 2
    assert calls[1] > calls[0]
    db.close()


def test_same_incident_different_attack_types_are_independently_idempotent(tmp_path):
    db = Database(tmp_path / "types.sqlite3")
    service = DetectorService({"thresholds": thresholds(), "mitigation": {"dry_run": True}}, db)
    calls = []
    original = service.nftables.block
    service.nftables.block = lambda ip, timeout: (calls.append(ip) or original(ip, timeout))
    service.process_window(syn("2026-01-01T00:00:00+00:00", "192.0.2.30"))
    service.process_window(udp("2026-01-01T00:00:01+00:00", "192.0.2.30"))
    service.process_window(syn("2026-01-01T00:00:02+00:00", "192.0.2.30"))
    assert calls == ["192.0.2.30", "192.0.2.30"]
    assert len(db.incidents(active_only=True)) == 2
    db.close()


def test_protected_source_never_escalates_or_blocks(tmp_path):
    db = Database(tmp_path / "protected.sqlite3")
    config = {"capture": {"protected_ip": "192.0.2.40"}, "thresholds": thresholds(), "mitigation": {"dry_run": True}}
    service = DetectorService(config, db)
    service.process_window(syn("2026-01-01T00:00:00+00:00", "192.0.2.40"))
    assert db.blocks(active_only=True) == []
    db.close()
