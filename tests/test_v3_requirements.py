from detector.detector_service import DetectorService
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import TrafficWindow
from mitigation.nftables_manager import NftablesManager
from storage.database import Database


def _thresholds():
    return {
        "syn_packets_per_second": 10,
        "syn_completion_rate_max": 0.2,
        "udp_packets_per_second": 1000,
        "udp_bytes_per_second": 1000000,
        "icmp_packets_per_second": 1000,
        "source_packets_per_second": 1000,
        "http_long_lived_connections": 2,
        "http_incomplete_connections": 2,
    }


def _attack(timestamp, source="192.0.2.10"):
    return TrafficWindow(
        timestamp=timestamp, duration_seconds=1, syn_packets=12, top_source_ip=source,
        source_stats={source: {"packets": 12, "syn_packets": 12, "ack_packets": 0}},
    )


def test_repeated_incident_calls_block_once(tmp_path):
    db = Database(tmp_path / "idempotent.sqlite3")
    service = DetectorService({"thresholds": _thresholds(), "mitigation": {"dry_run": True}}, db)
    calls = []
    original = service.nftables.block
    service.nftables.block = lambda ip, timeout: (calls.append(ip) or original(ip, timeout))
    service.process_window(_attack("2026-01-01T00:00:00+00:00"))
    service.process_window(_attack("2026-01-01T00:00:01+00:00"))
    assert calls == ["192.0.2.10"]
    assert db.events(10)[0]["event_type"] == "mitigation_skipped"
    db.close()


def test_inactivity_timeout_does_not_resolve_unrelated_source(tmp_path):
    db = Database(tmp_path / "timeout.sqlite3")
    config = {"thresholds": _thresholds(), "mitigation": {"dry_run": True, "incident_inactivity_timeout_seconds": 5}}
    service = DetectorService(config, db)
    service.process_window(_attack("2026-01-01T00:00:00+00:00"))
    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:06+00:00", source_stats={"192.0.2.11": {"packets": 1}}))
    assert db.incidents(active_only=True) == []
    service.process_window(_attack("2026-01-01T00:00:07+00:00"))
    assert len(db.incidents()) == 2
    db.close()


def test_http_attribution_is_uncertain_on_equal_tracked_sources():
    window = TrafficWindow(
        http_incomplete_connections=2,
        source_stats={
            "192.0.2.20": {"packets": 2, "http_incomplete_connections": 1},
            "192.0.2.21": {"packets": 9, "http_incomplete_connections": 1},
        },
        top_source_ip="192.0.2.21",
    )
    assert ThresholdDetector(_thresholds()).evaluate(window).source_ip is None


def test_real_ruleset_failure_is_not_ready(monkeypatch, tmp_path):
    monkeypatch.setattr(NftablesManager, "ensure_ruleset", lambda self: {"success": False, "results": [{"success": False}]})
    db = Database(tmp_path / "ruleset.sqlite3")
    service = DetectorService({"thresholds": _thresholds(), "mitigation": {"dry_run": False}}, db)
    service.start(capture=False)
    assert service.status()["mitigation_ready"] is False
    service.process_window(_attack("2026-01-01T00:00:00+00:00"))
    assert db.events(2)[0]["event_type"] == "mitigation_not_ready"
    service.stop()
