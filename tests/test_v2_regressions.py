from detector.detector_service import DetectorService
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import DetectionResult, TrafficWindow
from storage.database import Database


def thresholds():
    return {
        "syn_packets_per_second": 10, "syn_completion_rate_max": 0.2,
        "udp_packets_per_second": 10, "udp_bytes_per_second": 1000,
        "icmp_packets_per_second": 10, "source_packets_per_second": 15,
        "http_long_lived_connections": 30, "http_incomplete_connections": 20,
    }


def test_protocol_precedence_and_protocol_source_attribution():
    window = TrafficWindow(
        total_packets=100, duration_seconds=1, top_source_ip="192.0.2.20",
        source_stats={
            "192.0.2.10": {"packets": 20, "syn_packets": 12, "ack_packets": 0},
            "192.0.2.20": {"packets": 80, "syn_packets": 0, "ack_packets": 0},
        },
        syn_packets=12,
    )
    result = ThresholdDetector(thresholds()).evaluate(window)
    assert result.attack_type == "TCP SYN flood"
    assert result.source_ip == "192.0.2.10"


def test_udp_and_icmp_use_their_own_source_counters():
    detector = ThresholdDetector(thresholds())
    udp = TrafficWindow(duration_seconds=1, top_source_ip="192.0.2.30", udp_packets=20,
        source_stats={"192.0.2.31": {"packets": 5, "udp_packets": 11, "udp_bytes": 100}})
    assert detector.evaluate(udp).source_ip == "192.0.2.31"
    icmp = TrafficWindow(duration_seconds=1, top_source_ip="192.0.2.30", icmp_packets=20,
        source_stats={"192.0.2.32": {"packets": 5, "icmp_packets": 11, "icmp_bytes": 200}})
    assert detector.evaluate(icmp).source_ip == "192.0.2.32"


def test_incident_deduplication_scoped_resolution_and_recurrence(tmp_path):
    db = Database(tmp_path / "incidents.sqlite3")
    config = {"thresholds": thresholds(), "mitigation": {"dry_run": True, "source_packets_per_second": 15}}
    service = DetectorService(config, db)
    attack = TrafficWindow(timestamp="2026-01-01T00:00:00+00:00", duration_seconds=1,
        syn_packets=12, top_source_ip="192.0.2.10",
        source_stats={"192.0.2.10": {"packets": 12, "syn_packets": 12, "ack_packets": 0}})
    repeat = TrafficWindow(timestamp="2026-01-01T00:00:01+00:00", duration_seconds=1,
        syn_packets=12, top_source_ip="192.0.2.10",
        source_stats={"192.0.2.10": {"packets": 12, "syn_packets": 12, "ack_packets": 0}})
    service.process_window(attack)
    service.process_window(repeat)
    assert len(db.alerts()) == 1
    assert len(db.incidents(active_only=True)) == 1

    # A clear window for another source must not resolve source 10.
    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:02+00:00", source_stats={"192.0.2.11": {"packets": 1}}))
    assert len(db.incidents(active_only=True)) == 1
    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:03+00:00", source_stats={"192.0.2.10": {"packets": 1}}))
    assert len(db.incidents(active_only=True)) == 0

    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:04+00:00", duration_seconds=1,
        syn_packets=12, top_source_ip="192.0.2.10",
        source_stats={"192.0.2.10": {"packets": 12, "syn_packets": 12, "ack_packets": 0}}))
    assert len(db.alerts()) == 2
    assert len(db.incidents()) == 2
    db.close()


def test_dry_run_is_stored_as_simulated_not_real_success(tmp_path):
    db = Database(tmp_path / "dry.sqlite3")
    config = {"thresholds": thresholds(), "mitigation": {"dry_run": True, "default_quarantine_seconds": 30}}
    service = DetectorService(config, db)
    result = service.permanent_block("192.0.2.55")
    assert result["success"] is True and result["dry_run"] is True and result["outcome"] == "simulated"
    assert db.blocks(active_only=True)[0]["dry_run"] == 1
    assert db.events(1)[0]["event_type"] == "mitigation_simulated"
    db.close()
