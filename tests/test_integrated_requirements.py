import pytest

from configuration.loader import validate_config
from detector.packet_capture import PacketCapture
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import TrafficWindow


THRESHOLDS = {
    "syn_packets_per_second": 10,
    "syn_completion_rate_max": 0.2,
    "udp_packets_per_second": 10,
    "udp_bytes_per_second": 1000,
    "icmp_packets_per_second": 10,
    "source_packets_per_second": 1000,
    "http_long_lived_connections": 30,
    "http_incomplete_connections": 20,
}


def test_aggregate_protocol_rate_is_detected_without_attacker_attribution():
    window = TrafficWindow(
        duration_seconds=1,
        top_source_ip="192.0.2.99",
        syn_packets=20,
        ack_packets=0,
        source_stats={
            "192.0.2.10": {"packets": 5, "syn_packets": 5, "ack_packets": 0},
            "192.0.2.11": {"packets": 5, "syn_packets": 5, "ack_packets": 0},
        },
    )
    result = ThresholdDetector(THRESHOLDS).evaluate(window)
    assert result.attack_type == "TCP SYN flood"
    assert result.source_ip is None


def test_packet_capture_passes_filter_and_stops_backoff(monkeypatch):
    calls = []
    capture = PacketCapture("eth0", window_seconds=0.01, bpf_filter="tcp")

    def fail_once_then_stop(**kwargs):
        calls.append(kwargs)
        capture.stop()
        raise RuntimeError("capture failure")

    monkeypatch.setattr("detector.packet_capture.sniff", fail_once_then_stop)
    monkeypatch.setattr(capture._wake, "wait", lambda _: False)
    capture.run(lambda _: None)
    assert calls[0]["filter"] == "tcp"


def test_real_mitigation_requires_explicit_safety_addresses():
    with pytest.raises(ValueError, match="protected_ip"):
        validate_config({"mitigation": {"dry_run": False, "trusted_ips": ["192.0.2.10"]}})
    with pytest.raises(ValueError, match="trusted_ips"):
        validate_config({"mitigation": {"dry_run": False}, "capture": {"protected_ip": "192.0.2.1"}})
