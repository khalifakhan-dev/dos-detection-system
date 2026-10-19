from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import TrafficWindow


def detector() -> ThresholdDetector:
    return ThresholdDetector({
        "syn_packets_per_second": 10,
        "syn_completion_rate_max": 0.2,
        "udp_packets_per_second": 10,
        "udp_bytes_per_second": 1000,
        "icmp_packets_per_second": 10,
        "http_long_lived_connections": 3,
        "http_incomplete_connections": 2,
        "http_connection_age_seconds": 30,
    })


def test_syn_flood_detection():
    result = detector().evaluate(TrafficWindow(syn_packets=20, ack_packets=1, top_source_ip="192.0.2.10"))
    assert result.detected is True
    assert result.attack_type == "TCP SYN flood"


def test_udp_flood_detection():
    result = detector().evaluate(TrafficWindow(udp_packets=11, top_source_ip="192.0.2.11"))
    assert result.attack_type == "UDP flood"


def test_icmp_flood_detection():
    result = detector().evaluate(TrafficWindow(icmp_packets=11, top_source_ip="192.0.2.12"))
    assert result.attack_type == "ICMP flood"


def test_slowloris_detection():
    result = detector().evaluate(TrafficWindow(http_incomplete_connections=3, top_source_ip="192.0.2.13"))
    assert result.attack_type == "HTTP Slowloris"


def test_normal_traffic():
    result = detector().evaluate(TrafficWindow(total_packets=4, tcp_packets=4, ack_packets=3))
    assert result.detected is False
