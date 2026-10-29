import pytest

scapy = pytest.importorskip("scapy.all")
from scapy.layers.inet import IP, TCP, UDP, ICMP
from detector.feature_extractor import FeatureExtractor


def test_protocol_counts():
    extractor = FeatureExtractor()
    extractor.add_packet(IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40000, dport=80, flags="S"))
    extractor.add_packet(IP(src="192.0.2.10", dst="192.0.2.20") / UDP(sport=40000, dport=53) / b"x")
    extractor.add_packet(IP(src="192.0.2.10", dst="192.0.2.20") / ICMP())
    window = extractor.finish()
    assert window.total_packets == 3
    assert window.syn_packets == 1
    assert window.udp_packets == 1
    assert window.icmp_packets == 1
    assert window.source_stats["192.0.2.10"]["udp_packets"] == 1


def test_syn_ack_is_not_initial_syn_and_http_is_active():
    extractor = FeatureExtractor(http_age_seconds=30)
    extractor.add_packet(IP(src="192.0.2.10", dst="192.0.2.20") / TCP(sport=40000, dport=80, flags="SA"))
    extractor.add_packet(IP(src="192.0.2.11", dst="192.0.2.20") / TCP(sport=40001, dport=80, flags="S"))
    window = extractor.finish()
    assert window.syn_packets == 1
    assert window.source_stats["192.0.2.10"]["syn_packets"] == 0
    assert window.http_active_connections == 2
