from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Packet
except ImportError:  # Allows non-Scapy unit imports before dependencies are installed.
    IP = TCP = UDP = ICMP = Packet = Any

from .traffic_models import TrafficWindow, utc_now_iso


@dataclass
class _HttpConnection:
    source_ip: str
    started: float
    last_seen: float
    complete: bool = False


@dataclass
class WindowAccumulator:
    started: float = field(default_factory=monotonic)
    packets: int = 0
    bytes: int = 0
    tcp: int = 0
    syn: int = 0
    ack: int = 0
    udp: int = 0
    udp_bytes: int = 0
    icmp: int = 0
    icmp_bytes: int = 0
    sources: Counter[str] = field(default_factory=Counter)
    http: dict[tuple[str, int, str, int], _HttpConnection] = field(default_factory=dict)


class FeatureExtractor:
    def __init__(self, window_seconds: float = 1.0, http_age_seconds: float = 30.0):
        self.window_seconds = window_seconds
        self.http_age_seconds = http_age_seconds
        self._window = WindowAccumulator()
        self._http_connections: dict[tuple[str, int, str, int], _HttpConnection] = {}

    def add_packet(self, packet: Packet) -> None:
        current = self._window
        current.packets += 1
        current.bytes += len(packet)
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        source_ip = str(ip.src)
        current.sources[source_ip] += 1
        if packet.haslayer(TCP):
            current.tcp += 1
            tcp = packet[TCP]
            flags = int(tcp.flags)
            # SYN is bit 0x02; ACK is bit 0x10 in TCP flags.
            if flags & 0x02:
                current.syn += 1
            if flags & 0x10:
                current.ack += 1
            if int(tcp.dport) in (80, 443) or int(tcp.sport) in (80, 443):
                key = (source_ip, int(tcp.sport), str(ip.dst), int(tcp.dport))
                connection = self._http_connections.get(key)
                if connection is None:
                    connection = _HttpConnection(source_ip, monotonic(), monotonic())
                    self._http_connections[key] = connection
                connection.last_seen = monotonic()
                raw = bytes(tcp.payload) if getattr(tcp, "payload", None) else b""
                if b"\r\n\r\n" in raw or b"\n\n" in raw:
                    connection.complete = True
        elif packet.haslayer(UDP):
            current.udp += 1
            current.udp_bytes += len(packet)
        elif packet.haslayer(ICMP):
            current.icmp += 1
            current.icmp_bytes += len(packet)

    def finish(self) -> TrafficWindow:
        current = self._window
        now = monotonic()
        # Remove connections that have been quiet for two windows. This keeps
        # long-lived Slowloris connections while preventing stale state growth.
        stale_before = now - max(300.0, self.window_seconds * 2)
        self._http_connections = {
            key: conn for key, conn in self._http_connections.items()
            if conn.last_seen >= stale_before
        }
        ages = [now - conn.started for conn in self._http_connections.values()]
        incomplete = [conn for conn in self._http_connections.values() if not conn.complete]
        long_lived = [conn for conn in incomplete if now - conn.started >= self.http_age_seconds]
        duration = max(self.window_seconds, now - current.started)
        top_ip, top_count = current.sources.most_common(1)[0] if current.sources else (None, 0)
        result = TrafficWindow(
            timestamp=utc_now_iso(),
            duration_seconds=duration,
            total_packets=current.packets,
            total_bytes=current.bytes,
            tcp_packets=current.tcp,
            syn_packets=current.syn,
            ack_packets=current.ack,
            udp_packets=current.udp,
            udp_bytes=current.udp_bytes,
            icmp_packets=current.icmp,
            icmp_bytes=current.icmp_bytes,
            unique_source_ips=len(current.sources),
            top_source_ip=top_ip,
            top_source_packets=top_count,
            http_active_connections=len(current.http),
            http_incomplete_connections=len(incomplete),
            http_long_lived_connections=len(long_lived),
            http_max_connection_age_seconds=max(ages, default=0.0),
            source_packets_per_second=top_count / duration,
        )
        self._window = WindowAccumulator()
        return result
