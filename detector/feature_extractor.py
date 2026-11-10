from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Packet
except ImportError:
    IP = TCP = UDP = ICMP = Packet = Any

from .traffic_models import TrafficWindow, utc_now_iso


@dataclass
class _HttpConnection:
    source_ip: str
    started: float
    last_seen: float
    complete: bool = False
    closed: bool = False
    header: bytes = b""
    next_seq: int | None = None


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
    source_stats: dict[str, dict[str, int]] = field(default_factory=dict)


class FeatureExtractor:
    def __init__(self, window_seconds: float = 1.0, http_age_seconds: float = 30.0,
                 http_ports: tuple[int, ...] = (80,), max_http_connections: int = 50000,
                 max_http_header_bytes: int = 8192):
        self.window_seconds = window_seconds
        self.http_age_seconds = http_age_seconds
        # Only plaintext HTTP ports are meaningful: TLS payloads never expose a header terminator.
        self.http_ports = frozenset(int(p) for p in http_ports)
        self.max_http_connections = max_http_connections
        self.max_http_header_bytes = max_http_header_bytes
        self.http_table_overflows = 0
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
        stats = current.source_stats.setdefault(source_ip, {"packets": 0, "bytes": 0, "tcp_packets": 0, "syn_packets": 0, "ack_packets": 0, "udp_packets": 0, "udp_bytes": 0, "icmp_packets": 0, "icmp_bytes": 0})
        stats["packets"] += 1
        stats["bytes"] += len(packet)
        if packet.haslayer(TCP):
            current.tcp += 1
            stats["tcp_packets"] += 1
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:  # initial SYN, not SYN-ACK
                current.syn += 1
                stats["syn_packets"] += 1
            if flags & 0x10:
                current.ack += 1
                stats["ack_packets"] += 1
            if int(tcp.dport) in self.http_ports or int(tcp.sport) in self.http_ports:
                self._track_http(source_ip, str(ip.dst), tcp, flags)
        elif packet.haslayer(UDP):
            current.udp += 1
            current.udp_bytes += len(packet)
            stats["udp_packets"] += 1
            stats["udp_bytes"] += len(packet)
        elif packet.haslayer(ICMP):
            current.icmp += 1
            current.icmp_bytes += len(packet)
            stats["icmp_packets"] += 1
            stats["icmp_bytes"] += len(packet)

    def _track_http(self, source_ip: str, dst_ip: str, tcp: Any, flags: int) -> None:
        # Track only client -> configured plaintext HTTP server traffic.
        client_direction = int(tcp.dport) in self.http_ports
        key = ((source_ip, int(tcp.sport), dst_ip, int(tcp.dport)) if client_direction
               else (dst_ip, int(tcp.dport), source_ip, int(tcp.sport)))
        if flags & 0x05:  # FIN or RST from either endpoint
            connection = self._http_connections.get(key)
            if connection is not None:
                if connection.complete:
                    self._http_connections.pop(key, None)
                else:
                    # Include a closed incomplete request in this capture window
                    # only, then remove it in finish().
                    connection.closed = True
            return
        if not client_direction:
            return
        raw = bytes(tcp.payload) if getattr(tcp, "payload", None) else b""
        if not raw:
            return  # SYN/ACK handshakes alone are not HTTP requests
        now = monotonic()
        connection = self._http_connections.get(key)
        if connection is not None and connection.closed:
            self._http_connections.pop(key, None)
            connection = None
        if connection is None:
            if len(self._http_connections) >= self.max_http_connections:
                self.http_table_overflows += 1
                return
            # Do not count arbitrary non-HTTP payloads as incomplete requests.
            if not any(raw.startswith(method) for method in
                       (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                        b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")):
                return
            connection = _HttpConnection(source_ip, now, now)
            self._http_connections[key] = connection
        if connection.complete:
            return
        connection.last_seen = now
        seq = int(tcp.seq)
        if connection.next_seq is not None:
            if seq > connection.next_seq:
                # Out-of-order segments are not reassembled by this bounded parser.
                return
            overlap = connection.next_seq - seq
            if overlap >= len(raw):
                return
            raw = raw[overlap:]
        connection.next_seq = seq + len(raw)
        available = self.max_http_header_bytes - len(connection.header)
        if len(raw) > available:
            # Oversized headers cannot be safely classified: drop this state.
            self._http_connections.pop(key, None)
            return
        connection.header += raw
        if b"\r\n\r\n" in connection.header or b"\n\n" in connection.header:
            connection.complete = True

    def finish(self) -> TrafficWindow:
        current = self._window
        now = monotonic()
        stale_before = now - max(self.http_age_seconds * 2, self.window_seconds * 2, 30.0)
        self._http_connections = {key: conn for key, conn in self._http_connections.items() if conn.last_seen >= stale_before}
        ages = [now - conn.started for conn in self._http_connections.values()]
        incomplete = [conn for conn in self._http_connections.values() if not conn.complete]
        long_lived = [conn for conn in incomplete if now - conn.started >= self.http_age_seconds]
        http_by_source: dict[str, dict[str, int]] = {}
        for conn in incomplete:
            source = http_by_source.setdefault(conn.source_ip, {"http_incomplete_connections": 0, "http_long_lived_connections": 0})
            source["http_incomplete_connections"] += 1
            if now - conn.started >= self.http_age_seconds:
                source["http_long_lived_connections"] += 1
        duration = max(self.window_seconds, now - current.started)
        top_ip, top_count = current.sources.most_common(1)[0] if current.sources else (None, 0)
        source_stats = {ip: {**stats, **http_by_source.get(ip, {}), "packets_per_second": stats["packets"] / duration} for ip, stats in current.source_stats.items()}
        for ip, http_stats in http_by_source.items():
            if ip not in source_stats:
                source_stats[ip] = {"packets": 0, "bytes": 0, "tcp_packets": 0,
                                    "syn_packets": 0, "ack_packets": 0, "udp_packets": 0,
                                    "udp_bytes": 0, "icmp_packets": 0, "icmp_bytes": 0,
                                    "packets_per_second": 0.0, **http_stats}

        result = TrafficWindow(
            timestamp=utc_now_iso(), duration_seconds=duration, total_packets=current.packets, total_bytes=current.bytes,
            tcp_packets=current.tcp, syn_packets=current.syn, ack_packets=current.ack, udp_packets=current.udp,
            udp_bytes=current.udp_bytes, icmp_packets=current.icmp, icmp_bytes=current.icmp_bytes,
            unique_source_ips=len(current.sources), top_source_ip=top_ip, top_source_packets=top_count,
            http_active_connections=len(self._http_connections), http_incomplete_connections=len(incomplete),
            http_long_lived_connections=len(long_lived), http_max_connection_age_seconds=max(ages, default=0.0),
            source_packets_per_second=top_count / duration, source_stats=source_stats,
        )
        # Closed incomplete requests count for exactly one completed window.
        self._http_connections = {
            key: conn for key, conn in self._http_connections.items()
            if not conn.closed
        }
        self._window = WindowAccumulator()
        return result
