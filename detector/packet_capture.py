from __future__ import annotations

import logging
import threading
from typing import Callable

from scapy.all import conf, get_if_addr, sniff

from .feature_extractor import FeatureExtractor
from .traffic_models import TrafficWindow

logger = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, interface: str = "auto", window_seconds: float = 1.0, http_age_seconds: float = 30.0,
                 http_ports: tuple[int, ...] = (80,), bpf_filter: str = "ip"):
        self.interface = interface
        self.extractor = FeatureExtractor(window_seconds, http_age_seconds, http_ports)
        self.window_seconds = window_seconds
        self.bpf_filter = bpf_filter or None  # IPv4 only; the detector does not analyse IPv6
        self.running = False
        self._wake = threading.Event()

    def resolve_interface(self) -> str:
        if self.interface and self.interface != "auto":
            return self.interface
        return str(conf.iface)

    def run(self, on_window: Callable[[TrafficWindow], None]) -> None:
        interface = self.resolve_interface()
        logger.info("Starting Scapy capture on interface %s (filter=%s)", interface, self.bpf_filter)
        self.running = True
        failures = 0
        while self.running:
            try:
                sniff(iface=interface, timeout=self.window_seconds, prn=self.extractor.add_packet,
                      store=False, filter=self.bpf_filter)
                failures = 0
            except PermissionError:
                logger.exception("Packet capture requires appropriate privileges")
                raise
            except Exception:
                failures += 1
                logger.exception("Packet capture window failed (%d consecutive)", failures)
                # Back off so a persistent failure (bad interface, missing tcpdump) cannot spin the CPU.
                self._wake.wait(min(10.0, 2.0 ** failures))
                if not self.running:
                    break
            try:
                on_window(self.extractor.finish())
            except Exception:  # a storage/mitigation error must not kill the capture thread
                logger.exception("Window processing failed; capture continues")

    def stop(self) -> None:
        self.running = False
        self._wake.set()
