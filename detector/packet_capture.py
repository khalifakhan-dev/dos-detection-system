from __future__ import annotations

import logging
from typing import Callable

from scapy.all import conf, get_if_addr, sniff

from .feature_extractor import FeatureExtractor
from .traffic_models import TrafficWindow

logger = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, interface: str = "auto", window_seconds: float = 1.0, http_age_seconds: float = 30.0):
        self.interface = interface
        self.extractor = FeatureExtractor(window_seconds, http_age_seconds)
        self.window_seconds = window_seconds
        self.running = False

    def resolve_interface(self) -> str:
        if self.interface and self.interface != "auto":
            return self.interface
        return str(conf.iface)

    def run(self, on_window: Callable[[TrafficWindow], None]) -> None:
        interface = self.resolve_interface()
        logger.info("Starting Scapy capture on interface %s", interface)
        self.running = True
        while self.running:
            try:
                sniff(
                    iface=interface,
                    timeout=self.window_seconds,
                    prn=self.extractor.add_packet,
                    store=False,
                )
                on_window(self.extractor.finish())
            except PermissionError:
                logger.exception("Packet capture requires appropriate privileges")
                raise
            except Exception:
                logger.exception("Packet capture window failed")
                on_window(self.extractor.finish())

    def stop(self) -> None:
        self.running = False
