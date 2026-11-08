from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
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
        self._health_lock = threading.Lock()
        self._health = {"state": "STOPPED", "interface": interface,
                        "last_success": None, "last_error": None,
                        "consecutive_errors": 0, "error": None}

    def _update_health(self, **changes: object) -> None:
        with self._health_lock:
            self._health.update(changes)

    def health(self) -> dict:
        with self._health_lock:
            return dict(self._health)

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()


    def resolve_interface(self) -> str:
        if self.interface and self.interface != "auto":
            return self.interface
        return str(conf.iface)

    def run(self, on_window: Callable[[TrafficWindow], None]) -> None:
        interface = self.resolve_interface()
        logger.info("Starting Scapy capture on interface %s (filter=%s)", interface, self.bpf_filter)
        self.running = True
        self._wake.clear()
        self._update_health(state="STARTING", interface=interface)
        failures = 0
        while self.running:
            try:
                sniff(iface=interface, timeout=self.window_seconds, prn=self.extractor.add_packet,
                      store=False, filter=self.bpf_filter)
                failures = 0
                window = self.extractor.finish()
                self._update_health(state="RUNNING" if window.total_packets else "IDLE",
                                    last_success=self._timestamp(), consecutive_errors=0, error=None)
                try:
                    on_window(window)
                except Exception:
                    logger.exception("Window processing failed; capture continues")
            except PermissionError:
                logger.exception("Packet capture requires appropriate privileges")
                self._update_health(state="ERROR", last_error=self._timestamp(),
                                    consecutive_errors=failures + 1, error="Capture permission denied")
                break
            except Exception:
                failures += 1
                logger.exception("Packet capture window failed (%d consecutive)", failures)
                self._update_health(state="ERROR", last_error=self._timestamp(),
                                    consecutive_errors=failures, error="Packet capture failed; inspect server logs")
                self.extractor.finish()  # discard partial failed capture window
                # Back off so a persistent failure (bad interface, missing tcpdump) cannot spin the CPU.
                self._wake.wait(min(10.0, 2.0 ** failures))
                if not self.running:
                    break
        self.running = False
        if self.health()["state"] != "ERROR":
            self._update_health(state="STOPPED")

    def stop(self) -> None:
        self.running = False
        self._wake.set()
        self._update_health(state="STOPPED")
