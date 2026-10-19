from __future__ import annotations

import logging
import threading
from collections import defaultdict, deque
from typing import Any

from detector.packet_capture import PacketCapture
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import DetectionResult, TrafficWindow, utc_now_iso
from mitigation.block_policy import BlockPolicy
from mitigation.nftables_manager import NftablesManager
from mitigation.unblock_scheduler import UnblockScheduler
from storage.database import Database

logger = logging.getLogger(__name__)


class DetectorService:
    def __init__(self, config: dict[str, Any], database: Database):
        self.config = config
        self.database = database
        capture_cfg = config.get("capture", {})
        threshold_cfg = config.get("thresholds", {})
        mitigation_cfg = config.get("mitigation", {})
        http_age = float(threshold_cfg.get("http_connection_age_seconds", 30))
        self.capture = PacketCapture(capture_cfg.get("interface", "auto"), 1.0, http_age)
        self.detector = ThresholdDetector(threshold_cfg)
        self.nftables = NftablesManager(bool(mitigation_cfg.get("dry_run", True)))
        self.policy = BlockPolicy(config)
        self.scheduler = UnblockScheduler(database, self.nftables)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._latest_window: dict[str, Any] = {}
        self._latest_result: dict[str, Any] = {"detected": False}
        self._source_detections: dict[str, deque[float]] = defaultdict(deque)
        self.started_at: str | None = None

    def start(self, capture: bool = True) -> None:
        self.started_at = utc_now_iso()
        self._stop.clear()
        self.scheduler.start()
        if self.nftables.dry_run:
            logger.warning("Mitigation is in DRY-RUN mode; nftables will not be changed")
        else:
            self.nftables.ensure_ruleset()
        if capture:
            self._thread = threading.Thread(target=self.capture.run, args=(self.process_window,), name="packet-capture", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.capture.stop()
        self.scheduler.stop()
        if self._thread:
            self._thread.join(timeout=3)
        self.database.close()

    def process_window(self, window: TrafficWindow) -> DetectionResult:
        result = self.detector.evaluate(window)
        with self._lock:
            self._latest_window = window.to_dict()
            self._latest_result = result.to_dict()
        self.database.add_metric(window.to_dict())
        if result.detected:
            self._handle_detection(window, result)
        return result

    def _handle_detection(self, window: TrafficWindow, result: DetectionResult) -> None:
        timestamp = window.timestamp
        self.database.add_alert(result.to_dict(), timestamp)
        self.database.add_event("detection", result.to_dict(), result.source_ip, timestamp)
        if not result.source_ip:
            return
        now = window.timestamp
        history = self._source_detections[result.source_ip]
        history.append(__import__("time").time())
        cutoff = __import__("time").time() - float(self.config.get("mitigation", {}).get("repeated_detection_window_seconds", 600))
        while history and history[0] < cutoff:
            history.popleft()
        block = self.policy.decide(result, max(0, len(history) - 1))
        if not block:
            return
        nft_result = self.nftables.block(block["ip"])
        block["updated_at"] = utc_now_iso()
        self.database.upsert_block(block)
        self.database.add_event("block", {"block": block, "result": nft_result}, block["ip"], timestamp)
        logger.warning("Detected %s from %s; mitigation=%s", result.attack_type, result.source_ip, nft_result)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "started_at": self.started_at,
                "capture_running": bool(self._thread and self._thread.is_alive()),
                "dry_run": self.nftables.dry_run,
                "latest_window": self._latest_window,
                "latest_detection": self._latest_result,
            }

    def manual_unblock(self, ip: str) -> dict[str, Any]:
        result = self.nftables.unblock(ip)
        self.database.update_block_status(ip, "manually_unblocked", utc_now_iso())
        self.database.add_event("manual_unblock", {"result": result}, ip, utc_now_iso())
        return result

    def permanent_block(self, ip: str, reason: str = "Manual administrator block") -> dict[str, Any]:
        result = self.nftables.block(ip)
        now = utc_now_iso()
        block = {"ip": ip, "mode": "permanent", "status": "active", "reason": reason, "attack_type": "manual", "created_at": now, "expires_at": None, "updated_at": now}
        self.database.upsert_block(block)
        self.database.add_event("manual_permanent_block", {"result": result}, ip, now)
        return result

    def unblock_all(self) -> dict[str, Any]:
        result = self.nftables.unblock_all()
        for block in self.database.blocks(active_only=True):
            self.database.update_block_status(block["ip"], "manually_unblocked", utc_now_iso())
        self.database.add_event("manual_unblock_all", {"result": result}, None, utc_now_iso())
        return result
