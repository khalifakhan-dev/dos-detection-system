from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from detector.packet_capture import PacketCapture
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import DetectionResult, TrafficWindow, utc_now_iso
from mitigation.block_policy import BlockPolicy, ProtectedAddressError
from mitigation.nftables_manager import NftablesManager
from mitigation.unblock_scheduler import UnblockScheduler
from storage.database import Database

logger = logging.getLogger(__name__)


class DetectorService:
    def __init__(self, config: dict[str, Any], database: Database):
        self.config = config
        self.database = database
        capture_cfg, threshold_cfg, mitigation_cfg = config.get("capture", {}), config.get("thresholds", {}), config.get("mitigation", {})
        self.policy = BlockPolicy(config)
        self.capture = PacketCapture(capture_cfg.get("interface", "auto"), 1.0,
                                     float(threshold_cfg.get("http_connection_age_seconds", 30)),
                                     tuple(capture_cfg.get("http_ports", [80])), capture_cfg.get("bpf_filter", "ip"))
        # The protected server's own responses look like a high-rate source; exempt it (and
        # other trusted hosts) from the generic packet-rate rule only.
        self.detector = ThresholdDetector(threshold_cfg, generic_exempt=self.policy.trusted_ips)
        self.nftables = NftablesManager(bool(mitigation_cfg.get("dry_run", True)))
        self.scheduler = UnblockScheduler(database, self.nftables, on_expire=self._on_block_expired)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._latest_window: dict[str, Any] = {}
        self._latest_result: dict[str, Any] = {"detected": False}
        self._block_history: dict[str, deque[float]] = defaultdict(deque)   # automatic blocks per IP (for escalation)
        self._mitigation_failures: dict[tuple[str, str], float] = {}       # failed attempts only (retry cooldown)
        self._manual_unblocks: dict[str, float] = {}
        self._mitigation_attempts: dict[int, dict[str, Any]] = {}
        self._last_prune = 0.0
        self._mitigation_ready = self.nftables.dry_run
        self._ruleset_result: dict[str, Any] = {"success": self.nftables.dry_run, "dry_run": self.nftables.dry_run}
        self.started_at: str | None = None

    # ---- lifecycle ----------------------------------------------------------
    def start(self, capture: bool = True) -> None:
        self.started_at = utc_now_iso()
        self._stop.clear()
        self.scheduler.start()
        if self.nftables.dry_run:
            logger.warning("Mitigation is in DRY-RUN mode; nftables will not be changed")
            self._mitigation_ready = True
        else:
            self._ruleset_result = self.nftables.ensure_ruleset()
            self._mitigation_ready = bool(self._ruleset_result.get("success"))
            if self._mitigation_ready:
                self._reconcile_blocks()
            else:
                logger.error("nftables ruleset initialization failed; real mitigation is not ready: %s", self._ruleset_result)
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

    def _reconcile_blocks(self) -> None:
        """Re-apply DB blocks that are missing from the kernel set (reboot/flush/restart)."""
        now = datetime.now(timezone.utc)
        for block in self.database.blocks(active_only=True):
            ip = block["ip"]
            try:
                if block.get("dry_run"):  # created by an earlier simulation: never enforce it for real
                    self.database.update_block_status(ip, "simulation_ended", utc_now_iso())
                    continue
                remaining = None
                if block.get("expires_at"):
                    remaining = int((datetime.fromisoformat(block["expires_at"]) - now).total_seconds())
                    if remaining <= 0:
                        self.database.update_block_status(ip, "expired", utc_now_iso())
                        continue
                result = self.nftables.block(ip, remaining)
                self.database.add_event("mitigation_success" if result.get("success") else "mitigation_failed",
                                        {"action": "reconcile", "result": result}, ip, utc_now_iso())
            except Exception:
                logger.exception("Could not reconcile block for %s", ip)

    # ---- window processing --------------------------------------------------
    def process_window(self, window: TrafficWindow) -> DetectionResult:
        results = self.detector.evaluate_all(window)
        primary = results[0] if results else self.detector.normal_result(window)
        stored = self._slim_window(window)
        with self._lock:
            self._latest_window, self._latest_result = stored, primary.to_dict()
        self.database.add_metric(stored)
        for result in results:
            self._handle_detection(window, result)
        self._resolve_incidents(window, results)
        self._maybe_prune()
        return primary

    def _slim_window(self, window: TrafficWindow) -> dict[str, Any]:
        """Keep only the busiest sources in stored/served windows so rows stay small under floods."""
        data = window.to_dict()
        limit = int(self.config.get("retention", {}).get("max_sources_per_window", 20))
        stats = data.get("source_stats") or {}
        if len(stats) > limit:
            busiest = sorted(stats.items(), key=lambda item: item[1].get("packets", 0), reverse=True)[:limit]
            data["source_stats"] = dict(busiest)
        return data

    def _resolve_incidents(self, window: TrafficWindow, results: list[DetectionResult]) -> None:
        # Runs on EVERY window: sources seen and no longer offending are resolved, and any
        # incident silent for the inactivity timeout is resolved even while another source attacks.
        timeout = float(self.config.get("mitigation", {}).get("incident_inactivity_timeout_seconds", 30))
        cutoff = self._timestamp_minus(window.timestamp, timeout)
        observed = set(window.source_stats) or ({window.top_source_ip} if window.top_source_ip else set())
        observed -= {r.source_ip for r in results if r.source_ip}
        self.database.resolve_incidents(window.timestamp, observed, cutoff)

    def _maybe_prune(self) -> None:
        now = time.time()
        if now - self._last_prune < 300:
            return
        self._last_prune = now
        retention = self.config.get("retention", {})
        try:
            self.database.prune(int(retention.get("max_metric_rows", 86400)), int(retention.get("max_event_rows", 100000)))
        except Exception:
            logger.exception("Retention pruning failed")

    def _handle_detection(self, window: TrafficWindow, result: DetectionResult) -> None:
        timestamp, result_dict = window.timestamp, result.to_dict()
        created = self.database.upsert_incident(result_dict, timestamp)
        if created:
            self.database.add_alert(result_dict, timestamp)
        self.database.add_event("detection", {"outcome": "detection", "result": result_dict}, result.source_ip, timestamp)
        if not result.source_ip:
            return
        if not self._mitigation_ready:
            self.database.add_event("mitigation_not_ready", {"outcome": "not_ready", "ruleset": self._ruleset_result}, result.source_ip, timestamp)
            return
        mitigation_cfg = self.config.get("mitigation", {})
        if time.time() - self._manual_unblocks.get(result.source_ip, float("-inf")) < float(mitigation_cfg.get("manual_unblock_grace_seconds", 60)):
            self.database.add_event("mitigation_skipped", {"outcome": "idempotent_skip", "reason": "administrator recently unblocked this source"}, result.source_ip, timestamp)
            return
        incident = self.database.active_incident(result.source_ip, result.attack_type or "unknown")
        if not incident:
            return
        identity = int(incident["id"])
        now_wall = time.time()
        previous = getattr(self, "_mitigation_attempts", {}).get(identity)
        retry_seconds = float(mitigation_cfg.get("mitigation_retry_cooldown_seconds", 60))
        block_expired = previous and previous.get("expires_at") and datetime.fromisoformat(previous["expires_at"]) <= datetime.now(timezone.utc)
        active_block = self.database.has_active_block(result.source_ip)
        if previous and not block_expired and ((previous.get("success") and active_block) or (not previous.get("success") and now_wall - previous["attempted_at"] < retry_seconds)):
            self.database.add_event("mitigation_skipped", {"outcome": "idempotent_skip", "reason": "active incident already mitigated or retry cooldown not elapsed", "cooldown_seconds": retry_seconds}, result.source_ip, timestamp)
            return
        repeat_window = float(mitigation_cfg.get("repeated_detection_window_seconds", 600))
        recurrence_since = self._timestamp_minus(timestamp, repeat_window)
        previous_count = self.database.recent_incident_count(result.source_ip, result.attack_type or "unknown", recurrence_since) if created else (1 if previous and previous.get("success") and not active_block else 0)
        block = self.policy.decide(result, previous_count)
        if not block:
            return
        self.database.add_event("mitigation_attempt", {"outcome": "mitigation_attempt", "block": block}, block["ip"], timestamp)
        nft_result = self.nftables.block(block["ip"], self._duration(block))
        nft_result["simulated"] = bool(nft_result.get("dry_run"))
        outcome = "mitigation_simulated" if nft_result["simulated"] else ("mitigation_success" if nft_result.get("success") else "mitigation_failed")
        self.database.add_event(outcome, {"outcome": outcome, "block": block, "result": nft_result}, block["ip"], timestamp)
        self._mitigation_attempts[identity] = {"attempted_at": now_wall, "success": bool(nft_result.get("success")), "expires_at": block.get("expires_at"), "ip": block.get("ip")}
        if nft_result.get("success"):
            block["updated_at"], block["dry_run"] = utc_now_iso(), nft_result["simulated"]
            self.database.upsert_block(block)
        logger.warning("Detected %s from %s; mitigation=%s", result.attack_type, result.source_ip, nft_result)
    @staticmethod
    def _duration(block: dict[str, Any]) -> int | None:
        if not block.get("expires_at"):
            return None
        return max(1, int((datetime.fromisoformat(block["expires_at"]) - datetime.now(timezone.utc)).total_seconds()))

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"started_at": self.started_at, "capture_running": bool(self._thread and self._thread.is_alive()), "dry_run": self.nftables.dry_run, "mitigation_ready": self._mitigation_ready, "ruleset_result": self._ruleset_result, "latest_window": self._latest_window, "latest_detection": self._latest_result}

    @staticmethod
    def _timestamp_minus(timestamp: str, seconds: float) -> str:
        value = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (value - timedelta(seconds=seconds)).isoformat()

    # ---- manual (administrator) actions --------------------------------------
    def _record_action(self, action: str, result: dict[str, Any], ip: str | None, now: str) -> dict[str, Any]:
        result = {**result, "simulated": bool(result.get("dry_run"))}
        outcome = "simulated" if result["simulated"] else ("success" if result.get("success") else "failure")
        result["outcome"] = outcome
        self.database.add_event("mitigation_simulated" if outcome == "simulated" else ("mitigation_success" if outcome == "success" else "mitigation_failed"), {"outcome": outcome, "action": action, "result": result}, ip, now)
        return result

    def _on_block_expired(self, ip: str) -> None:
        self._mitigation_attempts = {key: value for key, value in self._mitigation_attempts.items() if value.get("ip") != ip}

    def manual_unblock(self, ip: str) -> dict[str, Any]:
        ip = NftablesManager.validate_ip(ip)  # ValueError for invalid / non-IPv4
        result = self._record_action("unblock", self.nftables.unblock(ip), ip, utc_now_iso())
        if result.get("success"):
            self._manual_unblocks[ip] = time.time()  # do not instantly re-block while the admin investigates
            self.database.update_block_status(ip, "manually_unblocked", utc_now_iso())
        return result

    def permanent_block(self, ip: str, reason: str = "Manual administrator block") -> dict[str, Any]:
        ip = NftablesManager.validate_ip(ip)
        if self.policy.is_trusted(ip):
            raise ProtectedAddressError(f"{ip} is a trusted/protected address and cannot be blocked")
        now = utc_now_iso()
        result = self._record_action("permanent_block", self.nftables.block(ip), ip, now)
        if result.get("success"):
            self._manual_unblocks.pop(ip, None)
            self.database.upsert_block({"ip": ip, "mode": "permanent", "status": "active", "reason": reason, "attack_type": "manual", "created_at": now, "expires_at": None, "updated_at": now, "dry_run": result["simulated"]})
        return result

    def unblock_all(self) -> dict[str, Any]:
        now = utc_now_iso()
        result = self._record_action("unblock-all", self.nftables.unblock_all(), None, now)
        if result.get("success"):
            for block in self.database.blocks(active_only=True):
                self.database.update_block_status(block["ip"], "manually_unblocked", now)
                self._manual_unblocks[block["ip"]] = time.time()
        return result
