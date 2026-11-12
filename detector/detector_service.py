from __future__ import annotations

import logging
import threading
import time
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
        self.detector = ThresholdDetector(threshold_cfg)
        self.nftables = NftablesManager(bool(mitigation_cfg.get("dry_run", True)))
        self.scheduler = UnblockScheduler(database, self.nftables, on_expire=self._on_block_expired)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._latest_window: dict[str, Any] = {}
        self._latest_result: dict[str, Any] = {"detected": False}
        self._manual_unblocks: dict[str, float] = {}
        self._mitigation_attempts: dict[int, dict[str, Any]] = {}
        # Mode and notifications are runtime state; DB remains for internal audit only.
        self._mode = "manual"
        self._live_alerts: dict[tuple[str, str], dict[str, Any]] = {}
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
        with self._lock:
            now = time.monotonic()
            timeout = float(self.config.get("mitigation", {}).get("incident_inactivity_timeout_seconds", 30))
            for key in list(self._live_alerts):
                alert = self._live_alerts[key]
                if now - alert["_last_seen"] > timeout:
                    if alert.get("ignored"):
                        # Acknowledged alerts may reappear only after a quiet period.
                        del self._live_alerts[key]
                    else:
                        # An unanswered decision persists after traffic subsides.
                        alert["ongoing"] = False
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
            return  # Never block unattributed aggregate traffic.
        if self.policy.is_trusted(result.source_ip):
            return  # Keep detection evidence in SQLite, but never offer trusted IPs for blocking.
        key = (result.source_ip, result.attack_type or "unknown")
        with self._lock:
            mode = self._mode
            # Existing blocks still produce detection evidence, not new decisions.
            blocked = self.database.has_active_block(result.source_ip)
            if blocked:
                self._clear_alerts_for_ip(result.source_ip)
            elif mode == "manual":
                previous_alert = self._live_alerts.get(key)
                if previous_alert is None:
                    self._live_alerts[key] = {
                        **result_dict, "timestamp": timestamp, "ignored": False,
                        "ongoing": True, "_last_seen": time.monotonic(),
                    }
                else:
                    # Keep the original evidence and decision until acknowledged.
                    previous_alert["_last_seen"] = time.monotonic()
                    previous_alert["ongoing"] = True
        if mode != "automatic" or blocked:
            return  # Manual mode NEVER blocks without administrator approval.
        if not self._mitigation_ready or self.policy.is_trusted(result.source_ip):
            return
        if time.time() - self._manual_unblocks.get(result.source_ip, float("-inf")) < float(self.config.get("mitigation", {}).get("manual_unblock_grace_seconds", 60)):
            return
        if self.database.has_active_block(result.source_ip):
            return
        incident = self.database.active_incident(result.source_ip, result.attack_type or "unknown")
        if not incident:
            return
        identity = int(incident["id"])
        now_wall = time.time()
        previous = self._mitigation_attempts.get(identity)
        retry_seconds = float(self.config.get("mitigation", {}).get("mitigation_retry_cooldown_seconds", 60))
        if previous and not previous.get("success") and now_wall - previous["attempted_at"] < retry_seconds:
            return
        block = self.policy.decide(result)  # Fixed 5-minute quarantine; no escalation.
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

    def mitigation_mode(self) -> str:
        with self._lock:
            return self._mode

    def set_mitigation_mode(self, mode: str) -> dict[str, Any]:
        if mode not in ("manual", "automatic"):
            raise ValueError("Mode must be manual or automatic")
        with self._lock:
            self._mode = mode
            if mode == "automatic":
                self._live_alerts.clear()  # No pending manual decisions in auto mode.
        self.database.add_event("mitigation_mode", {"mode": mode}, None, utc_now_iso())
        return {"mode": mode, "success": True}

    def _clear_alerts_for_ip(self, ip: str) -> None:
        """Caller must hold _lock (RLock permits nested calls)."""
        for key in list(self._live_alerts):
            if key[0] == ip:
                del self._live_alerts[key]

    def live_alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{k: v for k, v in alert.items() if not k.startswith("_")}
                    for alert in self._live_alerts.values() if not alert.get("ignored")]

    def ignore_alert(self, ip: str, attack_type: str) -> dict[str, Any]:
        ip = NftablesManager.validate_ip(ip)
        with self._lock:
            key = (ip, attack_type)
            if key not in self._live_alerts:
                return {"success": True, "ip": ip, "attack_type": attack_type, "expired": True}
            self._live_alerts[key]["ignored"] = True
        self.database.add_event("alert_ignored", {"attack_type": attack_type}, ip, utc_now_iso())
        return {"success": True, "ip": ip, "attack_type": attack_type}

    @staticmethod
    def _duration(block: dict[str, Any]) -> int | None:
        if not block.get("expires_at"):
            return None
        return max(1, int((datetime.fromisoformat(block["expires_at"]) - datetime.now(timezone.utc)).total_seconds()))

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"started_at": self.started_at, "capture_running": bool(self._thread and self._thread.is_alive()), "capture_health": self.capture.health(), "dry_run": self.nftables.dry_run, "mitigation_ready": self._mitigation_ready, "ruleset_result": self._ruleset_result, "latest_window": self._latest_window, "latest_detection": self._latest_result, "mitigation_mode": self._mode}

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
        if not self._mitigation_ready:
            raise ValueError("Mitigation firewall is not ready")
        result = self._record_action("permanent_block", self.nftables.block(ip), ip, now)
        if result.get("success"):
            self._manual_unblocks.pop(ip, None)
            self.database.upsert_block({"ip": ip, "mode": "permanent", "status": "active", "reason": reason, "attack_type": "manual", "created_at": now, "expires_at": None, "updated_at": now, "dry_run": result["simulated"]})
            with self._lock:
                self._clear_alerts_for_ip(ip)
        return result

    def unblock_all(self) -> dict[str, Any]:
        now = utc_now_iso()
        result = self._record_action("unblock-all", self.nftables.unblock_all(), None, now)
        if result.get("success"):
            for block in self.database.blocks(active_only=True):
                self.database.update_block_status(block["ip"], "manually_unblocked", now)
                self._manual_unblocks[block["ip"]] = time.time()
        return result
