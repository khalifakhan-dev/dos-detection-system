from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Any

from detector.traffic_models import utc_now_iso

logger = logging.getLogger(__name__)


class UnblockScheduler:
    def __init__(self, database: Any, nftables: Any, interval_seconds: float = 2.0, on_expire: Any = None):
        self.database, self.nftables, self.interval_seconds, self.on_expire = database, nftables, interval_seconds, on_expire
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="unblock-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self._expire_due_blocks()
            except Exception:  # one bad tick must never end the scheduler thread
                logger.exception("Unblock scheduler tick failed; will retry")

    def _expire_due_blocks(self) -> None:
        now = datetime.now(timezone.utc)
        for block in self.database.blocks(active_only=True):
            expires_at = block.get("expires_at")
            if block.get("mode") != "temporary" or not expires_at:
                continue
            try:
                if datetime.fromisoformat(expires_at) > now:
                    continue
                self._expire(block)
            except Exception:
                logger.exception("Failed to expire block for %s", block.get("ip"))

    def _expire(self, block: dict[str, Any]) -> None:
        ip = block["ip"]
        result = self.nftables.unblock(ip)
        result["simulated"] = bool(result.get("dry_run"))
        outcome = "mitigation_simulated" if result["simulated"] else ("mitigation_success" if result.get("success") else "mitigation_failed")
        if result.get("success"):
            self.database.update_block_status(ip, "expired", utc_now_iso())
        self.database.add_event(outcome, {"outcome": outcome, "action": "automatic_unblock", "result": result}, ip, utc_now_iso())
        if result.get("success") and self.on_expire:
            self.on_expire(ip)
