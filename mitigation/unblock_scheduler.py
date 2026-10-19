from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from detector.traffic_models import utc_now_iso

logger = logging.getLogger(__name__)


class UnblockScheduler:
    def __init__(self, database: Any, nftables: Any, interval_seconds: float = 2.0):
        self.database = database
        self.nftables = nftables
        self.interval_seconds = interval_seconds
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
            now = datetime.now(timezone.utc)
            for block in self.database.blocks(active_only=True):
                expires_at = block.get("expires_at")
                if block.get("mode") == "temporary" and expires_at:
                    try:
                        expiry = datetime.fromisoformat(expires_at)
                    except ValueError:
                        logger.warning("Invalid expiry timestamp for %s", block.get("ip"))
                        continue
                    if expiry <= now:
                        ip = block["ip"]
                        result = self.nftables.unblock(ip)
                        self.database.update_block_status(ip, "expired", utc_now_iso())
                        self.database.add_event("automatic_unblock", {"result": result}, ip, utc_now_iso())
