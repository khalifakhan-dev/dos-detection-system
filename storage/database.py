from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS traffic_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON traffic_metrics(timestamp);
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    reason TEXT NOT NULL,
                    observed TEXT NOT NULL,
                    threshold TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'detected'
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE TABLE IF NOT EXISTS blocks (
                    ip TEXT PRIMARY KEY,
                    mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    attack_type TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                """
            )

    def add_metric(self, payload: dict[str, Any]) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO traffic_metrics(timestamp, payload) VALUES (?, ?)",
                (payload.get("timestamp", ""), json.dumps(payload)),
            )

    def add_alert(self, result: dict[str, Any], timestamp: str) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """INSERT INTO alerts(timestamp, attack_type, severity, source_ip, reason, observed, threshold)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    timestamp,
                    result.get("attack_type") or "unknown",
                    result.get("severity", "high"),
                    result.get("source_ip"),
                    result.get("reason", ""),
                    json.dumps(result.get("observed", {})),
                    json.dumps(result.get("threshold", {})),
                ),
            )
            return int(cursor.lastrowid)

    def upsert_block(self, block: dict[str, Any]) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """INSERT INTO blocks(ip, mode, status, reason, attack_type, created_at, expires_at, updated_at)
                   VALUES (:ip, :mode, :status, :reason, :attack_type, :created_at, :expires_at, :updated_at)
                   ON CONFLICT(ip) DO UPDATE SET mode=excluded.mode, status=excluded.status,
                   reason=excluded.reason, attack_type=excluded.attack_type, expires_at=excluded.expires_at,
                   updated_at=excluded.updated_at""",
                block,
            )

    def update_block_status(self, ip: str, status: str, updated_at: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE blocks SET status=?, updated_at=? WHERE ip=?", (status, updated_at, ip)
            )

    def add_event(self, event_type: str, details: dict[str, Any], source_ip: str | None = None, timestamp: str = "") -> None:
        with self._lock, self._connection:
            self._connection.execute(
                "INSERT INTO events(timestamp, event_type, source_ip, details) VALUES (?, ?, ?, ?)",
                (timestamp, event_type, source_ip, json.dumps(details)),
            )

    def _rows(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._connection.execute(query, params).fetchall()]

    def latest_metrics(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = self._rows("SELECT payload FROM traffic_metrics ORDER BY id DESC LIMIT ?", (limit,))
        return [json.loads(row["payload"]) for row in reversed(rows)]

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def blocks(self, active_only: bool = False) -> list[dict[str, Any]]:
        if active_only:
            return self._rows("SELECT * FROM blocks WHERE status='active' ORDER BY updated_at DESC")
        return self._rows("SELECT * FROM blocks ORDER BY updated_at DESC")

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def close(self) -> None:
        with self._lock:
            self._connection.close()
