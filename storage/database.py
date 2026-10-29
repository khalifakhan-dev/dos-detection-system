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
            self._connection.executescript("""
            CREATE TABLE IF NOT EXISTS traffic_metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON traffic_metrics(timestamp);
            CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, attack_type TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT, reason TEXT NOT NULL, observed TEXT NOT NULL, threshold TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'detected');
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE TABLE IF NOT EXISTS blocks (ip TEXT PRIMARY KEY, mode TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL, attack_type TEXT, created_at TEXT NOT NULL, expires_at TEXT, updated_at TEXT NOT NULL, dry_run INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, source_ip TEXT, details TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE TABLE IF NOT EXISTS incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT, attack_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT, latest_details TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_identity ON incidents(source_ip, attack_type, status);
            """)
            columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(blocks)")}
            if "dry_run" not in columns:
                self._connection.execute("ALTER TABLE blocks ADD COLUMN dry_run INTEGER NOT NULL DEFAULT 0")
            # Older correction-pass databases had UNIQUE(source_ip, attack_type),
            # which prevented a later occurrence from becoming a new incident.
            indexes = self._connection.execute("PRAGMA index_list(incidents)").fetchall()
            if any(row["unique"] for row in indexes):
                self._connection.execute("ALTER TABLE incidents RENAME TO incidents_legacy")
                self._connection.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, source_ip TEXT, attack_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, resolved_at TEXT, latest_details TEXT NOT NULL)")
                self._connection.execute("INSERT INTO incidents SELECT id, source_ip, attack_type, status, first_seen, last_seen, resolved_at, latest_details FROM incidents_legacy")
                self._connection.execute("DROP TABLE incidents_legacy")
                self._connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
                self._connection.execute("CREATE INDEX IF NOT EXISTS idx_incidents_identity ON incidents(source_ip, attack_type, status)")

    def add_metric(self, payload: dict[str, Any]) -> None:
        with self._lock, self._connection:
            self._connection.execute("INSERT INTO traffic_metrics(timestamp, payload) VALUES (?, ?)", (payload.get("timestamp", ""), json.dumps(payload)))

    def add_alert(self, result: dict[str, Any], timestamp: str) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute("INSERT INTO alerts(timestamp, attack_type, severity, source_ip, reason, observed, threshold) VALUES (?, ?, ?, ?, ?, ?, ?)", (timestamp, result.get("attack_type") or "unknown", result.get("severity", "high"), result.get("source_ip"), result.get("reason", ""), json.dumps(result.get("observed", {})), json.dumps(result.get("threshold", {}))))
            return int(cursor.lastrowid)

    def upsert_incident(self, result: dict[str, Any], timestamp: str) -> bool:
        """Update the active incident, or create a new occurrence; return True on creation."""
        source_ip, attack_type = result.get("source_ip"), result.get("attack_type") or "unknown"
        with self._lock, self._connection:
            row = self._connection.execute("SELECT id FROM incidents WHERE source_ip IS ? AND attack_type=? AND status='active' ORDER BY id DESC LIMIT 1", (source_ip, attack_type)).fetchone()
            if row:
                self._connection.execute("UPDATE incidents SET last_seen=?, resolved_at=NULL, latest_details=? WHERE id=?", (timestamp, json.dumps(result), row["id"]))
                return False
            self._connection.execute("INSERT INTO incidents(source_ip, attack_type, status, first_seen, last_seen, resolved_at, latest_details) VALUES (?, ?, 'active', ?, ?, NULL, ?)", (source_ip, attack_type, timestamp, timestamp, json.dumps(result)))
            return True

    def active_incident(self, source_ip: str | None, attack_type: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM incidents WHERE source_ip IS ? AND attack_type=? AND status='active' ORDER BY id DESC LIMIT 1",
                (source_ip, attack_type),
            ).fetchone()
            return dict(row) if row else None

    def resolve_incidents(self, timestamp: str, source_ips: set[str] | None = None, inactive_before: str | None = None) -> None:
        """Resolve only explicitly observed sources and/or incidents past inactivity cutoff."""
        with self._lock, self._connection:
            clauses: list[str] = []
            params: list[Any] = []
            if source_ips:
                placeholders = ",".join("?" for _ in source_ips)
                clauses.append(f"source_ip IN ({placeholders})")
                params.extend(source_ips)
            if inactive_before:
                clauses.append("last_seen < ?")
                params.append(inactive_before)
            if not clauses:
                return
            self._connection.execute(f"UPDATE incidents SET status='resolved', resolved_at=? WHERE status='active' AND ({' OR '.join(clauses)})", (timestamp, *params))

    def recent_incident_count(self, source_ip: str | None, attack_type: str, since: str) -> int:
        """Count resolved occurrences for recurrence escalation within a time window."""
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM incidents WHERE source_ip IS ? AND attack_type=? AND status='resolved' AND first_seen >= ?",
                (source_ip, attack_type, since),
            ).fetchone()
            return int(row["count"])
    def incidents(self, active_only: bool = False, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE status='active' ORDER BY last_seen DESC LIMIT ?" if active_only else "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?"
        return self._rows(query, (limit,))

    def upsert_block(self, block: dict[str, Any]) -> None:
        with self._lock, self._connection:
            self._connection.execute("""INSERT INTO blocks(ip, mode, status, reason, attack_type, created_at, expires_at, updated_at, dry_run) VALUES (:ip, :mode, :status, :reason, :attack_type, :created_at, :expires_at, :updated_at, :dry_run)
                ON CONFLICT(ip) DO UPDATE SET mode=excluded.mode, status=excluded.status, reason=excluded.reason, attack_type=excluded.attack_type, expires_at=excluded.expires_at, updated_at=excluded.updated_at, dry_run=excluded.dry_run""", {**block, "dry_run": int(bool(block.get("dry_run", False)))})

    def has_active_block(self, ip: str) -> bool:
        return bool(self._rows("SELECT 1 FROM blocks WHERE ip=? AND status='active' LIMIT 1", (ip,)))

    def prune(self, max_metric_rows: int = 86400, max_event_rows: int = 100000) -> None:
        """Bound the two high-volume tables (one metric row per second, several events per window)."""
        with self._lock, self._connection:
            for table, keep in (("traffic_metrics", max_metric_rows), ("events", max_event_rows)):
                self._connection.execute(f"DELETE FROM {table} WHERE id <= (SELECT COALESCE(MAX(id), 0) FROM {table}) - ?", (int(keep),))

    def update_block_status(self, ip: str, status: str, updated_at: str) -> None:
        with self._lock, self._connection:
            self._connection.execute("UPDATE blocks SET status=?, updated_at=? WHERE ip=?", (status, updated_at, ip))

    def add_event(self, event_type: str, details: dict[str, Any], source_ip: str | None = None, timestamp: str = "") -> None:
        with self._lock, self._connection:
            self._connection.execute("INSERT INTO events(timestamp, event_type, source_ip, details) VALUES (?, ?, ?, ?)", (timestamp, event_type, source_ip, json.dumps(details)))

    def _rows(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._connection.execute(query, params).fetchall()]

    def latest_metrics(self, limit: int = 60) -> list[dict[str, Any]]:
        rows = self._rows("SELECT payload FROM traffic_metrics ORDER BY id DESC LIMIT ?", (limit,))
        return [json.loads(row["payload"]) for row in reversed(rows)]

    def alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def blocks(self, active_only: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM blocks WHERE status='active' ORDER BY updated_at DESC" if active_only else "SELECT * FROM blocks ORDER BY updated_at DESC"
        rows = self._rows(query)
        for row in rows:
            if "dry_run" in row:
                row["dry_run"] = bool(row["dry_run"])
        return rows

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        return self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    def close(self) -> None:
        with self._lock:
            self._connection.close()
