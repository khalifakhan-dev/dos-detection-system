"""Phase 8: persisted blocks must not bypass current trusted-IP configuration."""

from datetime import datetime, timedelta, timezone

from detector.detector_service import DetectorService
from storage.database import Database


def _record(db, ip, *, dry_run=False, expires_at=None):
    now = datetime.now(timezone.utc).isoformat()
    db.upsert_block({"ip": ip, "mode": "temporary" if expires_at else "permanent",
                     "status": "active", "reason": "previous block", "attack_type": "manual",
                     "created_at": now, "expires_at": expires_at,
                     "updated_at": now, "dry_run": dry_run})


def test_reconciliation_never_restores_trusted_or_protected_ips(tmp_path):
    db = Database(tmp_path / "reconcile.sqlite3")
    _record(db, "192.0.2.10")  # trusted management host
    _record(db, "192.0.2.20")  # protected server
    _record(db, "192.0.2.30")  # legitimate prior real block
    service = DetectorService({"capture": {"protected_ip": "192.0.2.20"},
                               "mitigation": {"dry_run": False, "trusted_ips": ["192.0.2.10"]}}, db)
    attempted = []
    service.nftables.block = lambda ip, timeout=None: (attempted.append(ip) or {"success": True})
    service._reconcile_blocks()
    assert attempted == ["192.0.2.30"]
    blocks = {b["ip"]: b for b in db.blocks()}
    assert blocks["192.0.2.10"]["status"] == "protected_skipped"
    assert blocks["192.0.2.20"]["status"] == "protected_skipped"
    assert blocks["192.0.2.30"]["status"] == "active"
    assert len([e for e in db.events() if e["event_type"] == "mitigation_skipped"]) == 2
    db.close()


def test_reconciliation_does_not_enforce_old_simulations(tmp_path):
    db = Database(tmp_path / "simulated.sqlite3")
    _record(db, "192.0.2.30", dry_run=True)
    service = DetectorService({"mitigation": {"dry_run": False}}, db)
    attempted = []
    service.nftables.block = lambda ip, timeout=None: attempted.append(ip)
    service._reconcile_blocks()
    assert attempted == []
    assert db.blocks()[0]["status"] == "simulation_ended"
    db.close()
