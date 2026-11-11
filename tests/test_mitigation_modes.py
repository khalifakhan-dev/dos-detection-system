"""Regression tests for administrator-controlled mitigation."""

import pytest

from detector.detector_service import DetectorService
from detector.traffic_models import TrafficWindow
from storage.database import Database


def attack(ip="192.0.2.51"):
    return TrafficWindow(duration_seconds=1, source_stats={ip: {"packets": 30, "syn_packets": 30, "ack_packets": 0}})


def make_service(tmp_path):
    db = Database(tmp_path / "modes.sqlite3")
    service = DetectorService({"thresholds": {"syn_packets_per_second": 10},
                               "mitigation": {"dry_run": True, "default_quarantine_seconds": 300},
                               "capture": {"protected_ip": "192.0.2.1"}}, db)
    return service, db


def test_manual_default_never_auto_blocks(tmp_path):
    service, db = make_service(tmp_path)
    service.process_window(attack())
    assert service.mitigation_mode() == "manual"
    assert service.live_alerts()[0]["attack_type"] == "TCP SYN flood"
    assert db.blocks(active_only=True) == []
    db.close()


def test_ignore_dismisses_alert_without_block(tmp_path):
    service, db = make_service(tmp_path)
    service.process_window(attack())
    assert service.ignore_alert("192.0.2.51", "TCP SYN flood")["success"]
    service.process_window(attack())
    assert service.live_alerts() == []
    assert db.blocks(active_only=True) == []
    db.close()


def test_automatic_blocks_for_fixed_five_minutes(tmp_path):
    service, db = make_service(tmp_path)
    service.set_mitigation_mode("automatic")
    service.process_window(attack())
    blocks = db.blocks(active_only=True)
    assert len(blocks) == 1
    assert blocks[0]["mode"] == "temporary"
    assert blocks[0]["expires_at"] is not None
    service.set_mitigation_mode("manual")
    assert db.blocks(active_only=True)[0]["mode"] == "temporary"
    db.close()


def test_trusted_ip_cannot_be_blocked(tmp_path):
    service, db = make_service(tmp_path)
    service.set_mitigation_mode("automatic")
    service.process_window(attack("192.0.2.1"))
    assert db.blocks(active_only=True) == []
    with pytest.raises(ValueError):
        service.permanent_block("192.0.2.1")
    db.close()


def test_manual_block_is_permanent_even_in_auto_mode(tmp_path):
    service, db = make_service(tmp_path)
    service.permanent_block("192.0.2.51")
    service.set_mitigation_mode("automatic")
    assert db.blocks(active_only=True)[0]["mode"] == "permanent"
    assert db.blocks(active_only=True)[0]["expires_at"] is None
    db.close()
