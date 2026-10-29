import subprocess
import time
import types

import pytest

from detector.detector_service import DetectorService
from detector.threshold_detector import ThresholdDetector
from detector.traffic_models import TrafficWindow
from mitigation.block_policy import ProtectedAddressError
from mitigation.nftables_manager import NftablesManager
from mitigation.unblock_scheduler import UnblockScheduler
from storage.database import Database

T = {"syn_packets_per_second": 250, "syn_completion_rate_max": 0.2, "udp_packets_per_second": 500,
     "udp_bytes_per_second": 500000, "icmp_packets_per_second": 250, "source_packets_per_second": 150}


def attack(ts, ip="9.9.9.9", rate=300):
    return TrafficWindow(timestamp=ts, duration_seconds=1, syn_packets=rate, top_source_ip=ip,
                         source_stats={ip: {"packets": rate, "syn_packets": rate, "ack_packets": 0}})


def make_service(tmp_path, mitigation=None, capture=None, name="v4.sqlite3"):
    db = Database(tmp_path / name)
    cfg = {"thresholds": dict(T), "mitigation": {"dry_run": True, **(mitigation or {})}, "capture": capture or {}}
    service = DetectorService(cfg, db)
    calls = []
    original = service.nftables.block
    service.nftables.block = lambda ip, timeout: (calls.append((ip, timeout)) or original(ip, timeout))
    return service, db, calls


# ---- detector ---------------------------------------------------------------
def test_missing_source_threshold_uses_default_instead_of_crashing():
    thresholds = {k: v for k, v in T.items() if k != "source_packets_per_second"}
    result = ThresholdDetector(thresholds).evaluate(TrafficWindow(source_stats={"192.0.2.1": {"packets": 5}}))
    assert result.detected is False


def test_every_offending_source_is_reported_strongest_rule_first():
    window = TrafficWindow(duration_seconds=1, source_stats={
        "1.1.1.1": {"packets": 400, "syn_packets": 400, "ack_packets": 0},
        "2.2.2.2": {"packets": 300, "syn_packets": 300, "ack_packets": 0},
        "3.3.3.3": {"packets": 900, "udp_packets": 900, "udp_bytes": 1000},
        "4.4.4.4": {"packets": 5},
    })
    results = ThresholdDetector(T).evaluate_all(window)
    assert [(r.source_ip, r.attack_type) for r in results] == [
        ("1.1.1.1", "TCP SYN flood"), ("2.2.2.2", "TCP SYN flood"), ("3.3.3.3", "UDP flood")]


def test_trusted_server_responses_do_not_trigger_generic_flood_alert():
    window = TrafficWindow(duration_seconds=1, source_stats={"192.0.2.1": {"packets": 5000}})
    assert ThresholdDetector(T, generic_exempt={"192.0.2.1"}).evaluate_all(window) == []
    assert ThresholdDetector(T).evaluate_all(window)[0].attack_type == "Source packet flood"


# ---- service: re-block, escalation, concurrency, resolution --------------------
def test_attacker_is_reblocked_with_escalated_duration_after_expiry(tmp_path):
    service, db, calls = make_service(tmp_path)
    service.process_window(attack("2026-01-01T00:00:00+00:00"))
    db.update_block_status("9.9.9.9", "expired", "x")          # what the scheduler does at expiry
    service.process_window(attack("2026-01-01T00:10:00+00:00"))
    assert [ip for ip, _ in calls] == ["9.9.9.9", "9.9.9.9"]
    assert 290 <= calls[0][1] <= 300
    assert 890 <= calls[1][1] <= 900                           # escalated quarantine
    assert len(db.alerts()) == 1                               # same incident, no duplicate alert
    db.close()


def test_two_concurrent_attackers_are_both_blocked(tmp_path):
    service, db, calls = make_service(tmp_path)
    window = TrafficWindow(timestamp="2026-01-01T00:00:00+00:00", duration_seconds=1, source_stats={
        "1.1.1.1": {"packets": 400, "syn_packets": 400, "ack_packets": 0},
        "2.2.2.2": {"packets": 300, "syn_packets": 300, "ack_packets": 0}})
    service.process_window(window)
    assert sorted(ip for ip, _ in calls) == ["1.1.1.1", "2.2.2.2"]
    assert len(db.incidents(active_only=True)) == 2
    db.close()


def test_silent_incident_resolves_even_while_another_source_keeps_attacking(tmp_path):
    service, db, _ = make_service(tmp_path, {"incident_inactivity_timeout_seconds": 5})
    service.process_window(attack("2026-01-01T00:00:00+00:00", "7.7.7.7"))
    for i in range(1, 12):
        service.process_window(attack(f"2026-01-01T00:00:{i:02d}+00:00", "8.8.8.8"))
    assert [r["source_ip"] for r in db.incidents(active_only=True)] == ["8.8.8.8"]
    db.close()


def test_recently_unblocked_source_is_not_instantly_reblocked(tmp_path):
    service, db, calls = make_service(tmp_path)
    service.process_window(attack("2026-01-01T00:00:00+00:00"))
    service.manual_unblock("9.9.9.9")
    service.process_window(attack("2026-01-01T00:00:01+00:00"))
    assert len(calls) == 1
    assert db.events(1)[0]["event_type"] == "mitigation_skipped"
    db.close()


def test_manual_actions_validate_input(tmp_path):
    service, db, _ = make_service(tmp_path, {"trusted_ips": ["192.0.2.2"]}, {"protected_ip": "192.0.2.1"})
    for protected in ("192.0.2.1", "192.0.2.2"):
        with pytest.raises(ProtectedAddressError):
            service.permanent_block(protected)
    with pytest.raises(ValueError):
        service.permanent_block("2001:db8::1")
    with pytest.raises(ValueError):
        service.manual_unblock("2001:db8::1")
    assert db.blocks() == []
    db.close()


def test_stored_windows_keep_only_the_busiest_sources(tmp_path):
    service, db, _ = make_service(tmp_path)
    service.config["retention"] = {"max_sources_per_window": 3}
    stats = {f"10.0.0.{i}": {"packets": i} for i in range(1, 11)}
    service.process_window(TrafficWindow(timestamp="2026-01-01T00:00:00+00:00", source_stats=stats))
    assert sorted(db.latest_metrics(1)[0]["source_stats"]) == ["10.0.0.10", "10.0.0.8", "10.0.0.9"]
    db.close()


def test_database_prune_and_active_block_lookup(tmp_path):
    db = Database(tmp_path / "prune.sqlite3")
    for i in range(10):
        db.add_metric({"timestamp": str(i), "total_packets": i})
        db.add_event("e", {}, None, str(i))
    db.prune(max_metric_rows=3, max_event_rows=4)
    assert [m["total_packets"] for m in db.latest_metrics(100)] == [7, 8, 9]
    assert len(db.events(100)) == 4
    assert db.has_active_block("1.2.3.4") is False
    db.close()


def test_startup_reconcile_reapplies_real_blocks_and_retires_simulated_ones(tmp_path, monkeypatch):
    db = Database(tmp_path / "rec.sqlite3")
    future = "2999-01-01T00:00:00+00:00"
    base = {"mode": "temporary", "status": "active", "reason": "r", "attack_type": "a", "created_at": "x", "updated_at": "x"}
    db.upsert_block({**base, "ip": "1.1.1.1", "expires_at": future, "dry_run": False})
    db.upsert_block({**base, "ip": "2.2.2.2", "expires_at": future, "dry_run": True})
    db.upsert_block({**base, "ip": "3.3.3.3", "expires_at": "2000-01-01T00:00:00+00:00", "dry_run": False})
    monkeypatch.setattr(NftablesManager, "ensure_ruleset", lambda self: {"success": True})
    applied = []
    monkeypatch.setattr(NftablesManager, "block", lambda self, ip, timeout=None: applied.append(ip) or {"success": True})
    service = DetectorService({"thresholds": dict(T), "mitigation": {"dry_run": False}}, db)
    service.start(capture=False)
    status = {b["ip"]: b["status"] for b in db.blocks()}
    assert applied == ["1.1.1.1"]
    assert status == {"1.1.1.1": "active", "2.2.2.2": "simulation_ended", "3.3.3.3": "expired"}
    service.stop()


# ---- nftables manager ---------------------------------------------------------
def _fake_run(monkeypatch, handler):
    seen = []
    def run(args, **kwargs):
        seen.append(list(args))
        returncode, stdout, stderr = handler(args)
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(subprocess, "run", run)
    return seen


def test_is_blocked_matches_exact_address_only(monkeypatch):
    _fake_run(monkeypatch, lambda a: (0, "elements = { 192.0.2.55 expires 4m }", ""))
    manager = NftablesManager(dry_run=False)
    assert manager.is_blocked("192.0.2.55") is True
    assert manager.is_blocked("192.0.2.5") is False


def test_unblock_of_already_expired_element_is_success(monkeypatch):
    _fake_run(monkeypatch, lambda a: (1, "", "Error: Could not process rule: No such file or directory"))
    result = NftablesManager(dry_run=False).unblock("192.0.2.9")
    assert result["success"] is True and result["already_absent"] is True
    _fake_run(monkeypatch, lambda a: (1, "", "Error: Operation not permitted"))
    assert NftablesManager(dry_run=False).unblock("192.0.2.9")["success"] is False


def test_real_block_passes_nft_timeout(monkeypatch):
    seen = _fake_run(monkeypatch, lambda a: (0, "", ""))
    NftablesManager(dry_run=False).block("192.0.2.9", 300)
    assert seen[-1] == ["nft", "add", "element", "inet", "dos_guard", "blocked_ipv4", "{", "192.0.2.9", "timeout", "300s", "}"]


def test_ensure_ruleset_adds_drop_rule_only_once(monkeypatch):
    present = {"rule": False}
    def handler(args):
        if args[1] == "list":
            return 0, ("ip saddr @blocked_ipv4 drop" if present["rule"] else "chain input {}"), ""
        if args[1] == "add" and args[2] == "rule":
            present["rule"] = True
        return 0, "", ""
    seen = _fake_run(monkeypatch, handler)
    manager = NftablesManager(dry_run=False)
    assert manager.ensure_ruleset()["success"] is True
    assert manager.ensure_ruleset()["success"] is True
    assert sum(1 for a in seen if a[1:3] == ["add", "rule"]) == 1


# ---- scheduler -----------------------------------------------------------------
def test_scheduler_survives_exceptions_and_still_expires_blocks():
    class FlakyDb:
        def __init__(self): self.calls, self.status = 0, []
        def blocks(self, active_only=True):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("database hiccup")
            return [{"ip": "1.2.3.4", "mode": "temporary", "expires_at": "2000-01-01T00:00:00+00:00"}] if not self.status else []
        def update_block_status(self, ip, status, ts): self.status.append((ip, status))
        def add_event(self, *a, **k): pass
    db = FlakyDb()
    scheduler = UnblockScheduler(db, NftablesManager(dry_run=True), interval_seconds=0.01)
    scheduler.start()
    deadline = time.time() + 3
    while not db.status and time.time() < deadline:
        time.sleep(0.02)
    scheduler.stop()
    assert db.status == [("1.2.3.4", "expired")]
