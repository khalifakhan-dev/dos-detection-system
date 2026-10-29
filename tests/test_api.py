import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from api.app import app, runtime
from detector.detector_service import DetectorService
from storage.database import Database

TOKEN = "unit-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _client(tmp_path, token=TOKEN):
    db = Database(tmp_path / "api.sqlite3")
    config = {"api": {"token": token}, "thresholds": {}, "capture": {"protected_ip": "192.0.2.1"}, "mitigation": {"dry_run": True}}
    runtime.config, runtime.service = config, DetectorService(config, db)
    return TestClient(app), db


def test_authentication_is_enforced_and_fails_closed(tmp_path):
    client, db = _client(tmp_path)
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/status", headers=AUTH).status_code == 200
    runtime.config["api"]["token"] = ""
    assert client.get("/api/status", headers=AUTH).status_code == 503
    db.close()


def test_manual_block_validation(tmp_path):
    client, db = _client(tmp_path)
    assert client.post("/api/blocks/2001:db8::1/permanent", headers=AUTH, json={}).status_code == 400
    assert client.post("/api/blocks/not-an-ip/unblock", headers=AUTH, json={}).status_code == 400
    assert client.post("/api/blocks/192.0.2.1/permanent", headers=AUTH, json={}).status_code == 403
    ok = client.post("/api/blocks/192.0.2.50/permanent", headers=AUTH, json={"reason": "test"})
    assert ok.status_code == 200 and ok.json()["outcome"] == "simulated"
    assert client.get("/api/blocks", headers=AUTH).json()[0]["ip"] == "192.0.2.50"
    db.close()
