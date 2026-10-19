from detector.traffic_models import TrafficWindow
from storage.database import Database


def test_database_round_trip(tmp_path):
    db = Database(tmp_path / "test.sqlite3")
    metric = TrafficWindow(total_packets=12).to_dict()
    db.add_metric(metric)
    assert db.latest_metrics(1)[0]["total_packets"] == 12
    db.add_event("test", {"ok": True}, timestamp=metric["timestamp"])
    assert db.events(1)[0]["event_type"] == "test"
    db.close()
