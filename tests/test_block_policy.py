from detector.traffic_models import DetectionResult
from mitigation.block_policy import BlockPolicy


def config():
    return {"capture": {"protected_ip": "192.0.2.1"}, "mitigation": {"trusted_ips": ["192.0.2.2"], "default_quarantine_seconds": 300, "escalation_quarantine_seconds": 900, "repeated_detection_limit": 2}}


def test_temporary_block():
    result = DetectionResult(True, "UDP flood", "high", "192.0.2.50", "test")
    block = BlockPolicy(config()).decide(result)
    assert block["mode"] == "temporary"
    assert block["expires_at"] is not None


def test_repeated_detection_escalates():
    result = DetectionResult(True, "UDP flood", "high", "192.0.2.50", "test")
    block = BlockPolicy(config()).decide(result, previous_count=1)
    assert block["mode"] == "permanent"
    assert block["expires_at"] is None


def test_trusted_ip_is_not_blocked():
    result = DetectionResult(True, "UDP flood", "high", "192.0.2.2", "test")
    assert BlockPolicy(config()).decide(result) is None
