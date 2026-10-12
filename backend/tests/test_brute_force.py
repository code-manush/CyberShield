import pytest
from app.detection.brute_force import BruteForceDetector


def test_successful_logins_do_not_trigger_brute_force():
    detector = BruteForceDetector(threshold_failures=5, window_seconds=30.0)
    alerts = []
    # 10 successful logins
    for i in range(10):
        a = detector.process_event(100.0 + i, "192.168.1.50", "admin", success=True)
        if a:
            alerts.append(a)

    assert len(alerts) == 0
    assert len(detector.failure_windows) == 0


def test_repeated_failed_logins_trigger_brute_force():
    detector = BruteForceDetector(threshold_failures=5, window_seconds=30.0, lockout_seconds=60.0)
    alerts = []
    for i in range(7):
        a = detector.process_event(100.0 + i, "192.168.1.60", "admin", success=False)
        if a:
            alerts.append(a)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attack_type"] == "BRUTE_FORCE_SUSPECTED"
    assert alert["source_ip"] == "192.168.1.60"
    assert alert["failed_attempts"] >= 5
    assert alert["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]
    assert alert["risk_score"] >= 50.0

    # Lockout check
    assert detector.is_ip_locked("192.168.1.60", now=107.0) is True


def test_brute_force_sliding_window_expiration():
    detector = BruteForceDetector(threshold_failures=5, window_seconds=10.0)
    # 3 failures at t=100
    for _ in range(3):
        detector.process_event(100.0, "10.0.0.5", "user1", success=False)

    # 3 failures at t=115 (t=100 events have expired)
    alerts = []
    for _ in range(3):
        a = detector.process_event(115.0, "10.0.0.5", "user1", success=False)
        if a:
            alerts.append(a)

    assert len(alerts) == 0


def test_password_spraying_detection():
    detector = BruteForceDetector(threshold_failures=4, window_seconds=30.0)
    accounts = ["admin", "root", "oracle", "postgres"]
    alerts = []
    for idx, acc in enumerate(accounts):
        a = detector.process_event(100.0 + idx, "10.0.0.99", acc, success=False)
        if a:
            alerts.append(a)

    assert len(alerts) == 1
    assert alerts[0]["distinct_accounts"] == 4
    assert alerts[0]["evidence"]["is_spraying"] is True


def test_lockout_expiration():
    detector = BruteForceDetector(threshold_failures=3, window_seconds=20.0, lockout_seconds=30.0)
    for _ in range(3):
        detector.process_event(100.0, "192.168.1.88", "admin", success=False)

    assert detector.is_ip_locked("192.168.1.88", now=110.0) is True
    # At t=135.0 (past 100 + 30 = 130), lockout should expire
    assert detector.is_ip_locked("192.168.1.88", now=135.0) is False
