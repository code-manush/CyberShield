import pytest
from app.detection.port_scan import PortScanDetector


def test_normal_traffic_no_port_scan_alert():
    detector = PortScanDetector(threshold_ports=10, window_seconds=10.0)
    # Probing only 3 legitimate service ports
    ports = [80, 443, 8080]
    alerts = []
    for p in ports:
        alert = detector.process_packet(ts=100.0, src_ip="192.168.1.50", dst_ip="192.168.1.10", dst_port=p, is_syn_attempt=True)
        if alert:
            alerts.append(alert)

    assert len(alerts) == 0


def test_port_scan_detection_exceeding_threshold():
    detector = PortScanDetector(threshold_ports=10, window_seconds=10.0, cooldown_seconds=30.0)
    alerts = []
    # Probe 12 distinct ports
    for i in range(1, 13):
        alert = detector.process_packet(
            ts=100.0 + (i * 0.1),
            src_ip="10.0.0.66",
            dst_ip="192.168.1.10",
            dst_port=1000 + i,
            is_syn_attempt=True
        )
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["attack_type"] == "PORT_SCAN"
    assert alert["source_ip"] == "10.0.0.66"
    assert alert["destination_ip"] == "192.168.1.10"
    assert alert["distinct_ports"] >= 10
    assert alert["severity"] in ["MEDIUM", "HIGH", "CRITICAL"]
    assert alert["risk_score"] >= 50.0


def test_randomized_scan_detection():
    detector = PortScanDetector(threshold_ports=5, window_seconds=10.0)
    random_ports = [1433, 21, 5432, 9999, 12345, 65432]
    alerts = []
    for idx, p in enumerate(random_ports):
        alert = detector.process_packet(
            ts=200.0 + idx,
            src_ip="10.0.0.88",
            dst_ip="192.168.1.20",
            dst_port=p,
            is_syn_attempt=True
        )
        if alert:
            alerts.append(alert)

    assert len(alerts) == 1
    assert alerts[0]["evidence"]["scan_type"] in ["Random", "Common Services Scan"]


def test_port_scan_sliding_window_expiration():
    detector = PortScanDetector(threshold_ports=5, window_seconds=5.0)
    # 3 ports at t=100
    for p in [21, 22, 23]:
        assert detector.process_packet(100.0, "1.1.1.1", "2.2.2.2", p) is None

    # 3 ports at t=108 (earlier 3 have expired because window is 5.0s)
    alerts = []
    for p in [80, 443, 8080]:
        a = detector.process_packet(108.0, "1.1.1.1", "2.2.2.2", p)
        if a:
            alerts.append(a)

    # Total active ports is 3 (< 5), so no alert
    assert len(alerts) == 0


def test_port_scan_cooldown_prevents_duplicate_spam():
    detector = PortScanDetector(threshold_ports=5, window_seconds=10.0, cooldown_seconds=30.0)
    alerts = []
    for i in range(10):
        a = detector.process_packet(100.0 + i, "1.1.1.1", "2.2.2.2", 1000 + i)
        if a:
            alerts.append(a)

    assert len(alerts) == 1  # Only 1 alert fired despite exceeding threshold multiple times


def test_port_scan_prune_cleans_memory():
    detector = PortScanDetector(threshold_ports=5, window_seconds=5.0, cooldown_seconds=10.0)
    detector.process_packet(100.0, "1.1.1.1", "2.2.2.2", 80)
    assert len(detector.windows) == 1

    # Prune at t=110.0 (past window_seconds)
    detector.prune(110.0)
    assert len(detector.windows) == 0
