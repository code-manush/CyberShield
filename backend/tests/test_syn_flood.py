import pytest
from app.detection.syn_flood import SynFloodDetector


def test_normal_syn_traffic_no_alert():
    detector = SynFloodDetector(threshold_syns=50, window_seconds=5.0)
    alerts = []
    # 15 legitimate SYNs
    for i in range(15):
        a = detector.process_packet(
            ts=100.0 + (i * 0.2),
            src_ip=f"192.168.1.{100 + i}",
            dst_ip="192.168.1.20",
            dst_port=80,
            is_syn=True,
            is_ack=False
        )
        if a:
            alerts.append(a)

    assert len(alerts) == 0


def test_syn_flood_burst_detection():
    detector = SynFloodDetector(threshold_syns=50, window_seconds=5.0, cooldown_seconds=20.0)
    alerts = []
    # Burst of 60 SYNs in 1 second
    for i in range(60):
        a = detector.process_packet(
            ts=100.0 + (i * 0.01),
            src_ip=f"10.0.0.{(i % 25) + 1}",
            dst_ip="192.168.1.20",
            dst_port=80,
            is_syn=True,
            is_ack=False
        )
        if a:
            alerts.append(a)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["destination_ip"] == "192.168.1.20"
    assert alert["destination_port"] == 80
    assert alert["syn_packets"] >= 50
    assert alert["unique_sources"] >= 20
    assert alert["attack_type"] in ["SYN_FLOOD_SUSPECTED", "POSSIBLE_DISTRIBUTED_FLOOD"]
    assert alert["severity"] in ["HIGH", "CRITICAL"]


def test_syn_ack_ignored():
    detector = SynFloodDetector(threshold_syns=10, window_seconds=5.0)
    alerts = []
    # 20 packets with SYN=1 and ACK=1 (handshake response, not new SYN attempt)
    for i in range(20):
        a = detector.process_packet(
            ts=100.0 + i,
            src_ip="1.1.1.1",
            dst_ip="2.2.2.2",
            dst_port=80,
            is_syn=True,
            is_ack=True
        )
        if a:
            alerts.append(a)

    assert len(alerts) == 0
    assert len(detector.windows) == 0


def test_syn_flood_target_isolation():
    detector = SynFloodDetector(threshold_syns=30, window_seconds=5.0)
    # 20 SYNs to port 80, 20 SYNs to port 443 -> Neither reaches threshold of 30
    for i in range(20):
        detector.process_packet(100.0 + (i * 0.05), "1.1.1.1", "2.2.2.2", 80, is_syn=True, is_ack=False)
        detector.process_packet(100.0 + (i * 0.05), "1.1.1.1", "2.2.2.2", 443, is_syn=True, is_ack=False)

    assert detector.windows[("2.2.2.2", 80)].count == 20
    assert detector.windows[("2.2.2.2", 443)].count == 20


def test_syn_flood_cooldown():
    detector = SynFloodDetector(threshold_syns=10, window_seconds=5.0, cooldown_seconds=30.0)
    alerts = []
    for i in range(25):
        a = detector.process_packet(100.0 + (i * 0.1), "1.1.1.1", "2.2.2.2", 80, is_syn=True, is_ack=False)
        if a:
            alerts.append(a)

    assert len(alerts) == 1
