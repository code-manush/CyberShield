import time
import os
import pytest
from app.monitoring.sniffer import sniffer_service
from app.database.session import SessionLocal
from app.database.models import SecurityEvent


def test_offline_pcap_detection_integration():
    pcap_path = "sample_traffic.pcap"
    assert os.path.exists(pcap_path), "sample_traffic.pcap must exist before running test"

    db = SessionLocal()
    initial_event_count = db.query(SecurityEvent).count()
    db.close()

    # Run PCAP analysis
    success = sniffer_service.start_offline(pcap_path)
    assert success is True

    # Allow worker thread to process packets from queue
    time.sleep(2.0)
    sniffer_service.stop()

    db = SessionLocal()
    final_event_count = db.query(SecurityEvent).count()
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(10).all()
    attack_types = [e.attack_type for e in events]
    db.close()

    # Verify that attacks in sample_traffic.pcap were identified
    assert final_event_count >= initial_event_count
    assert any("PORT_SCAN" in at for at in attack_types) or any("SYN" in at for at in attack_types)
