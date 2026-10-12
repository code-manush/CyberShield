import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.database.models import BlockedAddress, AuditLog
from app.prevention.policy_engine import PreventionPolicyEngine


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_observe_mode_does_not_block(test_db):
    engine = PreventionPolicyEngine(mode="OBSERVE")
    threat = {
        "attack_type": "PORT_SCAN",
        "source_ip": "10.0.0.50",
        "risk_score": 85.0,
        "severity": "HIGH"
    }
    action, details = engine.evaluate_threat(test_db, threat)
    assert action == "OBSERVED"
    assert test_db.query(BlockedAddress).count() == 0


def test_alert_mode_does_not_block(test_db):
    engine = PreventionPolicyEngine(mode="ALERT")
    threat = {
        "attack_type": "SYN_FLOOD",
        "source_ip": "10.0.0.60",
        "risk_score": 90.0,
        "severity": "CRITICAL"
    }
    action, details = engine.evaluate_threat(test_db, threat)
    assert action == "ALERTED"
    assert test_db.query(BlockedAddress).count() == 0


def test_enforce_mode_blocks_malicious_ip(test_db):
    engine = PreventionPolicyEngine(mode="ENFORCE")
    threat = {
        "attack_type": "PORT_SCAN",
        "source_ip": "10.0.0.70",
        "risk_score": 88.0,
        "severity": "HIGH"
    }
    action, details = engine.evaluate_threat(test_db, threat)
    assert action in ["BLOCKED", "SIMULATED_BLOCK"]

    record = test_db.query(BlockedAddress).filter(BlockedAddress.ip_address == "10.0.0.70").first()
    assert record is not None
    assert record.status == "ACTIVE"

    # Verify audit log was recorded
    audit = test_db.query(AuditLog).filter(AuditLog.target == "10.0.0.70").first()
    assert audit is not None
    assert audit.action == "BLOCK_IP"


def test_allowlist_protection_in_enforce_mode(test_db):
    engine = PreventionPolicyEngine(mode="ENFORCE")
    # Loopback IP
    threat_loopback = {
        "attack_type": "PORT_SCAN",
        "source_ip": "127.0.0.1",
        "risk_score": 95.0,
        "severity": "CRITICAL"
    }
    action, _ = engine.evaluate_threat(test_db, threat_loopback)
    assert action == "SKIPPED_ALLOWLIST"
    assert test_db.query(BlockedAddress).filter(BlockedAddress.ip_address == "127.0.0.1").count() == 0


def test_expire_blocks(test_db):
    engine = PreventionPolicyEngine(mode="ENFORCE")
    # Manually insert an expired block
    past_time = datetime.utcnow() - timedelta(minutes=5)
    rec = BlockedAddress(
        ip_address="198.51.100.5",
        reason="Test expired block",
        created_at=past_time - timedelta(minutes=10),
        expires_at=past_time,
        status="ACTIVE",
        action_mode="SIMULATION"
    )
    test_db.add(rec)
    test_db.commit()

    expired_count = engine.expire_blocks(test_db)
    assert expired_count == 1

    updated = test_db.query(BlockedAddress).filter(BlockedAddress.ip_address == "198.51.100.5").first()
    assert updated.status == "EXPIRED"
