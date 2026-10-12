import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, Index
from app.database.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    attack_type = Column(String(50), nullable=False, index=True)  # PORT_SCAN, SYN_FLOOD_SUSPECTED, BRUTE_FORCE_SUSPECTED, etc.
    source_ip = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)
    severity = Column(String(20), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False)  # 0.0 - 100.0
    detection_method = Column(String(50), nullable=False)  # RULE_BASED, ML_CLASSIFIER, HYBRID
    evidence_json = Column(Text, nullable=False, default="{}")
    action_taken = Column(String(50), nullable=False, default="NONE")  # OBSERVED, ALERTED, BLOCKED, SIMULATED_BLOCK
    status = Column(String(20), nullable=False, default="NEW")  # NEW, RESOLVED, DISMISSED


class NetworkStatistic(Base):
    __tablename__ = "network_statistics"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    packets_per_second = Column(Float, nullable=False, default=0.0)
    bytes_per_second = Column(Float, nullable=False, default=0.0)
    tcp_packets = Column(Integer, nullable=False, default=0)
    udp_packets = Column(Integer, nullable=False, default=0)
    icmp_packets = Column(Integer, nullable=False, default=0)
    active_flows = Column(Integer, nullable=False, default=0)


class AuthenticationEvent(Base):
    __tablename__ = "authentication_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    account_identifier = Column(String(100), nullable=True, index=True)
    success = Column(Boolean, nullable=False)
    event_source = Column(String(50), nullable=False, default="LOGIN_SERVICE")  # LOGIN_SERVICE, SSH_LOG, API


class BlockedAddress(Base):
    __tablename__ = "blocked_addresses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    reason = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True, index=True)
    status = Column(String(20), nullable=False, default="ACTIVE")  # ACTIVE, EXPIRED, UNBLOCKED
    action_mode = Column(String(30), nullable=False, default="SIMULATION")  # SIMULATION, ENFORCE_IPTABLES


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor = Column(String(100), nullable=False, default="SYSTEM")
    action = Column(String(100), nullable=False)  # BLOCK_IP, UNBLOCK_IP, MODE_CHANGE, ML_RETRAIN, etc.
    target = Column(String(100), nullable=True)
    result = Column(String(20), nullable=False)  # SUCCESS, FAILURE, REJECTED
    details_json = Column(Text, nullable=False, default="{}")
