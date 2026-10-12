import json
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.database.session import SessionLocal
from app.database.models import SecurityEvent, BlockedAddress, AuditLog
from app.prevention.policy_engine import prevention_engine
from app.websocket.connection_manager import ws_manager
from app.core.logging import logger


class EventService:
    """Manages security event processing, database persistence, and pub/sub routing."""

    @staticmethod
    def handle_detected_threat(threat_data: Dict[str, Any]) -> SecurityEvent:
        """Process a newly detected threat through prevention policy, database, and WebSockets."""
        db = SessionLocal()
        try:
            # 1. Evaluate prevention policy
            action_taken, action_details = prevention_engine.evaluate_threat(db, threat_data)

            # 2. Persist SecurityEvent
            ts = threat_data.get("timestamp")
            event_time = datetime.fromtimestamp(ts) if ts else datetime.utcnow()

            evidence = threat_data.get("evidence", {})
            evidence["action_details"] = action_details

            event = SecurityEvent(
                timestamp=event_time,
                attack_type=threat_data["attack_type"],
                source_ip=threat_data["source_ip"],
                destination_ip=threat_data.get("destination_ip"),
                destination_port=threat_data.get("destination_port"),
                severity=threat_data["severity"],
                risk_score=float(threat_data["risk_score"]),
                detection_method=threat_data.get("detection_method", "RULE_BASED"),
                evidence_json=json.dumps(evidence),
                action_taken=action_taken,
                status="NEW"
            )
            db.add(event)
            db.commit()
            db.refresh(event)

            logger.info(
                f"[THREAT-DETECTED] Type={event.attack_type} "
                f"Source={event.source_ip} Target={event.destination_ip}:{event.destination_port} "
                f"Severity={event.severity} Score={event.risk_score} Action={action_taken}"
            )

            # 3. Broadcast to WebSockets
            event_payload = {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "attack_type": event.attack_type,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "destination_port": event.destination_port,
                "severity": event.severity,
                "risk_score": event.risk_score,
                "detection_method": event.detection_method,
                "evidence": evidence,
                "action_taken": event.action_taken,
                "status": event.status
            }
            ws_manager.broadcast_sync("NEW_SECURITY_EVENT", event_payload)

            return event
        finally:
            db.close()

    @staticmethod
    def get_events(
        db: Session,
        attack_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[SecurityEvent], int]:
        """Query security events with filtering and pagination."""
        query = db.query(SecurityEvent)

        if attack_type:
            query = query.filter(SecurityEvent.attack_type == attack_type)
        if severity:
            query = query.filter(SecurityEvent.severity == severity)
        if source_ip:
            query = query.filter(SecurityEvent.source_ip == source_ip)
        if start_time:
            query = query.filter(SecurityEvent.timestamp >= start_time)
        if end_time:
            query = query.filter(SecurityEvent.timestamp <= end_time)

        total = query.count()
        events = query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()
        return events, total

    @staticmethod
    def get_event_by_id(db: Session, event_id: str) -> Optional[SecurityEvent]:
        return db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()

    @staticmethod
    def get_statistics(db: Session) -> Dict[str, Any]:
        """Aggregate security statistics across all recorded events."""
        total_events = db.query(SecurityEvent).count()
        port_scan_count = db.query(SecurityEvent).filter(SecurityEvent.attack_type == "PORT_SCAN").count()
        syn_flood_count = db.query(SecurityEvent).filter(
            SecurityEvent.attack_type.in_(["SYN_FLOOD_SUSPECTED", "HIGH_SYN_RATE", "POSSIBLE_DISTRIBUTED_FLOOD"])
        ).count()
        brute_force_count = db.query(SecurityEvent).filter(SecurityEvent.attack_type == "BRUTE_FORCE_SUSPECTED").count()

        # Severity breakdown
        severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        sev_dist = {s: 0 for s in severities}
        for sev, count in db.query(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity).all():
            if sev in sev_dist:
                sev_dist[sev] = count

        # Attack breakdown
        attack_dist = {}
        for atype, count in db.query(SecurityEvent.attack_type, func.count(SecurityEvent.id)).group_by(SecurityEvent.attack_type).all():
            attack_dist[atype] = count

        # Recent events for mini-chart
        recent = db.query(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(10).all()
        recent_list = [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "attack_type": e.attack_type,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "source_ip": e.source_ip
            }
            for e in recent
        ]

        return {
            "total_events": total_events,
            "port_scan_count": port_scan_count,
            "syn_flood_count": syn_flood_count,
            "brute_force_count": brute_force_count,
            "severity_distribution": sev_dist,
            "attack_distribution": attack_dist,
            "recent_events_timeline": recent_list
        }


event_service = EventService()
