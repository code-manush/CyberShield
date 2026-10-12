import ipaddress
import json
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.logging import logger
from app.database.models import BlockedAddress, AuditLog
from app.prevention.firewall_adapter import (
    BaseFirewallAdapter,
    SimulationFirewallAdapter,
    LinuxIptablesAdapter
)


class PreventionPolicyEngine:
    """Evaluates incoming security threats against configured defense policies."""

    def __init__(self, mode: Optional[str] = None):
        self.mode = mode or settings.PREVENTION_MODE  # OBSERVE, ALERT, ENFORCE
        self.default_block_duration = settings.DEFAULT_BLOCK_DURATION_SECONDS
        self.trusted_ips = set(settings.trusted_ip_list)
        
        # Initialize adapter
        if settings.FIREWALL_ADAPTER == "LINUX_IPTABLES":
            self.adapter: BaseFirewallAdapter = LinuxIptablesAdapter()
            if not self.adapter.is_available():
                logger.warning("Linux iptables adapter unavailable. Falling back to SimulationFirewallAdapter.")
                self.adapter = SimulationFirewallAdapter()
        else:
            self.adapter = SimulationFirewallAdapter()

    def is_allowlisted(self, ip_address: str) -> bool:
        """Check if an IP address is exempt from blocking (loopback, trusted IPs)."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            # Loopback or unspecified
            if ip_obj.is_loopback or ip_obj.is_unspecified:
                return True
        except ValueError:
            return False

        if ip_address in self.trusted_ips:
            return True
        return False

    def evaluate_threat(
        self,
        db: Session,
        threat_event: Dict[str, Any]
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """Evaluate a detected threat and execute defensive policy.
        
        Returns (action_taken, action_details).
        """
        source_ip = threat_event.get("source_ip")
        risk_score = threat_event.get("risk_score", 0.0)
        severity = threat_event.get("severity", "LOW")
        attack_type = threat_event.get("attack_type", "UNKNOWN")

        # In OBSERVE mode, purely log and observe
        if self.mode == "OBSERVE":
            return "OBSERVED", {"mode": "OBSERVE", "reason": "System configured in Observe mode"}

        # In ALERT mode, notify without blocking
        if self.mode == "ALERT":
            return "ALERTED", {"mode": "ALERT", "reason": "Alert dispatched to dashboard"}

        # In ENFORCE mode: evaluate conditions for defensive action
        if not source_ip:
            return "NONE", {"reason": "No source IP specified in threat event"}

        if self.is_allowlisted(source_ip):
            logger.info(f"[PREVENTION] IP {source_ip} is allowlisted/trusted. Blocking skipped.")
            self._log_audit(db, "SYSTEM", "BLOCK_SKIPPED_ALLOWLIST", source_ip, "SUCCESS", {"reason": "IP is on trusted allowlist"})
            return "SKIPPED_ALLOWLIST", {"reason": "IP is trusted or loopback"}

        # Block confirmed threats (score >= 60.0 or MEDIUM/HIGH/CRITICAL severity)
        if risk_score < 60.0 and severity not in ("MEDIUM", "HIGH", "CRITICAL"):
            return "ALERTED", {"reason": f"Risk score ({risk_score}) below enforcement threshold (60.0)"}

        # Check if already actively blocked
        existing = db.query(BlockedAddress).filter(
            BlockedAddress.ip_address == source_ip,
            BlockedAddress.status == "ACTIVE"
        ).first()

        if existing:
            # Refresh expiration if needed
            now = datetime.utcnow()
            if existing.expires_at and existing.expires_at > now:
                return "ALREADY_BLOCKED", {"ip": source_ip, "expires_at": existing.expires_at.isoformat()}

        # Enforce block
        duration = self.default_block_duration
        reason = f"Automatic block for {attack_type} (Risk: {risk_score}, Severity: {severity})"
        action_mode = "ENFORCE_IPTABLES" if isinstance(self.adapter, LinuxIptablesAdapter) and self.adapter.is_available() else "SIMULATION"

        success, msg, meta = self.adapter.block_ip(source_ip, reason, duration)
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=duration)

        if success:
            if existing:
                existing.status = "ACTIVE"
                existing.expires_at = expires_at
                existing.reason = reason
                existing.action_mode = action_mode
            else:
                block_record = BlockedAddress(
                    ip_address=source_ip,
                    reason=reason,
                    created_at=now,
                    expires_at=expires_at,
                    status="ACTIVE",
                    action_mode=action_mode
                )
                db.add(block_record)

            self._log_audit(db, "SYSTEM", "BLOCK_IP", source_ip, "SUCCESS", {
                "duration": duration,
                "reason": reason,
                "mode": action_mode,
                "meta": meta
            })
            db.commit()
            action_taken = "BLOCKED" if action_mode == "ENFORCE_IPTABLES" else "SIMULATED_BLOCK"
            return action_taken, {
                "ip": source_ip,
                "duration": duration,
                "expires_at": expires_at.isoformat(),
                "mode": action_mode,
                "message": msg
            }
        else:
            self._log_audit(db, "SYSTEM", "BLOCK_FAILED", source_ip, "FAILURE", {"error": msg, "meta": meta})
            db.commit()
            return "BLOCK_FAILED", {"error": msg}

    def manual_block(
        self,
        db: Session,
        ip_address: str,
        reason: str,
        duration_seconds: int = 300,
        actor: str = "ADMIN"
    ) -> Tuple[bool, str]:
        """Manually block an IP address via administrator action."""
        if self.is_allowlisted(ip_address):
            return False, f"Cannot block {ip_address}: IP is on trusted allowlist or loopback"

        action_mode = "ENFORCE_IPTABLES" if isinstance(self.adapter, LinuxIptablesAdapter) and self.adapter.is_available() else "SIMULATION"
        success, msg, meta = self.adapter.block_ip(ip_address, reason, duration_seconds)
        
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=duration_seconds) if duration_seconds > 0 else None

        existing = db.query(BlockedAddress).filter(BlockedAddress.ip_address == ip_address).first()
        if existing:
            existing.status = "ACTIVE"
            existing.reason = reason
            existing.expires_at = expires_at
            existing.action_mode = action_mode
        else:
            rec = BlockedAddress(
                ip_address=ip_address,
                reason=reason,
                created_at=now,
                expires_at=expires_at,
                status="ACTIVE",
                action_mode=action_mode
            )
            db.add(rec)

        self._log_audit(db, actor, "MANUAL_BLOCK", ip_address, "SUCCESS" if success else "FAILURE", {
            "duration": duration_seconds,
            "reason": reason,
            "mode": action_mode,
            "message": msg
        })
        db.commit()
        return success, msg

    def manual_unblock(
        self,
        db: Session,
        ip_address: str,
        actor: str = "ADMIN",
        reason: str = "Manual unblock"
    ) -> Tuple[bool, str]:
        """Manually remove an IP block."""
        success, msg, meta = self.adapter.unblock_ip(ip_address)
        rec = db.query(BlockedAddress).filter(
            BlockedAddress.ip_address == ip_address,
            BlockedAddress.status == "ACTIVE"
        ).first()

        if rec:
            rec.status = "UNBLOCKED"
        self._log_audit(db, actor, "MANUAL_UNBLOCK", ip_address, "SUCCESS" if success else "FAILURE", {
            "reason": reason,
            "message": msg
        })
        db.commit()
        return success, msg

    def expire_blocks(self, db: Session) -> int:
        """Scan and expire blocks whose TTL has elapsed."""
        now = datetime.utcnow()
        expired_records = db.query(BlockedAddress).filter(
            BlockedAddress.status == "ACTIVE",
            BlockedAddress.expires_at <= now
        ).all()

        count = 0
        for rec in expired_records:
            self.adapter.unblock_ip(rec.ip_address)
            rec.status = "EXPIRED"
            self._log_audit(db, "SYSTEM", "EXPIRE_BLOCK", rec.ip_address, "SUCCESS", {
                "expired_at": now.isoformat()
            })
            count += 1

        if count > 0:
            db.commit()
            logger.info(f"[PREVENTION] Expired {count} temporary IP block(s).")
        return count

    def _log_audit(self, db: Session, actor: str, action: str, target: str, result: str, details: Dict[str, Any]):
        log = AuditLog(
            actor=actor,
            action=action,
            target=target,
            result=result,
            details_json=json.dumps(details)
        )
        db.add(log)


prevention_engine = PreventionPolicyEngine()
