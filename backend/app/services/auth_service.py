import time
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.database.models import AuthenticationEvent
from app.detection.brute_force import BruteForceDetector
from app.services.event_service import event_service
from app.core.config import settings
from app.core.logging import logger

SALT = "cybershield_security_salt_2026"

def hash_credential(password: str) -> str:
    return hashlib.sha256((SALT + password).encode("utf-8")).hexdigest()

def verify_credential(plain: str, hashed: str) -> bool:
    attempt = hash_credential(plain)
    return hmac.compare_digest(attempt, hashed)


class AuthenticationService:
    """Authentication management and normalized event ingestion service."""

    def __init__(self):
        self.detector = BruteForceDetector(
            threshold_failures=settings.BRUTE_FORCE_THRESHOLD,
            window_seconds=settings.BRUTE_FORCE_WINDOW_SECONDS,
            lockout_seconds=settings.BRUTE_FORCE_LOCKOUT_SECONDS
        )
        # Test accounts for safe local verification: username -> hashed password
        self.test_accounts: Dict[str, str] = {
            "admin": hash_credential("AdminSecret2026!"),
            "analyst": hash_credential("CyberShieldAnalyst!"),
            "operator": hash_credential("OperatorSecurePass#")
        }

    def authenticate_user(
        self,
        username: str,
        password_attempt: str,
        source_ip: str,
        event_source: str = "LOGIN_SERVICE"
    ) -> Tuple[bool, str, bool]:
        """Authenticate a user credentials attempt.
        
        Passwords are evaluated in memory and NEVER stored or logged in plain text.
        Returns: (success: bool, message: str, is_locked: bool)
        """
        now_ts = time.time()

        # Check if source IP is under active lockout
        if self.detector.is_ip_locked(source_ip, now_ts):
            logger.warning(f"[AUTH-LOCKOUT] Rejected attempt from locked IP: {source_ip}")
            return False, "Account access temporarily locked due to excessive failed attempts", True

        stored_hash = self.test_accounts.get(username)
        success = False
        if stored_hash:
            success = verify_credential(password_attempt, stored_hash)

        msg = "Authentication successful" if success else "Invalid credentials provided"

        # Record normalized authentication event
        self.record_event(
            source_ip=source_ip,
            account=username,
            success=success,
            event_source=event_source,
            ts=now_ts
        )

        is_locked_now = self.detector.is_ip_locked(source_ip, now_ts)
        return success, msg, is_locked_now

    def record_event(
        self,
        source_ip: str,
        account: Optional[str],
        success: bool,
        event_source: str = "API",
        ts: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Normalized ingestion endpoint for external auth logs (e.g. SSH, API)."""
        now_ts = ts or time.time()
        event_time = datetime.fromtimestamp(now_ts)

        # 1. Persist normalized authentication telemetry
        db = SessionLocal()
        try:
            auth_record = AuthenticationEvent(
                timestamp=event_time,
                source_ip=source_ip,
                account_identifier=account,
                success=success,
                event_source=event_source
            )
            db.add(auth_record)
            db.commit()
        finally:
            db.close()

        # 2. Feed to BruteForceDetector
        alert = self.detector.process_event(
            ts=now_ts,
            src_ip=source_ip,
            account=account,
            success=success,
            event_source=event_source
        )

        if alert:
            # Threat detected! Dispatch through EventService
            event_service.handle_detected_threat(alert)
            return alert

        return None


auth_service = AuthenticationService()
