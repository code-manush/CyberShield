import time
from collections import defaultdict
from typing import Dict, Tuple, Optional, Any
from app.detection.sliding_window import SlidingWindow
from app.detection.threat_scoring import ThreatScoringEngine


class BruteForceDetector:
    """Detects brute-force authentication attacks and password spraying."""

    def __init__(
        self,
        threshold_failures: int = 10,
        window_seconds: float = 60.0,
        lockout_seconds: float = 60.0
    ):
        self.threshold_failures = threshold_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds

        # Map src_ip -> SlidingWindow of targeted account names for failed logins
        self.failure_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self.window_seconds)
        )
        # Map src_ip -> lockout expiration timestamp
        self.locked_ips: Dict[str, float] = {}
        # Map src_ip -> last alert timestamp
        self.last_alert_ts: Dict[str, float] = {}

    def process_event(
        self,
        ts: float,
        src_ip: str,
        account: Optional[str],
        success: bool,
        event_source: str = "LOGIN_SERVICE"
    ) -> Optional[Dict[str, Any]]:
        """Process a normalized authentication event.
        
        Zero credentials / passwords stored or referenced.
        """
        # If login was successful:
        if success:
            # Successful authentication does not increment failure count
            return None

        # Record failed attempt
        target_account = account or "UNKNOWN"
        window = self.failure_windows[src_ip]
        window.add(ts, target_account)

        if window.count >= self.threshold_failures:
            # Check if this IP is currently locked out or alerted recently
            last_alert = self.last_alert_ts.get(src_ip)
            if last_alert is not None and (ts - last_alert) < self.lockout_seconds:
                # Refresh lockout window without duplicate alert spam
                self.locked_ips[src_ip] = ts + self.lockout_seconds
                return None

            self.last_alert_ts[src_ip] = ts
            self.locked_ips[src_ip] = ts + self.lockout_seconds
            distinct_accounts = window.distinct

            risk_score, severity, evidence = ThreatScoringEngine.calculate_brute_force_score(
                failed_attempts=window.count,
                threshold=self.threshold_failures,
                span_seconds=window.span,
                distinct_accounts=distinct_accounts
            )

            evidence["targeted_accounts_sample"] = [
                acc for acc, _ in window.get_values().most_common(5)
            ]
            evidence["event_source"] = event_source
            evidence["lockout_expires_in_seconds"] = self.lockout_seconds

            return {
                "attack_type": "BRUTE_FORCE_SUSPECTED",
                "source_ip": src_ip,
                "destination_ip": None,
                "destination_port": None,
                "failed_attempts": window.count,
                "distinct_accounts": distinct_accounts,
                "window_seconds": self.window_seconds,
                "severity": severity,
                "risk_score": risk_score,
                "detection_method": "RULE_BASED",
                "evidence": evidence,
                "timestamp": ts
            }

        return None

    def is_ip_locked(self, src_ip: str, now: Optional[float] = None) -> bool:
        """Check if an IP is under temporary lockout."""
        if now is None:
            now = time.time()
        expiry = self.locked_ips.get(src_ip)
        if expiry is None:
            return False
        if now >= expiry:
            del self.locked_ips[src_ip]
            return False
        return True

    def prune(self, now: float) -> None:
        idle_ips = [ip for ip, w in self.failure_windows.items() if w.is_idle(now)]
        for ip in idle_ips:
            del self.failure_windows[ip]

        expired_locks = [ip for ip, exp in self.locked_ips.items() if now >= exp]
        for ip in expired_locks:
            del self.locked_ips[ip]

        expired_alerts = [ip for ip, t in self.last_alert_ts.items() if (now - t) >= self.lockout_seconds]
        for ip in expired_alerts:
            del self.last_alert_ts[ip]

    def reset(self) -> None:
        self.failure_windows.clear()
        self.locked_ips.clear()
        self.last_alert_ts.clear()
