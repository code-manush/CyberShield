import time
from collections import defaultdict
from typing import Dict, Tuple, Optional, Any, List
from app.detection.sliding_window import SlidingWindow
from app.detection.threat_scoring import ThreatScoringEngine


class PortScanDetector:
    """Detects horizontal and vertical port scanning activity using sliding time windows."""

    def __init__(
        self,
        threshold_ports: int = 15,
        window_seconds: float = 10.0,
        cooldown_seconds: float = 30.0
    ):
        self.threshold_ports = threshold_ports
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Map (src_ip, dst_ip) -> SlidingWindow of probed ports
        self.windows: Dict[Tuple[str, str], SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self.window_seconds)
        )
        # Map (src_ip, dst_ip) -> last alert timestamp
        self.last_alert_ts: Dict[Tuple[str, str], float] = {}

    def process_packet(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        is_syn_attempt: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Process a TCP packet connection attempt.
        
        Returns a detection alert dictionary if threshold exceeded and not on cooldown,
        otherwise returns None.
        """
        if not is_syn_attempt:
            return None

        key = (src_ip, dst_ip)
        window = self.windows[key]
        window.add(ts, dst_port)

        if window.distinct >= self.threshold_ports:
            # Check cooldown
            last_ts = self.last_alert_ts.get(key)
            if last_ts is not None and (ts - last_ts) < self.cooldown_seconds:
                return None  # On cooldown

            self.last_alert_ts[key] = ts
            probed_ports = sorted(list(window.get_values().keys()))
            scan_type = self._classify_scan_pattern(probed_ports)
            is_seq = scan_type == "Sequential"

            risk_score, severity, evidence = ThreatScoringEngine.calculate_port_scan_score(
                distinct_ports=window.distinct,
                threshold=self.threshold_ports,
                span_seconds=window.span,
                is_sequential=is_seq,
                scan_type=scan_type
            )
            evidence["probed_ports_sample"] = probed_ports[:25]
            evidence["total_probed_ports"] = len(probed_ports)
            evidence["attempts_count"] = window.count

            return {
                "attack_type": "PORT_SCAN",
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "distinct_ports": window.distinct,
                "window_seconds": self.window_seconds,
                "severity": severity,
                "risk_score": risk_score,
                "detection_method": "RULE_BASED",
                "evidence": evidence,
                "timestamp": ts
            }

        return None

    def _classify_scan_pattern(self, ports: List[int]) -> str:
        """Classify port scan pattern into Sequential, Common Services, or Random."""
        if len(ports) < 3:
            return "Indeterminate"

        # Check sequential: longest consecutive streak
        seq_count = 1
        max_seq = 1
        for i in range(1, len(ports)):
            if ports[i] == ports[i - 1] + 1:
                seq_count += 1
                max_seq = max(max_seq, seq_count)
            else:
                seq_count = 1

        if max_seq >= max(4, len(ports) // 3):
            return "Sequential"

        # Check well-known common service ports
        common_ports = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443}
        common_hits = sum(1 for p in ports if p in common_ports)
        if common_hits / len(ports) >= 0.5:
            return "Common Services Scan"

        return "Random"

    def prune(self, now: float) -> None:
        """Drop idle windows and expired cooldowns to prevent memory leaks."""
        idle_keys = [k for k, w in self.windows.items() if w.is_idle(now)]
        for k in idle_keys:
            del self.windows[k]

        expired_alerts = [k for k, t in self.last_alert_ts.items() if (now - t) >= self.cooldown_seconds]
        for k in expired_alerts:
            del self.last_alert_ts[k]

    def reset(self) -> None:
        self.windows.clear()
        self.last_alert_ts.clear()
