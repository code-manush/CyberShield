from collections import defaultdict
from typing import Dict, Tuple, Optional, Any
from app.detection.sliding_window import SlidingWindow
from app.detection.threat_scoring import ThreatScoringEngine


class SynFloodDetector:
    """Detects unusually high volumes of TCP SYN packets targeted at host:port endpoints."""

    def __init__(
        self,
        threshold_syns: int = 100,
        window_seconds: float = 5.0,
        cooldown_seconds: float = 30.0
    ):
        self.threshold_syns = threshold_syns
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        # Map (dst_ip, dst_port) -> SlidingWindow of source IPs
        self.windows: Dict[Tuple[str, int], SlidingWindow] = defaultdict(
            lambda: SlidingWindow(self.window_seconds)
        )
        # Map (dst_ip, dst_port) -> last alert timestamp
        self.last_alert_ts: Dict[Tuple[str, int], float] = {}

    def process_packet(
        self,
        ts: float,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        is_syn: bool = True,
        is_ack: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Process a TCP packet.
        
        Only packets with SYN set and ACK clear are counted as connection attempts.
        SYN-ACK packets and pure ACK packets are explicitly ignored.
        """
        # Connection attempts: SYN set, ACK clear
        if not (is_syn and not is_ack):
            return None

        key = (dst_ip, dst_port)
        window = self.windows[key]
        window.add(ts, src_ip)

        if window.count >= self.threshold_syns:
            # Check cooldown
            last_ts = self.last_alert_ts.get(key)
            if last_ts is not None and (ts - last_ts) < self.cooldown_seconds:
                return None  # Cooldown active

            self.last_alert_ts[key] = ts
            unique_sources = window.distinct
            syn_rate = window.count / max(0.1, window.span)

            # Classify attack specificity
            if unique_sources > 20:
                attack_type = "POSSIBLE_DISTRIBUTED_FLOOD"
            elif unique_sources > 5:
                attack_type = "SYN_FLOOD_SUSPECTED"
            else:
                attack_type = "HIGH_SYN_RATE"

            risk_score, severity, evidence = ThreatScoringEngine.calculate_syn_flood_score(
                syn_count=window.count,
                threshold=self.threshold_syns,
                span_seconds=window.span,
                unique_sources=unique_sources
            )
            evidence["target"] = f"{dst_ip}:{dst_port}"
            evidence["top_sources_sample"] = [
                {"src": ip, "count": cnt}
                for ip, cnt in window.get_values().most_common(10)
            ]

            # Primary source for single/few attackers, or representative source
            primary_src = window.get_values().most_common(1)[0][0] if window.distinct > 0 else src_ip

            return {
                "attack_type": attack_type,
                "source_ip": primary_src,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "syn_packets": window.count,
                "window_seconds": self.window_seconds,
                "unique_sources": unique_sources,
                "severity": severity,
                "risk_score": risk_score,
                "detection_method": "RULE_BASED",
                "evidence": evidence,
                "timestamp": ts
            }

        return None

    def prune(self, now: float) -> None:
        idle_keys = [k for k, w in self.windows.items() if w.is_idle(now)]
        for k in idle_keys:
            del self.windows[k]

        expired_alerts = [k for k, t in self.last_alert_ts.items() if (now - t) >= self.cooldown_seconds]
        for k in expired_alerts:
            del self.last_alert_ts[k]

    def reset(self) -> None:
        self.windows.clear()
        self.last_alert_ts.clear()
