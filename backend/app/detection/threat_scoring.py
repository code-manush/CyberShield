from typing import Dict, Any, Tuple


class ThreatScoringEngine:
    """Centralized Threat Scoring & Severity Assessment Engine.
    
    Provides deterministic, mathematically bounded risk scores (0-100)
    and severity tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL).
    """

    SEVERITY_LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    @staticmethod
    def calculate_port_scan_score(
        distinct_ports: int,
        threshold: int,
        span_seconds: float,
        is_sequential: bool = False,
        scan_type: str = "Random"
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate risk score and severity for a Port Scan event.
        
        Formula components:
        1. Base score: 50.0 (baseline for exceeding port scan threshold)
        2. Port volume ratio: up to +25.0 points based on (distinct_ports / threshold)
        3. Rate factor: up to +15.0 points based on probes per second
        4. Pattern multiplier: +10.0 points for rapid sequential or well-known service probing
        Bounded strictly between 0 and 100.
        """
        base_score = 50.0
        
        # Volume boost
        ratio = max(1.0, distinct_ports / max(1, threshold))
        volume_points = min(25.0, (ratio - 1.0) * 15.0)
        
        # Rate factor
        rate = distinct_ports / max(0.1, span_seconds)
        rate_points = min(15.0, rate * 0.5)
        
        # Pattern factor
        pattern_points = 10.0 if (is_sequential or scan_type == "Sequential") else 5.0

        raw_score = base_score + volume_points + rate_points + pattern_points
        final_score = round(min(100.0, max(0.0, raw_score)), 1)
        severity = ThreatScoringEngine.score_to_severity(final_score)

        evidence = {
            "distinct_ports": distinct_ports,
            "threshold": threshold,
            "span_seconds": round(span_seconds, 2),
            "rate_ports_per_sec": round(rate, 2),
            "scan_type": scan_type,
            "score_breakdown": {
                "base": base_score,
                "volume_points": round(volume_points, 1),
                "rate_points": round(rate_points, 1),
                "pattern_points": round(pattern_points, 1)
            }
        }
        return final_score, severity, evidence

    @staticmethod
    def calculate_syn_flood_score(
        syn_count: int,
        threshold: int,
        span_seconds: float,
        unique_sources: int
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate risk score and severity for a TCP SYN Flood event.
        
        Formula components:
        1. Base score: 55.0
        2. Volume intensity: up to +25.0 points
        3. Rate intensity: up to +10.0 points
        4. Source diversity: up to +10.0 points (distributed vs single-source flood)
        """
        base_score = 55.0
        ratio = max(1.0, syn_count / max(1, threshold))
        volume_points = min(25.0, (ratio - 1.0) * 12.0)

        rate = syn_count / max(0.1, span_seconds)
        rate_points = min(10.0, (rate / max(1.0, float(threshold))) * 5.0)

        # Source diversity
        diversity_points = min(10.0, unique_sources * 0.5)

        raw_score = base_score + volume_points + rate_points + diversity_points
        final_score = round(min(100.0, max(0.0, raw_score)), 1)
        severity = ThreatScoringEngine.score_to_severity(final_score)

        evidence = {
            "syn_count": syn_count,
            "threshold": threshold,
            "span_seconds": round(span_seconds, 2),
            "syn_rate_per_sec": round(rate, 2),
            "unique_sources": unique_sources,
            "score_breakdown": {
                "base": base_score,
                "volume_points": round(volume_points, 1),
                "rate_points": round(rate_points, 1),
                "diversity_points": round(diversity_points, 1)
            }
        }
        return final_score, severity, evidence

    @staticmethod
    def calculate_brute_force_score(
        failed_attempts: int,
        threshold: int,
        span_seconds: float,
        distinct_accounts: int = 1
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate risk score and severity for a Brute-Force authentication attack.
        
        Formula components:
        1. Base score: 50.0
        2. Failure volume: up to +25.0 points
        3. Rate factor: up to +15.0 points
        4. Account spraying diversity: +10.0 points if multiple accounts targeted
        """
        base_score = 50.0
        ratio = max(1.0, failed_attempts / max(1, threshold))
        volume_points = min(25.0, (ratio - 1.0) * 15.0)

        rate = failed_attempts / max(0.1, span_seconds)
        rate_points = min(15.0, rate * 2.0)

        spraying_points = min(10.0, (distinct_accounts - 1) * 3.0) if distinct_accounts > 1 else 0.0

        raw_score = base_score + volume_points + rate_points + spraying_points
        final_score = round(min(100.0, max(0.0, raw_score)), 1)
        severity = ThreatScoringEngine.score_to_severity(final_score)

        evidence = {
            "failed_attempts": failed_attempts,
            "threshold": threshold,
            "span_seconds": round(span_seconds, 2),
            "rate_attempts_per_sec": round(rate, 2),
            "distinct_accounts": distinct_accounts,
            "is_spraying": distinct_accounts > 1,
            "score_breakdown": {
                "base": base_score,
                "volume_points": round(volume_points, 1),
                "rate_points": round(rate_points, 1),
                "spraying_points": round(spraying_points, 1)
            }
        }
        return final_score, severity, evidence

    # Base risk scores per attack class (floor when model confidence = 100%)
    _CLASS_BASE_SCORES: Dict[str, float] = {
        "BENIGN":      0.0,
        "PORT_SCAN":  50.0,
        "SYN_FLOOD":  60.0,
        "DOS_DDOS":   65.0,
        "BRUTE_FORCE": 55.0,
    }
    _CLASS_RANGE: Dict[str, float] = {
        "BENIGN":      15.0,
        "PORT_SCAN":   40.0,
        "SYN_FLOOD":   35.0,
        "DOS_DDOS":    35.0,
        "BRUTE_FORCE": 40.0,
    }

    @staticmethod
    def calculate_ml_anomaly_score(
        predicted_class: str,
        probability: float,
        flow_features: Dict[str, Any]
    ) -> Tuple[float, str, Dict[str, Any]]:
        """Calculate threat score from ML classification output.

        Each attack class has a calibrated base score and range so that
        high-confidence BENIGN flows score near 0 and high-confidence
        attack flows score within their severity tier.
        """
        base  = ThreatScoringEngine._CLASS_BASE_SCORES.get(predicted_class, 50.0)
        rng   = ThreatScoringEngine._CLASS_RANGE.get(predicted_class, 40.0)

        if predicted_class == "BENIGN":
            final_score = round(probability * rng, 1)
            severity = "INFO"
        else:
            final_score = round(base + probability * rng, 1)
            final_score = min(100.0, final_score)
            severity = ThreatScoringEngine.score_to_severity(final_score)

        evidence = {
            "predicted_class": predicted_class,
            "model_confidence": round(probability, 4),
            "flow_features": flow_features,
        }
        return final_score, severity, evidence

    @staticmethod
    def score_to_severity(score: float) -> str:
        """Map a numeric risk score (0-100) to standard severity tiers."""
        if score >= 90.0:
            return "CRITICAL"
        elif score >= 70.0:
            return "HIGH"
        elif score >= 45.0:
            return "MEDIUM"
        elif score >= 20.0:
            return "LOW"
        else:
            return "INFO"
