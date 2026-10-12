import pytest
from app.detection.threat_scoring import ThreatScoringEngine


def test_severity_tier_mapping():
    assert ThreatScoringEngine.score_to_severity(95.0) == "CRITICAL"
    assert ThreatScoringEngine.score_to_severity(80.0) == "HIGH"
    assert ThreatScoringEngine.score_to_severity(55.0) == "MEDIUM"
    assert ThreatScoringEngine.score_to_severity(30.0) == "LOW"
    assert ThreatScoringEngine.score_to_severity(10.0) == "INFO"


def test_port_scan_scoring_bounds():
    score, severity, evidence = ThreatScoringEngine.calculate_port_scan_score(
        distinct_ports=20,
        threshold=15,
        span_seconds=5.0,
        is_sequential=True,
        scan_type="Sequential"
    )
    assert 0.0 <= score <= 100.0
    assert severity in ["MEDIUM", "HIGH", "CRITICAL"]
    assert "score_breakdown" in evidence


def test_syn_flood_scoring_bounds():
    score, severity, evidence = ThreatScoringEngine.calculate_syn_flood_score(
        syn_count=200,
        threshold=100,
        span_seconds=2.0,
        unique_sources=15
    )
    assert 0.0 <= score <= 100.0
    assert severity in ["HIGH", "CRITICAL"]
    assert evidence["unique_sources"] == 15


def test_brute_force_scoring_bounds():
    score, severity, evidence = ThreatScoringEngine.calculate_brute_force_score(
        failed_attempts=25,
        threshold=10,
        span_seconds=15.0,
        distinct_accounts=4
    )
    assert 0.0 <= score <= 100.0
    assert severity in ["HIGH", "CRITICAL"]
    assert evidence["is_spraying"] is True
