from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventCreate(BaseModel):
    attack_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float = Field(..., ge=0.0, le=100.0)
    detection_method: str = "RULE_BASED"
    evidence_json: str = "{}"
    action_taken: str = "NONE"
    status: str = "NEW"


class SecurityEventResponse(BaseModel):
    id: str
    timestamp: datetime
    attack_type: str
    source_ip: str
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    severity: str
    risk_score: float
    detection_method: str
    evidence_json: str
    action_taken: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class EventStatisticsResponse(BaseModel):
    total_events: int
    port_scan_count: int
    syn_flood_count: int
    brute_force_count: int
    severity_distribution: Dict[str, int]
    attack_distribution: Dict[str, int]
    recent_events_timeline: List[Dict[str, Any]]
