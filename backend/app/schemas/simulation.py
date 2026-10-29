from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class StartAttackRequest(BaseModel):
    attack_type: str = Field(..., description="Type of attack: PORT_SCAN, SYN_FLOOD, BRUTE_FORCE, MULTI_VECTOR")
    source_ip: Optional[str] = Field(None, description="Simulated attacker IP (e.g. 198.51.100.42)")
    target_ip: Optional[str] = Field("192.168.1.1", description="Target destination IP")
    target_port: Optional[int] = Field(80, description="Target destination port (for SYN flood)")
    intensity: str = Field("medium", description="Intensity level: low, medium, high")
    auto_enforce: bool = Field(False, description="Automatically enable ENFORCE prevention mode to demonstrate auto-blocking")


class AttackSimulationStatusResponse(BaseModel):
    is_attacking: bool
    attack_type: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    packets_sent: int = 0
    total_packets: int = 0
    progress_percent: int = 0
    current_step: str = "Idle"
    logs: List[str] = []
    started_at: Optional[str] = None
    last_threat_flagged: Optional[Dict[str, Any]] = None
