from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str
    duration_seconds: Optional[int] = 300
    action_mode: Optional[str] = None  # None uses current engine mode


class UnblockIPRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = "Manual administrative unblock"


class BlockedIPResponse(BaseModel):
    id: str
    ip_address: str
    reason: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    status: str
    action_mode: str

    model_config = ConfigDict(from_attributes=True)


class PreventionStatusResponse(BaseModel):
    mode: str  # OBSERVE, ALERT, ENFORCE
    adapter: str  # SIMULATION, LINUX_IPTABLES
    active_blocks_count: int
    trusted_ips: List[str]
    default_block_duration_seconds: int
    dry_run_mode: bool
