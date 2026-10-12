from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class MonitoringStatusResponse(BaseModel):
    is_running: bool
    mode: str  # IDLE, LIVE_CAPTURE, PCAP_REPLAY
    interface: Optional[str] = None
    packets_captured: int
    bytes_captured: int
    start_time: Optional[datetime] = None
    uptime_seconds: float = 0.0
    active_threats_detected: int = 0
    available_interfaces: List[str] = []
    has_capture_permissions: bool = True
    error_message: Optional[str] = None


class StartMonitoringRequest(BaseModel):
    interface: Optional[str] = None
    pcap_path: Optional[str] = None
    bpf_filter: str = "ip"


class NetworkStatisticsResponse(BaseModel):
    current_pps: float
    current_bps: float
    total_packets: int
    total_bytes: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    top_talkers: List[Dict[str, Any]]
    top_ports: List[Dict[str, Any]]
    history: List[Dict[str, Any]]
