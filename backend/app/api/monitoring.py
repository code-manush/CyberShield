from fastapi import APIRouter, HTTPException
from app.monitoring.sniffer import sniffer_service
from app.schemas.monitoring import StartMonitoringRequest, MonitoringStatusResponse, NetworkStatisticsResponse

router = APIRouter(prefix="/api/monitoring", tags=["Monitoring"])


@router.get("/status", response_model=MonitoringStatusResponse)
def get_monitoring_status():
    return sniffer_service.get_status()


@router.post("/start")
def start_monitoring(req: StartMonitoringRequest):
    if req.pcap_path:
        success = sniffer_service.start_offline(req.pcap_path)
        if not success:
            raise HTTPException(status_code=400, detail=sniffer_service.error_message or "Failed to start PCAP analysis")
        return {"status": "SUCCESS", "mode": "PCAP_REPLAY", "pcap_path": req.pcap_path}
    else:
        success = sniffer_service.start_live(interface=req.interface, bpf_filter=req.bpf_filter)
        if not success:
            raise HTTPException(status_code=500, detail=sniffer_service.error_message or "Failed to start live capture")
        return {"status": "SUCCESS", "mode": "LIVE_CAPTURE", "interface": req.interface}


@router.post("/stop")
def stop_monitoring():
    sniffer_service.stop()
    return {"status": "SUCCESS", "message": "Monitoring stopped"}


@router.get("/statistics", response_model=NetworkStatisticsResponse)
def get_monitoring_statistics():
    return sniffer_service.get_statistics()
