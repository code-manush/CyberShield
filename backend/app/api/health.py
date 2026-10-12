import platform
import time
from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.database.session import get_db
from app.core.config import settings
from app.monitoring.sniffer import sniffer_service
from app.prevention.policy_engine import prevention_engine
from app.ml.classifier import ml_classifier

router = APIRouter(tags=["System"])

SERVER_START_TIME = datetime.utcnow()


@router.get("/api/health")
def get_health(db: Session = Depends(get_db)):
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return {
        "status": "HEALTHY" if db_ok else "DEGRADED",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database_connected": db_ok,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/api/system/status")
def get_system_status():
    uptime = (datetime.utcnow() - SERVER_START_TIME).total_seconds()
    return {
        "system": {
            "os": platform.system(),
            "os_release": platform.release(),
            "python_version": platform.python_version(),
            "server_start_time": SERVER_START_TIME.isoformat(),
            "uptime_seconds": round(uptime, 1)
        },
        "monitoring": {
            "is_running": sniffer_service.is_running,
            "mode": sniffer_service.mode,
            "interface": sniffer_service.interface
        },
        "prevention": {
            "mode": prevention_engine.mode,
            "adapter": prevention_engine.adapter.__class__.__name__
        },
        "machine_learning": {
            "is_trained": ml_classifier.is_trained,
            "model_type": ml_classifier.get_metrics().get("model_type", "RandomForestClassifier")
        }
    }


@router.get("/api/system/config")
def get_system_config():
    return {
        "project_name": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "prevention_mode": settings.PREVENTION_MODE,
        "firewall_adapter": settings.FIREWALL_ADAPTER,
        "default_block_duration_seconds": settings.DEFAULT_BLOCK_DURATION_SECONDS,
        "trusted_ips": settings.trusted_ip_list,
        "thresholds": {
            "port_scan_threshold": settings.PORT_SCAN_THRESHOLD,
            "port_scan_window_seconds": settings.PORT_SCAN_WINDOW_SECONDS,
            "syn_flood_threshold": settings.SYN_FLOOD_THRESHOLD,
            "syn_flood_window_seconds": settings.SYN_FLOOD_WINDOW_SECONDS,
            "brute_force_threshold": settings.BRUTE_FORCE_THRESHOLD,
            "brute_force_window_seconds": settings.BRUTE_FORCE_WINDOW_SECONDS
        }
    }
