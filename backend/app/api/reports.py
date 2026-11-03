from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.event_service import event_service
from app.services.report_service import report_service
from app.prevention.policy_engine import prevention_engine

router = APIRouter(prefix="/api/reports", tags=["SOC Reports"])


@router.get("/incidents.csv")
def export_incidents_csv(
    attack_type: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_time: Optional[datetime] = Query(None, description="Filter events after start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before end timestamp"),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db)
):
    """Generate and download a CSV file of recorded security incidents."""
    events, _ = event_service.get_events(
        db=db,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=0
    )

    csv_content = report_service.generate_csv(events)
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"cybershield_incidents_{timestamp_str}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@router.get("/incidents.pdf")
def export_incidents_pdf(
    attack_type: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_time: Optional[datetime] = Query(None, description="Filter events after start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before end timestamp"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Generate and download an Executive PDF Incident & Telemetry Report."""
    events, _ = event_service.get_events(
        db=db,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=0
    )

    stats = event_service.get_statistics(db)
    pdf_bytes = report_service.generate_executive_pdf(
        events=events,
        stats=stats,
        prevention_mode=prevention_engine.mode
    )

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"cybershield_executive_report_{timestamp_str}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )


@router.get("/events/{event_id}.pdf")
def export_single_event_pdf(
    event_id: str,
    db: Session = Depends(get_db)
):
    """Generate a detailed Forensic Incident Dossier (PDF) for a single security alert."""
    event = event_service.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event not found: {event_id}")

    pdf_bytes = report_service.generate_single_incident_pdf(event)
    filename = f"incident_dossier_{event.id[:8]}_{event.attack_type.lower()}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache"
        }
    )
