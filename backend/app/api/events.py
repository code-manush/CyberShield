from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.event_service import event_service
from app.schemas.events import SecurityEventResponse, EventStatisticsResponse

router = APIRouter(prefix="/api/events", tags=["Security Events"])


@router.get("", response_model=List[SecurityEventResponse])
def list_events(
    attack_type: Optional[str] = Query(None, description="Filter by attack category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    start_time: Optional[datetime] = Query(None, description="Filter events after start timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before end timestamp"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    events, _ = event_service.get_events(
        db=db,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset
    )
    return events


@router.get("/recent", response_model=List[SecurityEventResponse])
def get_recent_events(limit: int = Query(10, ge=1, le=50), db: Session = Depends(get_db)):
    events, _ = event_service.get_events(db=db, limit=limit, offset=0)
    return events


@router.get("/statistics", response_model=EventStatisticsResponse)
def get_event_statistics(db: Session = Depends(get_db)):
    return event_service.get_statistics(db)


@router.get("/{event_id}", response_model=SecurityEventResponse)
def get_event_detail(event_id: str, db: Session = Depends(get_db)):
    event = event_service.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Security event not found: {event_id}")
    return event
