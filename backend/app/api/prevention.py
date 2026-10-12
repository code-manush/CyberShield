from typing import List
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.database.models import BlockedAddress
from app.prevention.policy_engine import prevention_engine
from app.schemas.prevention import (
    BlockIPRequest,
    UnblockIPRequest,
    BlockedIPResponse,
    PreventionStatusResponse
)

router = APIRouter(prefix="/api/prevention", tags=["Prevention"])


@router.get("/status", response_model=PreventionStatusResponse)
def get_prevention_status(db: Session = Depends(get_db)):
    # Scan and expire old blocks
    prevention_engine.expire_blocks(db)
    active_blocks = db.query(BlockedAddress).filter(BlockedAddress.status == "ACTIVE").count()

    return {
        "mode": prevention_engine.mode,
        "adapter": prevention_engine.adapter.__class__.__name__,
        "active_blocks_count": active_blocks,
        "trusted_ips": list(prevention_engine.trusted_ips),
        "default_block_duration_seconds": prevention_engine.default_block_duration,
        "dry_run_mode": prevention_engine.mode == "OBSERVE"
    }


@router.get("/blocked-ips", response_model=List[BlockedIPResponse])
def get_blocked_ips(db: Session = Depends(get_db)):
    prevention_engine.expire_blocks(db)
    return db.query(BlockedAddress).order_by(desc(BlockedAddress.created_at)).all()


@router.post("/block-ip")
def block_ip(req: BlockIPRequest, db: Session = Depends(get_db)):
    if prevention_engine.is_allowlisted(req.ip_address):
        raise HTTPException(status_code=400, detail=f"Cannot block {req.ip_address}: IP is on trusted allowlist or loopback.")

    success, msg = prevention_engine.manual_block(
        db=db,
        ip_address=req.ip_address,
        reason=req.reason,
        duration_seconds=req.duration_seconds or 300,
        actor="ADMIN"
    )
    if not success:
        raise HTTPException(status_code=500, detail=msg)
    return {"status": "SUCCESS", "message": msg, "ip_address": req.ip_address}


@router.post("/unblock-ip")
def unblock_ip(req: UnblockIPRequest, db: Session = Depends(get_db)):
    success, msg = prevention_engine.manual_unblock(
        db=db,
        ip_address=req.ip_address,
        actor="ADMIN",
        reason=req.reason or "Manual unblock"
    )
    return {"status": "SUCCESS", "message": msg, "ip_address": req.ip_address}


@router.post("/mode")
def set_prevention_mode(mode: str = Body(..., embed=True)):
    upper_mode = mode.upper()
    if upper_mode not in ("OBSERVE", "ALERT", "ENFORCE"):
        raise HTTPException(status_code=400, detail="Invalid mode. Must be OBSERVE, ALERT, or ENFORCE.")
    prevention_engine.mode = upper_mode
    return {"status": "SUCCESS", "mode": upper_mode}
