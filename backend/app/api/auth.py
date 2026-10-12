from fastapi import APIRouter, Request, HTTPException, Body
from app.services.auth_service import auth_service
from app.schemas.auth import LoginAttemptRequest, LoginAttemptResponse

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginAttemptResponse)
def login_attempt(req: LoginAttemptRequest, request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    success, msg, is_locked = auth_service.authenticate_user(
        username=req.username,
        password_attempt=req.password,
        source_ip=client_ip,
        event_source="LOGIN_SERVICE"
    )
    return {
        "success": success,
        "message": msg,
        "is_locked": is_locked
    }


@router.post("/event")
def ingest_auth_event(
    source_ip: str = Body(...),
    account: str = Body(...),
    success: bool = Body(...),
    event_source: str = Body("API_INGEST")
):
    alert = auth_service.record_event(
        source_ip=source_ip,
        account=account,
        success=success,
        event_source=event_source
    )
    return {
        "status": "RECORDED",
        "threat_flagged": alert is not None,
        "alert": alert
    }
