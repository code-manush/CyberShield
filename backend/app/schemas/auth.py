from typing import Optional
from pydantic import BaseModel


class LoginAttemptRequest(BaseModel):
    username: str
    password: str  # Discarded immediately; never stored or logged in plain text


class LoginAttemptResponse(BaseModel):
    success: bool
    message: str
    is_locked: bool = False
