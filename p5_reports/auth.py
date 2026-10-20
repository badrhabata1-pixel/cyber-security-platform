"""Local JWT guard for the P5 service: reports are for admin and analyst only."""
import os
from fastapi import Header, HTTPException
import jwt


def _disabled() -> bool:
    return os.getenv("AUTH_DISABLED", "false").lower() == "true"


def require_reporter(authorization: str | None = Header(default=None)) -> dict:
    """Returns the token claims plus the raw token, so report jobs can call the other services as this user."""
    if _disabled():
        return {"sub": "local-admin", "role": "admin", "token": None}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    token = authorization[7:]
    try:
        payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
    except (KeyError, jwt.PyJWTError) as exc:
        raise HTTPException(401, "Invalid token") from exc
    if payload.get("role") not in {"admin", "analyst"}:
        raise HTTPException(403, "admin or analyst role required")
    return {**payload, "token": token}
