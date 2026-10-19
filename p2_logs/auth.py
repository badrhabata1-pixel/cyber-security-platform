"""Local JWT guard shared only by the P2 service."""
import os
from fastapi import Header, HTTPException
import jwt


def _disabled() -> bool:
    return os.getenv("AUTH_DISABLED", "false").lower() == "true"


def require_reader(authorization: str | None = Header(default=None)) -> dict:
    if _disabled():
        return {"sub": "local-admin", "role": "admin"}
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Bearer token required")
    try:
        payload = jwt.decode(authorization[7:], os.environ["JWT_SECRET"], algorithms=["HS256"])
    except (KeyError, jwt.PyJWTError) as exc:
        raise HTTPException(401, "Invalid token") from exc
    if payload.get("role") not in {"admin", "analyst"}:
        raise HTTPException(403, "admin or analyst role required")
    return payload


def require_admin(authorization: str | None = Header(default=None)) -> dict:
    payload = require_reader(authorization)
    if payload.get("role") != "admin":
        raise HTTPException(403, "admin role required")
    return payload
