from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from ..config import LOCKOUT_MINUTES, MAX_FAILED_ATTEMPTS
from ..database import get_db, utcnow
from ..models import User
from ..schemas import LoginRequest, LoginResponse, RegisterRequest, UserOut
from ..security import (
    create_access_token,
    get_current_claims,
    hash_password,
    require_role,
    verify_password,
)
from ..telemetry import send_login_event

router = APIRouter(prefix="/auth", tags=["auth"])


def _login_failed(ip: str, email: str, code: int, detail: str) -> JSONResponse:
    # Returned (not raised) so the telemetry background task still runs.
    return JSONResponse(
        {"detail": detail},
        status_code=code,
        background=BackgroundTask(send_login_event, ip, email, False),
    )


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    email = body.email.lower()
    user = db.query(User).filter(User.email == email).first()
    now = utcnow().replace(tzinfo=None)  # naive UTC, matches DB column

    if user is None or not user.is_active:
        return _login_failed(ip, email, status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.locked_until and user.locked_until > now:
        return _login_failed(
            ip, email, status.HTTP_423_LOCKED, "Account temporarily locked. Try again later."
        )

    if user.locked_until:  # lock has expired; start a fresh attempt window
        user.locked_until = None
        user.failed_login_attempts = 0

    if not verify_password(body.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
        db.commit()
        return _login_failed(ip, email, status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    payload = LoginResponse(
        access_token=create_access_token(user.email, user.role),
        user=UserOut(email=user.email, role=user.role),
    )
    return JSONResponse(
        payload.model_dump(),
        background=BackgroundTask(send_login_event, ip, email, True),
    )


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    body: RegisterRequest,
    db: Session = Depends(get_db),
    _: dict = Depends(require_role(["admin"])),
):
    email = body.email.lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(
        email=email,
        password_hash=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    return UserOut(email=user.email, role=user.role)


@router.get("/me", response_model=UserOut)
def me(claims: dict = Depends(get_current_claims)):
    return UserOut(email=claims["sub"], role=claims["role"])
