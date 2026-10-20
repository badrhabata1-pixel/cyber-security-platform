from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr

Role = Literal["admin", "analyst", "viewer"]


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    email: str
    role: Role


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: Role


class HistoryCreate(BaseModel):
    module: str
    action: str
    ref_id: str | None = None
    summary: str


class HistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: str
    user: str
    module: str
    action: str
    ref_id: str | None
    summary: str
