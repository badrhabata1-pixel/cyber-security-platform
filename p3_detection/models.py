from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class StatusEnum(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"

# شكل التنبيه الصادر والمطابق لـ contracts/alert.json
class AlertContract(BaseModel):
    id: int
    created_at: str  # ISO 8601 UTC
    rule: str
    severity: SeverityEnum
    ip: str
    count: int
    description: str
    event_ids: List[int]
    status: StatusEnum

class AlertStatusUpdate(BaseModel):
    status: StatusEnum

# شكل الحدث القادم من شخص 2 (أو المحاكي)
class NormalizedEvent(BaseModel):
    id: int
    timestamp: str  # ISO 8601 UTC
    event_type: str  # login_failed, login_success, http_request
    ip: str
    user_id: Optional[str] = None
    country: Optional[str] = None
    http_status: Optional[int] = None
    http_path: Optional[str] = None
