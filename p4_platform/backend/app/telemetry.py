import httpx

from .config import TELEMETRY_TIMEOUT, TELEMETRY_URL
from .database import iso_utc


async def send_login_event(ip: str, username: str, success: bool) -> None:
    """Forward a login event to Person 2's ingest service. Never raises."""
    payload = {
        "events": [
            {
                "timestamp": iso_utc(),
                "source": "platform_login",
                "ip": ip,
                "username": username,
                "event_type": "login_success" if success else "login_failed",
                "status": "success" if success else "fail",
            }
        ]
    }
    try:
        async with httpx.AsyncClient(timeout=TELEMETRY_TIMEOUT) as client:
            await client.post(TELEMETRY_URL, json=payload)
    except Exception:
        pass
