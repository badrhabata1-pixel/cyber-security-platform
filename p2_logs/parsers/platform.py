"""Parser for JSON-lines emitted by the platform login service."""
import json
from datetime import datetime, timezone


def parse_platform(line: str) -> dict | None:
    try:
        item = json.loads(line)
        at = datetime.fromisoformat(str(item["timestamp"]).replace("Z", "+00:00"))
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return None
    outcome = str(item.get("status", "")).lower()
    event_type = "login_success" if outcome in {"success", "ok"} else "login_failed"
    return {"timestamp": at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": "platform_login", "ip": item.get("ip"), "username": item.get("username"),
            "event_type": event_type, "status": "success" if event_type == "login_success" else "fail",
            "user_agent": item.get("user_agent"), "http_path": None, "http_status": None, "raw": line.rstrip()}
