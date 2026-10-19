"""Person 4 (Platform, port 8000): audit history. Fire-and-forget: a report never fails because of it."""
import json
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

from clients.base import TIMEOUT_SECONDS

BASE_URL = os.getenv("PLATFORM_SERVICE_URL", "http://127.0.0.1:8000")


def record_history(user: str, action: str, ref_id: str, summary: str, token: str | None = None) -> bool:
    body = json.dumps({"user": user, "module": "reports", "action": action, "ref_id": ref_id, "summary": summary}).encode("utf-8")
    request = Request(f"{BASE_URL.rstrip('/')}/history", data=body, method="POST", headers={"Content-Type": "application/json"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS):
            return True
    except (URLError, OSError, ValueError):
        return False
