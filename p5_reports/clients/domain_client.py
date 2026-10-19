"""Person 1 (Domain checker, port 8001): stored domain scans."""
import os

from clients.base import fetch

BASE_URL = os.getenv("DOMAIN_SERVICE_URL", "http://127.0.0.1:8001")


def scans(date_from: str | None = None, date_to: str | None = None, token: str | None = None) -> list[dict] | None:
    data = fetch(BASE_URL, "/scans", "scans.json", {"from": date_from, "to": date_to}, token)
    if data is None:
        return None
    # GET /scans is not in contracts/ yet: accept a bare list or {"scans": [...]}
    return data if isinstance(data, list) else data.get("scans", [])
