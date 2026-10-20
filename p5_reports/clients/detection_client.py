"""Person 3 (Intrusion detection, port 8003): alerts and their summary."""
import os

from clients.base import fetch

BASE_URL = os.getenv("DETECTION_SERVICE_URL", "http://127.0.0.1:8003")


def alerts(date_from: str | None = None, date_to: str | None = None, token: str | None = None) -> list[dict] | None:
    data = fetch(BASE_URL, "/alerts", "alerts.json", {"from": date_from, "to": date_to}, token)
    if data is None:
        return None
    # P3 returns a bare list; {"alerts": [...]} is accepted too in case that changes
    return data if isinstance(data, list) else data.get("alerts", [])


def alerts_summary(date_from: str | None = None, date_to: str | None = None, token: str | None = None) -> dict | None:
    return fetch(BASE_URL, "/alerts/summary", "alerts_summary.json", {"from": date_from, "to": date_to}, token)
