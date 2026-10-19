"""Person 2 (Log analysis / SIEM, port 8002): log statistics."""
import os

from clients.base import fetch

BASE_URL = os.getenv("LOGS_SERVICE_URL", "http://127.0.0.1:8002")


def summary(date_from: str | None = None, date_to: str | None = None, token: str | None = None) -> dict | None:
    """{total_events, failed_logins, top_ips, top_countries, top_users, by_hour}; top_* items are {value, count}."""
    return fetch(BASE_URL, "/stats/summary", "stats_summary.json", {"from": date_from, "to": date_to}, token)
