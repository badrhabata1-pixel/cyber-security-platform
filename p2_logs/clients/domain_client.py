"""Best-effort IP reputation client. Reputation is intentionally not persisted in the Event contract."""
import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

MOCKS = Path(__file__).parents[1] / "mocks" / "reputation.json"


def reputation(ip: str | None) -> dict | None:
    if not ip:
        return None
    if os.getenv("USE_MOCKS", "false").lower() == "true":
        try:
            return json.loads(MOCKS.read_text(encoding="utf-8")).get(ip)
        except (OSError, json.JSONDecodeError):
            return None
    try:
        with urlopen(f"http://localhost:8001/reputation/ip/{ip}", timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))
    except (URLError, OSError, ValueError, json.JSONDecodeError):
        return None
