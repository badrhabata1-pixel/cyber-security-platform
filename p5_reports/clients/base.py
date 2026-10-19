"""Shared GET helper for the three clients: 3-second timeout, optional mocks, and a None fallback."""
import json
import os
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MOCKS = Path(__file__).parents[1] / "mocks"
TIMEOUT_SECONDS = 3


def use_mocks() -> bool:
    return os.getenv("USE_MOCKS", "true").lower() == "true"


def fetch(base_url: str, path: str, mock_file: str, params: dict | None = None, token: str | None = None) -> dict | None:
    """None means "this section is unavailable": the report must still be generated without it."""
    if use_mocks():
        try:
            return json.loads((MOCKS / mock_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
    query = urlencode({k: v for k, v in (params or {}).items() if v is not None})
    request = Request(f"{base_url.rstrip('/')}{path}{'?' + query if query else ''}")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (URLError, OSError, ValueError):
        return None
