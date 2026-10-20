import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

import database  # noqa: E402
import generator  # noqa: E402
import main  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def history(monkeypatch):
    """Records POST /history calls instead of sending them to P4."""
    calls = []
    monkeypatch.setattr(generator.platform_client, "record_history", lambda *args: calls.append(args) or True)
    return calls


@pytest.fixture
def client(tmp_path, monkeypatch, history):
    monkeypatch.setenv("AUTH_DISABLED", "true")
    monkeypatch.setenv("USE_MOCKS", "true")
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "reports.sqlite3")
    monkeypatch.setattr(generator, "OUTPUT_DIR", tmp_path / "generated")
    with TestClient(main.app) as test_client:
        yield test_client
