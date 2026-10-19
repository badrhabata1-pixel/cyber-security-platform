import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("logs.sqlite3")


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialise() -> None:
    with connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, source TEXT NOT NULL,
          ip TEXT, username TEXT, event_type TEXT NOT NULL, status TEXT NOT NULL,
          country TEXT, city TEXT, user_agent TEXT, http_path TEXT, http_status INTEGER, raw TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip);
        CREATE TABLE IF NOT EXISTS unparsed (
          id INTEGER PRIMARY KEY AUTOINCREMENT, received_at TEXT NOT NULL, source TEXT NOT NULL, raw TEXT NOT NULL, reason TEXT NOT NULL
        );
        """)


FIELDS = ("timestamp", "source", "ip", "username", "event_type", "status", "country", "city", "user_agent", "http_path", "http_status", "raw")


def insert_event(event: dict) -> int:
    with connection() as conn:
        cursor = conn.execute(f"INSERT INTO events ({','.join(FIELDS)}) VALUES ({','.join('?' for _ in FIELDS)})", [event.get(k) for k in FIELDS])
        return cursor.lastrowid


def insert_unparsed(received_at: str, source: str, raw: str, reason: str) -> None:
    with connection() as conn:
        conn.execute("INSERT INTO unparsed(received_at,source,raw,reason) VALUES(?,?,?,?)", (received_at, source, raw, reason))
