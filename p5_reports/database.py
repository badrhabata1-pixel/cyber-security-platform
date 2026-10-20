import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name("reports.sqlite3")


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialise() -> None:
    conn = connection()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT, created_at TEXT NOT NULL,
          date_from TEXT NOT NULL, date_to TEXT NOT NULL, sections TEXT NOT NULL, requested_by TEXT NOT NULL,
          status TEXT NOT NULL, file_path TEXT, completed_at TEXT, error TEXT, unavailable TEXT
        );
        """)
        # A restart kills in-flight background jobs: never leave them "processing" forever
        conn.execute("UPDATE reports SET status='failed', error='Interrupted by a service restart' WHERE status='processing'")
        conn.commit()
    finally:
        conn.close()


def _row(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    report = dict(row)
    report["sections"] = json.loads(report["sections"])
    report["unavailable"] = json.loads(report["unavailable"] or "[]")
    return report


def create_report(created_at: str, date_from: str, date_to: str, sections: list[str], requested_by: str) -> dict:
    conn = connection()
    try:
        cursor = conn.execute(
            "INSERT INTO reports(created_at,date_from,date_to,sections,requested_by,status) VALUES(?,?,?,?,?,'processing')",
            (created_at, date_from, date_to, json.dumps(sections), requested_by))
        report_id = cursor.lastrowid
        # Human-friendly unique reference for the cover page, e.g. RPT-20261020-0007
        conn.execute("UPDATE reports SET reference=? WHERE id=?", (f"RPT-{created_at[:10].replace('-', '')}-{report_id:04d}", report_id))
        conn.commit()
        return _row(conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone())
    finally:
        conn.close()


def get_report(report_id: int) -> dict | None:
    conn = connection()
    try:
        return _row(conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone())
    finally:
        conn.close()


def list_reports(limit: int) -> list[dict]:
    conn = connection()
    try:
        return [_row(row) for row in conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
    finally:
        conn.close()


def finish_report(report_id: int, completed_at: str, file_path: str, unavailable: list[str]) -> None:
    conn = connection()
    try:
        conn.execute("UPDATE reports SET status='completed', completed_at=?, file_path=?, unavailable=? WHERE id=?",
                     (completed_at, file_path, json.dumps(unavailable), report_id))
        conn.commit()
    finally:
        conn.close()


def fail_report(report_id: int, completed_at: str, error: str) -> None:
    conn = connection()
    try:
        conn.execute("UPDATE reports SET status='failed', completed_at=?, error=? WHERE id=?", (completed_at, error[:400], report_id))
        conn.commit()
    finally:
        conn.close()
