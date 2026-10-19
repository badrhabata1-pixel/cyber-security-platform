import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from auth import require_admin, require_reader
from database import connection, initialise, insert_event, insert_unparsed
from geoip import GeoEnricher
from parsers import PARSERS

app = FastAPI(title="P2 Log Analysis / SIEM", version="1.0.0")
geo = GeoEnricher()
ALLOWED_SOURCES = {"ssh", "web", "platform_login"}
ALLOWED_TYPES = {"login_failed", "login_success", "invalid_user", "http_request"}


class IngestLines(BaseModel):
    source: str
    lines: list[str] = Field(min_length=1)


class ReadyEvent(BaseModel):
    timestamp: str
    source: str
    ip: str | None = None
    username: str | None = None
    event_type: str
    status: str
    country: str | None = None
    city: str | None = None
    user_agent: str | None = None
    http_path: str | None = None
    http_status: int | None = None
    raw: str = ""


class IngestEvents(BaseModel):
    events: list[ReadyEvent] = Field(min_length=1)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalise(event: dict) -> dict:
    if event["source"] not in ALLOWED_SOURCES or event["event_type"] not in ALLOWED_TYPES:
        raise ValueError("source or event_type is not allowed by the Event contract")
    try:
        parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        event["timestamp"] = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError) as exc:
        raise ValueError("timestamp must be ISO 8601") from exc
    if not event.get("country") and not event.get("city"):
        event["country"], event["city"] = geo.lookup(event.get("ip"))
    return event


def store_lines(source: str, lines: list[str]) -> dict:
    if source not in PARSERS:
        raise HTTPException(422, "source must be ssh, web, or platform_login when ingesting raw lines")
    created = unparsed = 0
    for line in lines:
        try:
            event = PARSERS[source](line)
            if event is None:
                insert_unparsed(utc_now(), source, line, "parser did not recognise line")
                unparsed += 1
                continue
            normalise(event)
            insert_event(event)
            created += 1
        except Exception as exc:  # a bad record must never abort a batch
            insert_unparsed(utc_now(), source, line, str(exc)[:400])
            unparsed += 1
    return {"accepted": len(lines), "created": created, "unparsed": unparsed}


@app.on_event("startup")
def startup() -> None:
    initialise()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/ingest", dependencies=[Depends(require_admin)])
def ingest(payload: IngestLines | IngestEvents) -> dict:
    if isinstance(payload, IngestLines):
        return store_lines(payload.source, payload.lines)
    created = unparsed = 0
    for model in payload.events:
        event = model.model_dump()
        try:
            normalise(event)
            insert_event(event)
            created += 1
        except ValueError as exc:
            insert_unparsed(utc_now(), event.get("source", "unknown"), event.get("raw", ""), str(exc))
            unparsed += 1
    return {"accepted": len(payload.events), "created": created, "unparsed": unparsed}


@app.post("/upload", dependencies=[Depends(require_admin)])
async def upload(file: Annotated[UploadFile, File(...)], source: str = "ssh") -> dict:
    # splitlines avoids retaining a 50k-line file as a second copy after decoding
    text = (await file.read()).decode("utf-8", errors="replace")
    return store_lines(source, text.splitlines())


@app.get("/events", dependencies=[Depends(require_reader)])
def events(
    since_id: int | None = None, from_: str | None = Query(default=None, alias="from"),
    to: str | None = None, ip: str | None = None, limit: int = Query(default=100, ge=1, le=5000),
) -> dict:
    clauses, params = [], []
    if since_id is not None: clauses.append("id > ?"); params.append(since_id)
    if from_: clauses.append("timestamp >= ?"); params.append(from_)
    if to: clauses.append("timestamp <= ?"); params.append(to)
    if ip: clauses.append("ip = ?"); params.append(ip)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    with connection() as conn:
        rows = conn.execute(f"SELECT * FROM events{where} ORDER BY id ASC LIMIT ?", (*params, limit)).fetchall()
    return {"events": [dict(row) for row in rows]}


@app.get("/stats/summary", dependencies=[Depends(require_reader)])
def summary() -> dict:
    with connection() as conn:
        rows = conn.execute("SELECT timestamp, ip, username, country, event_type, status FROM events").fetchall()
    total = len(rows)
    # The reporting contract calls this failed_logins: HTTP failures are not login failures.
    failures = [r for r in rows if r["event_type"] in {"login_failed", "invalid_user"}]
    top = lambda values: [{"value": value, "count": count} for value, count in Counter(v for v in values if v).most_common(10)]
    by_hour = [{"hour": f"{hour:02d}", "count": sum(1 for r in rows if r["timestamp"][11:13] == f"{hour:02d}")} for hour in range(24)]
    return {"total_events": total, "failed_logins": len(failures), "top_ips": top(r["ip"] for r in failures),
            "top_countries": top(r["country"] for r in failures), "top_users": top(r["username"] for r in failures), "by_hour": by_hour}


@app.get("/stats/geo", dependencies=[Depends(require_reader)])
def stats_geo() -> dict:
    with connection() as conn:
        rows = conn.execute("SELECT ip,country,city,COUNT(*) AS count FROM events WHERE ip IS NOT NULL GROUP BY ip,country,city ORDER BY count DESC").fetchall()
    locations = []
    for row in rows:
        point = dict(row)
        country, city, latitude, longitude = geo.details(point["ip"])
        point.update(country=point["country"] or country, city=point["city"] or city, latitude=latitude, longitude=longitude)
        locations.append(point)
    return {"locations": locations}


@app.get("/logs", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(Path(__file__).parent / "ui" / "index.html")


@app.get("/ui/{asset:path}", include_in_schema=False)
def ui_assets(asset: str) -> FileResponse:
    target = (Path(__file__).parent / "ui" / asset).resolve()
    if Path(__file__).parent.resolve() not in target.parents or not target.is_file():
        raise HTTPException(404)
    return FileResponse(target)
