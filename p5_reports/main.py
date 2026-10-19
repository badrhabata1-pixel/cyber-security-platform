from dotenv import load_dotenv

load_dotenv()  # first, so auth and the clients see the .env values

import os
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Annotated

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from auth import require_reporter
from database import create_report, get_report, initialise, list_reports
from generator import generate_report, utc_now
from report_data import SECTIONS

UI_DIR = Path(__file__).with_name("ui")
DEFAULT_DAYS = 7


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialise()
    yield


app = FastAPI(title="P5 Executive Security Reports", version="1.0.0", lifespan=lifespan)
# The platform shell (P4) runs on another port and calls this API from the browser
app.add_middleware(
    CORSMiddleware, allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX", r"https?://(localhost|127\.0\.0\.1)(:\d+)?"),
    allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"], expose_headers=["Content-Disposition"],
)
User = Annotated[dict, Depends(require_reporter)]


class ReportRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    date_from: str | None = Field(default=None, alias="from", description="ISO 8601 date or UTC datetime; default 7 days before `to`")
    date_to: str | None = Field(default=None, alias="to", description="ISO 8601 date or UTC datetime; default now")
    sections: list[str] | None = Field(default=None, description=f"Any of {', '.join(SECTIONS)}; default all")


def _bound(value: str, end_of_day: bool) -> datetime:
    try:
        if len(value) == 10:  # a bare date covers the whole day
            day = datetime.strptime(value, "%Y-%m-%d").date()
            return datetime.combine(day, time(23, 59, 59) if end_of_day else time(0, 0, 0), tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(422, f"'{value}' is not an ISO 8601 date or datetime") from exc
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _public(report: dict) -> dict:
    view = {key: value for key, value in report.items() if key != "file_path"}
    view["download_url"] = f"/reports/{report['id']}/download" if report["status"] == "completed" else None
    return view


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/reports", status_code=202)
def request_report(payload: ReportRequest, background_tasks: BackgroundTasks, user: User) -> dict:
    end = _bound(payload.date_to, end_of_day=True) if payload.date_to else datetime.now(timezone.utc).replace(microsecond=0)
    start = _bound(payload.date_from, end_of_day=False) if payload.date_from else end - timedelta(days=DEFAULT_DAYS)
    if start > end:
        raise HTTPException(422, "'from' must be before 'to'")
    sections = payload.sections if payload.sections is not None else list(SECTIONS)
    if not sections or set(sections) - set(SECTIONS):
        raise HTTPException(422, f"sections must be a non-empty list of: {', '.join(SECTIONS)}")
    ordered = [name for name in SECTIONS if name in sections]
    report = create_report(utc_now(), _iso(start), _iso(end), ordered, str(user.get("sub") or "unknown"))
    background_tasks.add_task(generate_report, report["id"], user["token"])
    return {"id": report["id"], "reference": report["reference"], "status": "processing"}


@app.get("/reports")
def reports(_user: User, limit: int = Query(default=50, ge=1, le=500)) -> dict:
    return {"reports": [_public(report) for report in list_reports(limit)]}


@app.get("/reports/{report_id}")
def report_status(report_id: int, _user: User) -> dict:
    report = get_report(report_id)
    if report is None:
        raise HTTPException(404, "Report not found")
    return _public(report)


@app.get("/reports/{report_id}/download")
def download(report_id: int, _user: User) -> FileResponse:
    report = get_report(report_id)
    if report is None:
        raise HTTPException(404, "Report not found")
    if report["status"] == "processing":
        raise HTTPException(409, "Report is still being generated")
    if report["status"] == "failed":
        raise HTTPException(409, f"Report generation failed: {report['error']}")
    path = Path(report["file_path"] or "")
    if not path.is_file():
        raise HTTPException(410, "The report file no longer exists; generate it again")
    return FileResponse(path, media_type="application/pdf", filename=f"{report['reference']}.pdf")


# Standalone UI (also embeddable in the P4 shell through ui/index.jsx)
@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(UI_DIR / "index.html")


@app.get("/ui/{asset:path}", include_in_schema=False)
def ui_assets(asset: str) -> FileResponse:
    target = (UI_DIR / asset).resolve()
    if UI_DIR.resolve() not in target.parents or not target.is_file():
        raise HTTPException(404)
    media_type = "text/javascript" if target.suffix in {".js", ".jsx"} else None
    return FileResponse(target, media_type=media_type)
