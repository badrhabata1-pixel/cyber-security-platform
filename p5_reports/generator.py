"""The background job behind POST /reports: collect -> build -> render -> record."""
import logging
from datetime import datetime, timezone
from pathlib import Path

from clients import platform_client
from database import fail_report, finish_report, get_report
from pdf import render_pdf
from report_data import build_context, collect

OUTPUT_DIR = Path(__file__).with_name("generated")
log = logging.getLogger("p5.reports")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _history_summary(report: dict, ctx: dict) -> str:
    parts = [f"Executive report {report['reference']} for {ctx['period_label']}", f"threat level {ctx['posture']['label']}"]
    if ctx["alerts"]:
        parts.append(f"{ctx['alerts']['by_severity']['critical']} critical alerts")
    if ctx["logs"]:
        parts.append(f"{ctx['logs']['failed']:,} failed logins")
    if ctx["unavailable"]:
        parts.append("partial data: " + ", ".join(sorted(ctx["unavailable"])) + " unavailable")
    return "; ".join(parts)


def generate_report(report_id: int, token: str | None) -> None:
    """Never raises: any failure is stored on the report so the UI can show it."""
    report = get_report(report_id)
    if report is None:
        return
    try:
        OUTPUT_DIR.mkdir(exist_ok=True)
        ctx = build_context(report, collect(report["date_from"], report["date_to"], token))
        path = OUTPUT_DIR / f"{report['reference']}.pdf"
        render_pdf(ctx, path)
        finish_report(report_id, utc_now(), str(path), sorted(ctx["unavailable"]))
    except Exception as exc:  # a failed report must be visible, not a stuck "processing" row
        log.exception("Report %s failed", report_id)
        fail_report(report_id, utc_now(), f"{type(exc).__name__}: {exc}")
        return
    # Audit trail on the platform; done after the report is marked complete so a slow P4 never delays it
    platform_client.record_history(report["requested_by"], "report_generated", report["reference"], _history_summary(report, ctx), token)
