"""P5 Definition of Done: reports in < 5 s, never fail because a service is down, valid PDFs for empty
periods, RBAC on every endpoint, and untrusted text from other services can't break or steer the renderer."""
import io
import socket
import time

import jwt
import pytest
from pypdf import PdfReader

import database
import generator
import report_data
from clients import base, detection_client, domain_client, logs_client
from recommendations import build_recommendations

DEAD = "http://127.0.0.1:9"  # nothing listens here
PERIOD = {"from": "2026-10-13", "to": "2026-10-20"}


def pdf_text(content: bytes) -> tuple[int, str]:
    reader = PdfReader(io.BytesIO(content))
    return len(reader.pages), "\n".join(page.extract_text() for page in reader.pages)


def generate(client, body=None) -> dict:
    created = client.post("/reports", json=body or PERIOD)
    assert created.status_code == 202, created.text
    assert created.json()["status"] == "processing"
    return client.get(f"/reports/{created.json()['id']}").json()


def kill_services(monkeypatch) -> None:
    monkeypatch.setenv("USE_MOCKS", "false")
    for module in (domain_client, logs_client, detection_client):
        monkeypatch.setattr(module, "BASE_URL", DEAD)


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_mocks_follow_the_contracts_and_agree_with_each_other(monkeypatch):
    monkeypatch.setenv("USE_MOCKS", "true")
    scans, stats = domain_client.scans(), logs_client.summary()
    alerts, alerts_summary = detection_client.alerts(), detection_client.alerts_summary()
    assert {s["risk_level"] for s in scans} == {"critical", "high", "medium", "low"}
    assert stats["failed_logins"] == sum(i["count"] for i in stats["top_ips"])
    assert stats["total_events"] == sum(h["count"] for h in stats["by_hour"]) and len(stats["by_hour"]) == 24
    assert alerts_summary["total_alerts"] == len(alerts) == sum(alerts_summary["by_severity"].values())
    assert all(a["severity"] in report_data.SEVERITIES and a["status"] in report_data.ALERT_STATUSES for a in alerts)


def test_clients_give_up_quietly_when_a_service_is_down(monkeypatch):
    kill_services(monkeypatch)
    started = time.monotonic()
    assert domain_client.scans() is None and logs_client.summary() is None
    assert detection_client.alerts() is None and detection_client.alerts_summary() is None
    assert time.monotonic() - started < 4 * base.TIMEOUT_SECONDS


def test_full_report_from_mocks_is_fast_complete_and_audited(client, history):
    started = time.monotonic()
    report = generate(client)
    assert time.monotonic() - started < 5
    assert report["status"] == "completed" and report["unavailable"] == []
    assert report["reference"].startswith("RPT-") and report["requested_by"] == "local-admin"
    pdf = client.get(report["download_url"])
    assert pdf.headers["content-type"] == "application/pdf"
    assert f'{report["reference"]}.pdf' in pdf.headers["content-disposition"]
    pages, text = pdf_text(pdf.content)
    assert pages >= 6
    for expected in ("Executive summary", "Log intelligence", "Intrusion alerts", "Domain threat intelligence",
                     "Recommended actions", "acme-bank-verify.xyz", "203.0.113.5", "Overall threat level: Critical"):
        assert expected in text, expected
    assert len(history) == 1 and history[0][1:3] == ("report_generated", report["reference"])


def test_report_still_generates_when_every_service_is_down(client, monkeypatch):
    kill_services(monkeypatch)
    report = generate(client)
    assert report["status"] == "completed"
    assert report["unavailable"] == ["alerts", "domains", "logs"]
    _, text = pdf_text(client.get(report["download_url"]).content)
    assert text.count("Data for this section is currently unavailable") == 3


def test_one_service_down_only_blanks_its_own_section(client, monkeypatch):
    monkeypatch.setattr(detection_client, "fetch", lambda *a, **k: None)
    report = generate(client)
    assert report["unavailable"] == ["alerts"]
    _, text = pdf_text(client.get(report["download_url"]).content)
    assert text.count("currently unavailable") == 1 and "acme-bank-verify.xyz" in text and "1,856" in text


def test_alert_summary_alone_still_fills_the_alert_counts(client, monkeypatch):
    monkeypatch.setattr(detection_client, "fetch", lambda base_url, path, *rest: None if path == "/alerts" else
                        {"total_alerts": 3, "by_severity": {"critical": 1, "high": 2}, "by_rule": {"brute_force": 3}, "by_status": {"open": 3}})
    report = generate(client)
    assert report["unavailable"] == []
    _, text = pdf_text(client.get(report["download_url"]).content)
    assert "The alert list could not be retrieved" in text and "Critical alerts" in text


def test_empty_period_still_produces_a_readable_pdf(client, monkeypatch):
    empty = {"stats": {"total_events": 0, "failed_logins": 0, "top_ips": [], "top_countries": [], "top_users": [], "by_hour": []},
             "alerts": [], "alerts_summary": {"total_alerts": 0}, "scans": []}
    monkeypatch.setattr(generator, "collect", lambda *args: empty)
    report = generate(client)
    assert report["status"] == "completed" and report["unavailable"] == []
    _, text = pdf_text(client.get(report["download_url"]).content)
    for expected in ("No log events were recorded", "No alerts were raised", "No domains were scanned", "Maintain current controls"):
        assert expected in text, expected


def test_unexpected_data_shapes_mark_sections_unavailable_instead_of_failing(client, monkeypatch):
    garbage = {"stats": ["not", "an", "object"], "alerts": "nonsense", "alerts_summary": None,
               "scans": [{"domain": "x.com", "risk_score": "very high"}]}
    monkeypatch.setattr(generator, "collect", lambda *args: garbage)
    report = generate(client)
    assert report["status"] == "completed"
    assert report["unavailable"] == ["alerts", "domains", "logs"]


def test_text_from_other_services_is_escaped_and_never_fetched(client, monkeypatch):
    hostile = '<img src="http://169.254.169.254/latest/meta-data/">evil-login.com'
    scans = [{"id": 1, "domain": hostile, "scanned_at": "2026-10-15T10:00:00Z", "risk_score": 80, "risk_level": "critical",
              "reasons": ['<link rel="stylesheet" href="file:///C:/Windows/win.ini">']}]
    monkeypatch.setattr(generator, "collect", lambda *args: {"stats": None, "alerts": None, "alerts_summary": None, "scans": scans})
    attempts, real_connect = [], socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", lambda sock, address: attempts.append(address) or real_connect(sock, address))
    report = generate(client)
    assert report["status"] == "completed"
    _, text = pdf_text(client.get(report["download_url"]).content)
    assert "evil-login.com" in text and "169.254.169.254" in text  # shown as text, not followed
    assert not any(address[0] == "169.254.169.254" for address in attempts if isinstance(address, tuple))


def test_lists_are_limited_to_the_requested_period(monkeypatch):
    monkeypatch.setenv("USE_MOCKS", "true")
    report = {"date_from": "2026-10-17T00:00:00Z", "date_to": "2026-10-17T23:59:59Z", "sections": list(report_data.SECTIONS),
              "created_at": "2026-10-20T00:00:00Z"}
    ctx = report_data.build_context(report, report_data.collect(report["date_from"], report["date_to"], None))
    assert ctx["alerts"]["total"] == 3  # alerts 104, 105 and 106 were raised on 17 Oct
    assert [row["domain"] for row in ctx["domains"]["rows"]] == ["secure-docs-share.online"]


@pytest.mark.parametrize("body, problem", [
    ({"from": "2026-10-20", "to": "2026-10-13"}, "before"),
    ({"from": "13/10/2026", "to": "2026-10-20"}, "ISO 8601"),
    ({**PERIOD, "sections": ["logs", "payroll"]}, "sections"),
    ({**PERIOD, "sections": []}, "sections"),
])
def test_invalid_requests_are_rejected(client, body, problem):
    response = client.post("/reports", json=body)
    assert response.status_code == 422 and problem in response.json()["detail"]


def test_defaults_cover_the_last_seven_days(client):
    report = generate(client, {})
    start, end = report_data.parse_time(report["date_from"]), report_data.parse_time(report["date_to"])
    assert (end - start).days == 7 and report["sections"] == list(report_data.SECTIONS)


def test_rbac_viewer_is_refused_everywhere(client, monkeypatch):
    monkeypatch.setenv("AUTH_DISABLED", "false")
    monkeypatch.setenv("JWT_SECRET", "a-long-test-secret-shared-by-the-whole-team")

    def bearer(role: str, expires_in: int = 300) -> dict:
        claims = {"sub": f"{role}@test.com", "role": role, "exp": int(time.time()) + expires_in}
        return {"Authorization": "Bearer " + jwt.encode(claims, "a-long-test-secret-shared-by-the-whole-team", algorithm="HS256")}

    assert client.post("/reports", json=PERIOD).status_code == 401
    assert client.post("/reports", json=PERIOD, headers=bearer("analyst", -10)).status_code == 401
    created = client.post("/reports", json=PERIOD, headers=bearer("analyst"))
    assert created.status_code == 202
    report_id = created.json()["id"]
    for method, path in (("post", "/reports"), ("get", "/reports"), ("get", f"/reports/{report_id}"), ("get", f"/reports/{report_id}/download")):
        response = getattr(client, method)(path, headers=bearer("viewer"), **({"json": PERIOD} if method == "post" else {}))
        assert response.status_code == 403, path
    report = client.get(f"/reports/{report_id}", headers=bearer("admin")).json()
    assert report["requested_by"] == "analyst@test.com"
    assert client.get(report["download_url"], headers=bearer("admin")).status_code == 200


def test_download_reports_its_state(client, tmp_path):
    assert client.get("/reports/999/download").status_code == 404
    pending = database.create_report("2026-10-20T00:00:00Z", "2026-10-13T00:00:00Z", "2026-10-20T00:00:00Z", ["logs"], "x")
    assert client.get(f"/reports/{pending['id']}/download").status_code == 409
    database.fail_report(pending["id"], "2026-10-20T00:00:01Z", "boom")
    response = client.get(f"/reports/{pending['id']}/download")
    assert response.status_code == 409 and "boom" in response.json()["detail"]
    report = generate(client)
    (tmp_path / "generated" / f"{report['reference']}.pdf").unlink()
    assert client.get(report["download_url"]).status_code == 410


def test_a_crashing_renderer_marks_the_report_failed(client, monkeypatch, history):
    monkeypatch.setattr(generator, "render_pdf", lambda *args: (_ for _ in ()).throw(RuntimeError("disk full")))
    report = generate(client)
    assert report["status"] == "failed" and "disk full" in report["error"] and report["download_url"] is None
    assert history == []


def test_restart_never_leaves_reports_processing(client):
    pending = database.create_report("2026-10-20T00:00:00Z", "2026-10-13T00:00:00Z", "2026-10-20T00:00:00Z", ["logs"], "x")
    database.initialise()
    assert database.get_report(pending["id"])["status"] == "failed"


def test_list_newest_first_without_internal_paths(client):
    first, second = generate(client), generate(client)
    listed = client.get("/reports").json()["reports"]
    assert [r["id"] for r in listed[:2]] == [second["id"], first["id"]]
    assert all("file_path" not in r for r in listed)


def test_recommendations_are_prioritised_and_specific(monkeypatch):
    monkeypatch.setenv("USE_MOCKS", "true")
    report = {"date_from": "2026-10-13T00:00:00Z", "date_to": "2026-10-20T23:59:59Z", "sections": list(report_data.SECTIONS), "created_at": "x"}
    recs = report_data.build_context(report, report_data.collect(report["date_from"], report["date_to"], None))["recommendations"]
    ranks = [("Immediate", "High", "Medium", "Low").index(r["priority"]) for r in recs]
    assert ranks == sorted(ranks) and recs[0]["priority"] == "Immediate"
    brute = next(r for r in recs if r["title"] == "Block brute-force sources")
    assert "203.0.113.5" in brute["action"] and "203.0.113.19" in brute["action"]
    assert build_recommendations(None, None, None)[0]["title"] == "Maintain current controls"
