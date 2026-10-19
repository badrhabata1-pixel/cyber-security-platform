# P5 Executive Security Reports

Turns the other services' data into an executive PDF report for a chosen period: cover page, executive summary, log intelligence, intrusion alerts, domain threat intelligence, prioritised recommendations and an appendix. Runs on port 8005.

## Run locally

```powershell
cd p5_reports
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn main:app --host 0.0.0.0 --port 8005
```

Open `http://localhost:8005/` for the reports page, or `http://localhost:8005/docs` for the API. With `USE_MOCKS=true` (the default in `.env.example`) reports are built from `mocks/`, so nothing else needs to be running.

Tests (22, covering the Definition of Done below):

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Everything installs from PyPI on Windows, Linux and macOS. The PDF engine is xhtml2pdf rather than WeasyPrint because WeasyPrint needs the GTK/Pango system libraries on Windows.

## API

All `/reports` endpoints need an HS256 bearer JWT signed with the shared `JWT_SECRET` whose `role` is `admin` or `analyst`. `viewer` gets `403`, a missing or expired token `401`. `AUTH_DISABLED=true` treats every request as admin, for local development only.

| Endpoint | Method | Purpose |
|---|---|---|
| `/health` | GET | `{"status": "ok"}` |
| `/reports` | POST | Body `{"from": "2026-10-13", "to": "2026-10-20", "sections": [...]}`. Returns `202` with `{"id", "reference", "status": "processing"}` and generates the PDF in the background |
| `/reports` | GET | `{"reports": [...]}`, newest first (`?limit=`, default 50) |
| `/reports/{id}` | GET | One report, for polling its `status` (`processing`, `completed` or `failed`) |
| `/reports/{id}/download` | GET | The PDF. `409` while processing or after a failure, `410` if the file was deleted |

* `from` / `to` accept a date (`2026-10-20` covers the whole day) or a UTC datetime (`2026-10-20T14:00:00Z`). Both are optional: the default is the last 7 days.
* `sections` is any of `summary`, `logs`, `alerts`, `domains`, `recommendations` (default: all). The cover page and the appendix are always included.
* Each report row records who asked for it (`requested_by`, the token's `sub`), a unique reference such as `RPT-20261020-0007`, and `unavailable`: the data sources that were down while it was generated.
* When a report completes, a summary is sent to P4 with `POST /history` (`module: "reports"`, `action: "report_generated"`, `ref_id`: the reference). If P4 is down, it is skipped.

## Resilience

* Each data source is fetched in parallel with a 3-second timeout. A source that is down, or that answers with an unexpected shape, turns its section into a "Data for this section is currently unavailable" notice. The rest of the report is still generated, and the cover and appendix list each source's status.
* An empty period still produces a valid PDF, with "No alerts were raised in this period" and similar messages.
* A report that fails to render is marked `failed` with the error. Reports left `processing` by a restart are marked `failed` on startup.
* Measured on Windows: about 1.1 s from mocks and 2.8 s with P2 live and P1 and P3 down, against a 5-second target.

## Data sources

| Client | Service | Calls | Mock |
|---|---|---|---|
| `clients/domain_client.py` | P1, port 8001 | `GET /scans?from=&to=` | `mocks/scans.json` |
| `clients/logs_client.py` | P2, port 8002 | `GET /stats/summary?from=&to=` | `mocks/stats_summary.json` |
| `clients/detection_client.py` | P3, port 8003 | `GET /alerts?from=&to=`, `GET /alerts/summary?from=&to=` | `mocks/alerts.json`, `mocks/alerts_summary.json` |
| `clients/platform_client.py` | P4, port 8000 | `POST /history` | none |

Set `USE_MOCKS=false` to use the real services. Their URLs come from `DOMAIN_SERVICE_URL`, `LOGS_SERVICE_URL`, `DETECTION_SERVICE_URL` and `PLATFORM_SERVICE_URL`. The defaults use `127.0.0.1`, not `localhost`: on Windows, `localhost` tries IPv6 first, so a service that is down costs two connection timeouts instead of one. The user's token is forwarded to each service.

### What P5 expects from each service (please confirm)

The mocks match the real responses where they exist. P1's scan objects are exactly P1's `POST /scan` result, and P2's summary is exactly P2's `/stats/summary`. These parts are not built yet, so they are proposals:

* **P1, `GET /scans`**: `{"scans": [<the POST /scan result>, ...]}`, filtered by `from`/`to` on `scanned_at`. A bare list also works.
* **P2, `GET /stats/summary`**: please honour `from`/`to`. Today it returns all-time figures. Lists from P1 and P3 are re-filtered by P5, but this summary cannot be.
* **P3, `GET /alerts`**: `{"alerts": [<Alert contract>, ...]}` filtered on `created_at`. A bare list also works.
* **P3, `GET /alerts/summary`**: `{"total", "by_severity": {...}, "by_rule": {...}, "by_status": {...}}`, as in `mocks/alerts_summary.json`. P5 uses it only when `/alerts` is unavailable: counts are otherwise computed from the alert list, so the chart and the table always agree.
* **P4, `JWT_SECRET`**: at least 32 characters. PyJWT warns about shorter HS256 keys.

## UI and the P4 shell

* `ui/manifest.js`: `{ path: "/reports", title: "Security Reports", roles: ["admin", "analyst"] }`
* `ui/index.jsx` default-exports the React page. The shell renders it with optional props `token` (the user's JWT; falls back to `localStorage.token`) and `apiBase` (falls back to `VITE_REPORTS_API`, then `http://127.0.0.1:8005`). It imports only `react`.
* CORS allows any `localhost` / `127.0.0.1` origin, so the shell can call the API from its own port. Override it with `CORS_ORIGIN_REGEX`.
* `ui/index.html` runs the same page standalone at `http://localhost:8005/`, loading React from a CDN. Pass a token as `/#token=<jwt>` when auth is enabled.

## Security

* Text from other services (domain names, alert descriptions, usernames) is HTML-escaped by Jinja2 autoescaping.
* xhtml2pdf runs under a strict resource policy: no network fetches and no local file reads except the bundled fonts. A hostile domain name like `<img src="http://169.254.169.254/...">` is printed as text, never fetched (tested).
* Downloads are served by report id, never by a path from the request. UI assets reject `..` traversal.

## Files

| File | Role |
|---|---|
| `main.py` | FastAPI app, validation, endpoints, UI hosting |
| `auth.py` | Local JWT check (admin / analyst) |
| `database.py` | SQLite `reports` table (`reports.sqlite3`, git-ignored) |
| `generator.py` | Background job: collect, build, render, record history |
| `report_data.py` | Fetches the sources in parallel and builds each section defensively |
| `recommendations.py` | Turns findings into prioritised remediation actions |
| `charts.py` | matplotlib charts as base64 PNGs |
| `pdf.py`, `templates/report.html` | Jinja2 A4 template rendered with xhtml2pdf; PDFs land in `generated/` (git-ignored) |
| `ui/` | Reports page and shell manifest |
| `tests/` | pytest suite |
