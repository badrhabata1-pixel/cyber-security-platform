# P2 Log Analysis / SIEM

Run locally on port 8002:

```powershell
cd p2_logs
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python generate_logs.py
uvicorn main:app --host 0.0.0.0 --port 8002
```

Open `http://localhost:8002/logs` for the dashboard. `AUTH_DISABLED=true` is intended only for local development. Set it to `false` and set `JWT_SECRET` in deployed environments; requests then require an HS256 bearer JWT whose `role` is `admin` or `analyst`.

## Real GeoIP

Create a free MaxMind account, download **GeoLite2 City** from MaxMind, and place the extracted `GeoLite2-City.mmdb` at `p2_logs/geoip/GeoLite2-City.mmdb` (this binary is deliberately git-ignored due to its license/size). The service enriches public IPs with actual country/city values when it is present. It continues safely without it.

## Integration

* `POST /ingest` accepts `{ "source": "ssh|web|platform_login", "lines": ["..."] }`, or `{ "events": [...] }`.
* `POST /upload` accepts multipart field `file` and optional `source` (`ssh` by default).
* `GET /events?since_id=&from=&to=&ip=&limit=` is poll-safe for Person 3.
* `GET /stats/summary` and `GET /stats/geo` are report/dashboard-safe for Person 5.

All event timestamps are UTC ISO-8601 values ending in `Z`. Bad lines are retained in the `unparsed` SQLite table and never fail an ingestion batch.
