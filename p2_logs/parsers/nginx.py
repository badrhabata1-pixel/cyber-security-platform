import re
from datetime import datetime, timezone

NGINX_RE = re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<stamp>[^]]+)\] "(?P<method>\S+) (?P<path>\S+)(?: \S+)?" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"')


def parse_nginx(line: str) -> dict | None:
    match = NGINX_RE.match(line.strip())
    if not match:
        return None
    data = match.groupdict()
    try:
        timestamp = datetime.strptime(data["stamp"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return {"timestamp": timestamp, "source": "web", "ip": data["ip"], "username": None,
            "event_type": "http_request", "status": "success" if int(data["status"]) < 400 else "fail",
            "user_agent": data["ua"] or None, "http_path": data["path"], "http_status": int(data["status"]), "raw": line.rstrip()}
