import re
from datetime import datetime, timezone

SSH_RE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?:(?P<invalid>Invalid user)\s+(?P<invalid_user>\S+)\s+from\s+(?P<invalid_ip>\S+)|"
    r"(?P<action>Failed password|Accepted password)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+))"
)


def _timestamp(value: str) -> str:
    parsed = datetime.strptime(f"{datetime.now(timezone.utc).year} {value}", "%Y %b %d %H:%M:%S")
    return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ssh(line: str) -> dict | None:
    match = SSH_RE.match(line.strip())
    if not match:
        return None
    groups = match.groupdict()
    invalid = bool(groups["invalid"])
    action = groups["action"]
    return {
        "timestamp": _timestamp(groups["stamp"]), "source": "ssh",
        "ip": groups["invalid_ip"] if invalid else groups["ip"],
        "username": groups["invalid_user"] if invalid else groups["user"],
        "event_type": "invalid_user" if invalid else ("login_failed" if action == "Failed password" else "login_success"),
        "status": "fail" if invalid or action == "Failed password" else "success",
        "user_agent": None, "http_path": None, "http_status": None, "raw": line.rstrip(),
    }
