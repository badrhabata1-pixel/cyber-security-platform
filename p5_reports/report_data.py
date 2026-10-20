"""Collects the three services' data for a period and turns it into the report's sections.

Every section is built defensively: a service that is down (None) or that answers with an
unexpected shape becomes an "unavailable" section, and the rest of the report still renders.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from clients import detection_client, domain_client, logs_client
from recommendations import build_recommendations

SECTIONS = ("summary", "logs", "alerts", "domains", "recommendations")
SEVERITIES = ("critical", "high", "medium", "low")
RISK_LEVELS = ("critical", "high", "medium", "low")
ALERT_STATUSES = ("open", "acknowledged", "resolved")
RULE_NAMES = {
    "brute_force": "Brute force", "password_spraying": "Password spraying", "success_after_failures": "Login after failures",
    "new_country": "New country login", "off_hours_login": "Off-hours login", "web_scan": "Web scan", "injection_attempt": "Injection attempt",
}
COUNTRIES = {
    "AE": "United Arab Emirates", "AR": "Argentina", "AU": "Australia", "BR": "Brazil", "CA": "Canada", "CH": "Switzerland",
    "CN": "China", "DE": "Germany", "EG": "Egypt", "ES": "Spain", "FR": "France", "GB": "United Kingdom", "HK": "Hong Kong",
    "ID": "Indonesia", "IL": "Israel", "IN": "India", "IR": "Iran", "IT": "Italy", "JO": "Jordan", "JP": "Japan", "KP": "North Korea",
    "KR": "South Korea", "KW": "Kuwait", "LB": "Lebanon", "MA": "Morocco", "MX": "Mexico", "NG": "Nigeria", "NL": "Netherlands",
    "PK": "Pakistan", "PL": "Poland", "QA": "Qatar", "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden",
    "SG": "Singapore", "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "US": "United States", "VN": "Vietnam", "ZA": "South Africa",
}
SOURCES = {
    "logs": ("Log analysis (SIEM)", "P2, port 8002"),
    "alerts": ("Intrusion detection", "P3, port 8003"),
    "domains": ("Domain intelligence", "P1, port 8001"),
}


class SectionError(Exception):
    """The service answered, but not with data this report can use."""


def parse_time(value) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def day_label(value: str) -> str:
    parsed = parse_time(value)
    return parsed.strftime("%d %b %Y") if parsed else value


def time_label(value) -> str:
    parsed = parse_time(value)
    return parsed.strftime("%d %b %Y, %H:%M UTC") if parsed else (value or "")


def short_time(value) -> str:
    parsed = parse_time(value)
    return parsed.strftime("%d %b %H:%M") if parsed else (value or "")


def country_name(code) -> str:
    return COUNTRIES.get(str(code).upper(), str(code)) if code else "Unknown"


def collect(date_from: str, date_to: str, token: str | None) -> dict:
    # The calls are independent, so a slow or dead service costs one timeout, not three
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {
            "stats": pool.submit(logs_client.summary, date_from, date_to, token),
            "alerts": pool.submit(detection_client.alerts, date_from, date_to, token),
            "alerts_summary": pool.submit(detection_client.alerts_summary, date_from, date_to, token),
            "scans": pool.submit(domain_client.scans, date_from, date_to, token),
        }
    return {name: job.result() for name, job in jobs.items()}


def _in_period(items: list, key: str, start: datetime, end: datetime) -> list[dict]:
    # Services are asked for the period too; filtering again keeps the report right if one ignores it
    kept = []
    for item in items:
        if not isinstance(item, dict):
            raise SectionError("list item is not an object")
        at = parse_time(item.get(key))
        if at is None or start <= at <= end:
            kept.append(item)
    return kept


def _pairs(items, limit: int = 8) -> list[tuple[str, int]]:
    if not isinstance(items, list):
        return []
    return [(str(item.get("value")), int(item.get("count") or 0)) for item in items if isinstance(item, dict) and item.get("value")][:limit]


def _logs(stats) -> dict:
    if not isinstance(stats, dict):
        raise SectionError("summary is not an object")
    total, failed = int(stats.get("total_events") or 0), int(stats.get("failed_logins") or 0)
    hours = [0] * 24
    for item in stats.get("by_hour") or []:
        hour = int(item.get("hour"))
        if 0 <= hour < 24:
            hours[hour] = int(item.get("count") or 0)
    top_ips = _pairs(stats.get("top_ips"))
    countries = [(country_name(code), count) for code, count in _pairs(stats.get("top_countries"))]
    peak = max(range(24), key=lambda h: hours[h]) if any(hours) else None
    return {
        "total": total, "failed": failed, "failure_rate": round(failed / total * 100, 1) if total else 0.0,
        "top_ips": top_ips, "top_countries": countries, "top_users": _pairs(stats.get("top_users")),
        "by_hour": hours, "peak_hour": peak,
        "top_ip_share": round(top_ips[0][1] / failed * 100) if top_ips and failed else 0,
        "top_country_share": round(countries[0][1] / failed * 100) if countries and failed else 0,
    }


def _alerts(alerts, summary, start: datetime, end: datetime) -> dict:
    if alerts is not None:
        if not isinstance(alerts, list):
            raise SectionError("alerts is not a list")
        alerts = _in_period(alerts, "created_at", start, end)
        by_severity = Counter(str(a.get("severity")) for a in alerts)
        by_status = Counter(str(a.get("status")) for a in alerts)
        by_rule = Counter(str(a.get("rule")) for a in alerts)
        unresolved = [a for a in alerts if a.get("status") != "resolved"]
        open_by_severity = Counter(str(a.get("severity")) for a in unresolved)
        rank = {severity: i for i, severity in enumerate(SEVERITIES)}
        priority = sorted(unresolved, key=lambda a: (rank.get(a.get("severity"), 9), -int(a.get("count") or 0)))
        details = True
    elif isinstance(summary, dict):
        # The list is down but the summary answered: show the counts without the alert table
        priority, details = [], False
        by_severity, by_status = Counter(summary.get("by_severity") or {}), Counter(summary.get("by_status") or {})
        # Per-alert status is unknown here: count every alert as unresolved, the cautious reading
        by_rule, open_by_severity = Counter(summary.get("by_rule") or {}), Counter(by_severity)
    else:
        raise SectionError("neither /alerts nor /alerts/summary returned data")
    rows = [{
        "id": a.get("id"), "severity": a.get("severity"), "rule": RULE_NAMES.get(a.get("rule"), str(a.get("rule"))),
        "rule_key": a.get("rule"), "ip": a.get("ip") or "", "count": int(a.get("count") or 0), "description": a.get("description") or "",
        "status": a.get("status"), "created_at": time_label(a.get("created_at")), "created_short": short_time(a.get("created_at")),
    } for a in priority]
    total = sum(by_severity.values())
    return {
        "total": total, "details": details, "rows": rows,
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITIES},
        "by_status": {s: by_status.get(s, 0) for s in ALERT_STATUSES},
        "by_rule": sorted(((RULE_NAMES.get(rule, rule), rule, count) for rule, count in by_rule.items()), key=lambda r: -r[2]),
        "open_by_severity": {s: open_by_severity.get(s, 0) for s in SEVERITIES},
        "open": by_status.get("open", 0) + by_status.get("acknowledged", 0),
    }


def _domains(scans, start: datetime, end: datetime) -> dict:
    if not isinstance(scans, list):
        raise SectionError("scans is not a list")
    latest: dict[str, dict] = {}
    for scan in sorted(_in_period(scans, "scanned_at", start, end), key=lambda s: str(s.get("scanned_at"))):
        if scan.get("domain"):
            latest[str(scan["domain"])] = scan  # a re-scanned domain keeps only its newest result
    rows = []
    for scan in sorted(latest.values(), key=lambda s: -int(s.get("risk_score") or 0)):
        whois, dns, ssl, blacklist = (scan.get(k) if isinstance(scan.get(k), dict) else {} for k in ("whois", "dns", "ssl", "blacklist"))
        reasons = [str(r) for r in scan.get("reasons") or []]
        rows.append({
            "domain": str(scan["domain"]), "score": int(scan.get("risk_score") or 0), "level": str(scan.get("risk_level") or "low"),
            "age_days": whois.get("age_days"), "registrar": whois.get("registrar"),
            "detections": blacklist.get("virustotal"), "safebrowsing": blacklist.get("safebrowsing"),
            "ssl_valid": ssl.get("valid"), "email_auth": bool(dns.get("spf")) and bool(dns.get("dmarc")),
            "reasons": [r for r in reasons if not r.startswith("Note: ")][:4],
            "scanned_at": time_label(scan.get("scanned_at")),
        })
    by_level = Counter(row["level"] for row in rows)
    return {"total": len(rows), "rows": rows, "by_level": {level: by_level.get(level, 0) for level in RISK_LEVELS},
            "riskiest": rows[0] if rows and rows[0]["score"] > 0 else None}


def _posture(logs, alerts, domains) -> tuple[str, str, str]:
    """Overall threat level: (label, status key, one-line reason)."""
    open_sev = alerts["open_by_severity"] if alerts else {}
    levels = domains["by_level"] if domains else {}
    if open_sev.get("critical") or levels.get("critical"):
        return "Critical", "critical", "Unresolved critical alerts or critical-risk domains require immediate action."
    if open_sev.get("high") or levels.get("high"):
        return "High", "high", "Unresolved high-severity activity needs attention within 24 hours."
    if open_sev.get("medium") or levels.get("medium") or (logs and logs["failed"] > 0):
        return "Elevated", "medium", "Suspicious activity was observed but nothing critical is unresolved."
    return "Low", "low", "No significant threat activity was observed in this period."


def _narrative(period: str, logs, alerts, domains) -> list[str]:
    sentences = []
    if logs:
        text = f"Between {period}, the SOC processed {logs['total']:,} log events, of which {logs['failed']:,} ({logs['failure_rate']}%) were failed or invalid login attempts"
        if logs["top_ips"]:
            ip, count = logs["top_ips"][0]
            text += f"; the most active source, {ip}, alone accounted for {count:,} of them ({logs['top_ip_share']}%)"
        sentences.append(text + ".")
    if alerts:
        sev = alerts["by_severity"]
        if alerts["total"]:
            sentences.append(f"Intrusion detection raised {alerts['total']} alerts ({sev['critical']} critical, {sev['high']} high), "
                             f"and {alerts['open']} of them are still awaiting resolution.")
        else:
            sentences.append("Intrusion detection raised no alerts in this period.")
    if domains:
        risky = domains["by_level"]["critical"] + domains["by_level"]["high"]
        text = f"{domains['total']} domains were assessed for threat intelligence and {risky} rated high or critical risk"
        if domains["riskiest"]:
            top = domains["riskiest"]
            text += f", led by {top['domain']} at {top['score']}/100"
        sentences.append(text + ".")
    return sentences or ["No data source was available when this report was generated."]


def _findings(logs, alerts, domains) -> list[str]:
    findings = []
    if alerts:
        for row in [r for r in alerts["rows"] if r["severity"] == "critical"][:2]:
            findings.append(f"Critical: {row['description']} (source {row['ip']}, {row['created_at']}).")
    if logs and logs["top_ips"]:
        ip, count = logs["top_ips"][0]
        findings.append(f"{ip} was the most persistent attacker with {count:,} failed logins ({logs['top_ip_share']}% of all failures).")
    if logs and logs["top_countries"]:
        country, count = logs["top_countries"][0]
        findings.append(f"{country} was the leading origin of failed logins ({count:,}, {logs['top_country_share']}%).")
    if domains and domains["riskiest"]:
        top = domains["riskiest"]
        reason = f": {top['reasons'][0].rstrip('.').lower()}" if top["reasons"] else ""
        findings.append(f"{top['domain']} scored {top['score']}/100 ({top['level']}){reason}.")
    if logs and logs["peak_hour"] is not None:
        findings.append(f"Activity peaked at {logs['peak_hour']:02d}:00 UTC with {logs['by_hour'][logs['peak_hour']]:,} events in that hour.")
    return findings[:5]


def build_context(report: dict, raw: dict) -> dict:
    start, end = parse_time(report["date_from"]), parse_time(report["date_to"])
    wanted = set(report["sections"])
    built, unavailable = {}, {}
    for name, build in (("logs", lambda: _logs(raw["stats"]) if raw["stats"] is not None else None),
                        ("alerts", lambda: _alerts(raw["alerts"], raw["alerts_summary"], start, end) if raw["alerts"] is not None or raw["alerts_summary"] is not None else None),
                        ("domains", lambda: _domains(raw["scans"], start, end) if raw["scans"] is not None else None)):
        try:
            built[name] = build()
            if built[name] is None:
                unavailable[name] = "The service did not respond when this report was generated."
        except (SectionError, AttributeError, KeyError, TypeError, ValueError):
            built[name] = None
            unavailable[name] = "The service responded with data in an unexpected format."
    logs, alerts, domains = built["logs"], built["alerts"], built["domains"]
    period = f"{day_label(report['date_from'])} and {day_label(report['date_to'])}"
    posture = _posture(logs, alerts, domains)
    narrative = _narrative(period, logs, alerts, domains)
    if unavailable and len(unavailable) < len(SOURCES):
        names = [SOURCES[name][0] for name in SOURCES if name in unavailable]
        narrative.append(f"{' and '.join(names)} data {'was' if len(names) == 1 else 'were'} unavailable when this report was generated, "
                         f"so {'that section is' if len(names) == 1 else 'those sections are'} marked as incomplete.")
    return {
        "report": report, "wanted": wanted,
        "period_label": f"{day_label(report['date_from'])} – {day_label(report['date_to'])}",
        "generated_label": time_label(report["created_at"]),
        "logs": logs, "alerts": alerts, "domains": domains,
        "unavailable": {name: {"reason": reason, "title": SOURCES[name][0], "service": SOURCES[name][1]} for name, reason in unavailable.items()},
        "sources": [{"key": key, "title": title, "service": service, "available": key not in unavailable} for key, (title, service) in SOURCES.items()],
        "posture": {"label": posture[0], "key": posture[1], "reason": posture[2]},
        "narrative": narrative,
        "findings": _findings(logs, alerts, domains),
        "recommendations": build_recommendations(logs, alerts, domains),
    }
