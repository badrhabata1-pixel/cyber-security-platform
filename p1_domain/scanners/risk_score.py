"""Risk scoring engine: turns the five scanner results into one 0-100 score, a level and reasons."""

# Points per category are capped so one noisy area can't dominate: 50 + 25 + 25 + 15 + 30 = 145
# possible, clamped to 100, which means "critical" needs problems in several areas at once
CAPS = {"blacklist": 50, "registration": 25, "ssl": 25, "email": 15, "heuristics": 30}

# (lowest score, level), checked from the top
LEVELS = ((75, "critical"), (50, "high"), (25, "medium"), (0, "low"))

CLEAN = "Clean: Passed all security and reputation checks"
# Notes explain a gap in the picture (a check that couldn't run or doesn't apply). They add no
# points, but they stop "Clean" from being claimed. The console UI recognises this prefix.
NOTE = "Note: "


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _int(value) -> int | None:
    # bool is an int subclass, but True/False here would be a data error, not a number
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _calculate(whois: dict, dns: dict, ssl: dict, blacklist: dict, heuristics: dict) -> tuple[int, str, list[str]]:
    points = dict.fromkeys(CAPS, 0)
    scored: list[tuple[int, str]] = []
    notes: list[str] = []

    def flag(category: str, value: int, reason: str) -> None:
        points[category] += value
        scored.append((value, reason))

    details = _dict(heuristics.get("details"))
    ip_host = details.get("ip_host") is True
    # A domain with no A, MX or NS record isn't live: SSL and e-mail checks don't apply to it
    resolves = ip_host or any(isinstance(dns.get(key), list) and dns[key] for key in ("a", "mx", "ns"))
    if dns and not resolves:
        notes.append(f"{NOTE}the domain has no DNS records, so it does not appear to be live; SSL and email checks do not apply")

    # Blacklist / threat intelligence (max 50)
    hits = _int(blacklist.get("virustotal"))
    if blacklist.get("error"):
        error = str(blacklist["error"])
        notes.append(
            f"{NOTE}VirusTotal has no history for this domain, so its reputation is unknown"
            if error.startswith("Not found")
            else f"{NOTE}reputation check unavailable ({error}), so the score excludes threat-intelligence data"
        )
    elif hits is None:
        notes.append(f"{NOTE}reputation check returned no data, so the score excludes threat-intelligence data")
    elif hits >= 3:
        flag("blacklist", 45, "Flagged by multiple security engines as malicious")
    elif blacklist.get("safebrowsing") == "unsafe":
        flag("blacklist", 45, "Listed as unsafe by Google Safe Browsing")
    elif hits > 0:
        flag("blacklist", 15, "Flagged by isolated vendor on VirusTotal")

    # Domain age & expiry (max 25); IP addresses have no registration age
    age = _int(whois.get("age_days"))
    days_left = _int(whois.get("expires_days_left"))
    if age is None:
        if resolves and not ip_host:
            notes.append(f"{NOTE}WHOIS data unavailable, so the domain's age and expiry could not be verified")
    elif age < 30:
        flag("registration", 25, "Domain is brand new: less than 30 days old")
    elif age < 90:
        flag("registration", 10, "Domain is young: less than 90 days old")
    if days_left is not None and days_left < 0:
        flag("registration", 20, "Domain registration has expired")

    # SSL / encryption (max 25). The error texts come from scanners/ssl_check.py.
    ssl_error = str(ssl.get("error") or "")
    if ssl.get("valid") is False:
        if ssl_error.startswith("Skipped"):
            notes.append(f"{NOTE}SSL not checked because the domain points to an internal network address")
        elif ssl_error.startswith("DNS lookup timed out"):
            notes.append(f"{NOTE}SSL could not be checked because the DNS lookup timed out")
        elif resolves and "does not resolve" not in ssl_error and ssl_error != "No domain provided":
            detail = f" ({ssl_error})" if ssl_error else ""
            flag("ssl", 20, f"Missing, invalid, self-signed, or expired SSL certificate{detail}")

    # Email security (max 15); only real, live domains can publish SPF / DMARC
    if dns.get("spf") is False and dns.get("dmarc") is False and resolves and not ip_host:
        flag("email", 15, "No SPF or DMARC email authentication configured (spoofing risk)")

    # Heuristic patterns (max 30): every finding is listed even once the cap is reached
    findings = heuristics.get("findings")
    for finding in findings if isinstance(findings, list) else []:
        flag("heuristics", 10, str(finding))
    if heuristics.get("error"):
        notes.append(f"{NOTE}URL patterns could not be analysed ({heuristics['error']})")

    score = max(0, min(100, sum(min(points[category], cap) for category, cap in CAPS.items())))
    level = next(name for floor, name in LEVELS if score >= floor)
    # Heaviest red flags first (stable, so equal weights keep their check order), notes last
    reasons = [reason for _, reason in sorted(scored, key=lambda item: -item[0])] + notes
    if score == 0 and not reasons:
        reasons.append(CLEAN)
    return score, level, reasons


def calculate_risk(whois_data, dns_data, ssl_data, blacklist_data, heuristics_data) -> tuple[int, str, list[str]]:
    try:
        return _calculate(
            _dict(whois_data), _dict(dns_data), _dict(ssl_data), _dict(blacklist_data), _dict(heuristics_data)
        )
    except Exception:
        # Never claim "Clean" when scoring itself broke
        return 0, "low", [f"{NOTE}risk scoring failed, so review the individual checks below"]
