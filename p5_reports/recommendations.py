"""Turns what the report found into prioritised, concrete remediation actions."""

PRIORITIES = ("Immediate", "High", "Medium", "Low")


def _ips(rows: list[dict], rule: str) -> list[str]:
    seen = []
    for row in rows:
        if row["rule_key"] == rule and row["ip"] and row["ip"] not in seen:
            seen.append(row["ip"])
    return seen


def _join(items: list[str], limit: int = 4) -> str:
    shown = items[:limit]
    text = ", ".join(shown[:-1]) + (" and " if len(shown) > 1 else "") + shown[-1]
    return text + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def build_recommendations(logs, alerts, domains) -> list[dict]:
    actions = []

    def add(priority: str, title: str, action: str, evidence: str) -> None:
        actions.append({"priority": priority, "title": title, "action": action, "evidence": evidence})

    rows = alerts["rows"] if alerts else []
    if ips := _ips(rows, "success_after_failures"):
        add("Immediate", "Contain possibly compromised accounts",
            f"Treat the accounts that logged in from {_join(ips)} as compromised: reset their passwords, revoke active sessions and keys, "
            "and review everything they accessed after the login.",
            "A successful login followed a run of failed attempts from the same source.")
    if ips := _ips(rows, "brute_force"):
        add("Immediate", "Block brute-force sources",
            f"Block {_join(ips)} at the firewall, enable fail2ban or equivalent rate limiting on SSH, "
            "and switch SSH to key-based authentication only.",
            f"{len(ips)} source{'s' if len(ips) > 1 else ''} triggered the brute-force rule.")
    if ips := _ips(rows, "password_spraying"):
        add("High", "Stop password spraying",
            f"Block {_join(ips)}, enforce multi-factor authentication for all remote logins and apply an account lockout policy.",
            "One source tried many different usernames in a short window.")
    if ips := _ips(rows, "injection_attempt"):
        add("High", "Harden web applications against injection",
            f"Block {_join(ips)}, enable WAF rules for SQL injection and path traversal, "
            "and confirm the affected endpoints use parameterised queries and strict path validation.",
            "Requests contained SQL injection, path traversal or script payloads.")
    if ips := _ips(rows, "web_scan"):
        add("Medium", "Throttle web scanners",
            f"Rate-limit or block {_join(ips)} and remove server version banners to reduce reconnaissance value.",
            "Bursts of 404 responses show automated content discovery.")
    if _ips(rows, "new_country"):
        add("Medium", "Verify logins from new countries",
            "Confirm with the affected users that their first login from a new country was legitimate, and consider conditional access by location.",
            "A user signed in from a country never seen in their history.")
    if _ips(rows, "off_hours_login"):
        add("Low", "Review off-hours access",
            "Review successful logins between 01:00 and 05:00 UTC and restrict administrative access outside working hours to VPN only.",
            "Successful logins occurred during off hours.")

    if domains:
        for level, priority in (("critical", "Immediate"), ("high", "High")):
            names = [row["domain"] for row in domains["rows"] if row["level"] == level]
            if names:
                add(priority, f"Block {level}-risk domains",
                    f"Block {_join(names)} at the DNS resolver and web proxy, and warn staff not to open links to {'them' if len(names) > 1 else 'it'}.",
                    f"{len(names)} domain{'s' if len(names) > 1 else ''} scored {level} risk in threat-intelligence scans.")

    if logs and logs["failed"]:
        users = [user for user, _ in logs["top_users"]]
        if "root" in users:
            add("High", "Disable direct root login",
                "Set PermitRootLogin no in sshd_config and require named accounts with sudo, so attacks on root cannot succeed.",
                f"root is among the most targeted usernames in {logs['failed']:,} failed logins.")
        if logs["top_countries"] and logs["top_country_share"] >= 25:
            country, _ = logs["top_countries"][0]
            add("Medium", "Consider geo-restricting remote access",
                f"If the organisation has no users in {country}, restrict SSH and admin panels from that region at the edge firewall.",
                f"{country} is the origin of {logs['top_country_share']}% of failed logins.")

    if not actions:
        add("Low", "Maintain current controls",
            "No action is required beyond routine monitoring. Keep detection rules and threat-intelligence feeds up to date.",
            "No significant threats were detected in this period.")
    rank = {priority: i for i, priority in enumerate(PRIORITIES)}
    return sorted(actions, key=lambda a: rank[a["priority"]])
