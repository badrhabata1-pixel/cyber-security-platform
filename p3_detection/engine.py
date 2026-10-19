import os
import yaml
from datetime import datetime, timezone
from typing import List, Dict, Any
try:
    from p3_detection.database import get_db
except ImportError:
    from database import get_db

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.yaml")

def load_rules_config() -> dict:
    if not os.path.exists(RULES_FILE):
        return {}
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f).get("rules", {})

def parse_iso(ts_str: str) -> datetime:
    """تحويل نص التاريخ ISO 8601 إلى datetime بتوقيت UTC دائماً"""
    return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

class DetectionEngine:
    def __init__(self):
        self.rules = load_rules_config()

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        تستقبل قائمة Events نظيفة وترجع قائمة Alerts مكتشفة
        """
        alerts = []
        if not events:
            return alerts

        # ترتيب الأحداث زمنياً للتأكد من دقة النوافذ الزمنية
        sorted_events = sorted(events, key=lambda x: parse_iso(x["timestamp"]))

        # تطبيق القواعد السبعة
        alerts.extend(self._check_brute_force(sorted_events))
        alerts.extend(self._check_password_spraying(sorted_events))
        alerts.extend(self._check_success_after_failures(sorted_events))
        alerts.extend(self._check_new_country(sorted_events))
        alerts.extend(self._check_off_hours_login(sorted_events))
        alerts.extend(self._check_web_scan(sorted_events))
        alerts.extend(self._check_injection_attempt(sorted_events))

        return alerts

    # 1. قاعدة Brute Force
    def _check_brute_force(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("brute_force", {})
        if not cfg.get("enabled", True):
            return []

        threshold = cfg.get("threshold", 5)
        window = cfg.get("window_seconds", 60)
        alerts = []

        by_ip = {}
        for ev in events:
            if ev.get("event_type") == "login_failed":
                by_ip.setdefault(ev["ip"], []).append(ev)

        for ip, ev_list in by_ip.items():
            for i in range(len(ev_list)):
                window_evs = [ev_list[i]]
                t_start = parse_iso(ev_list[i]["timestamp"])
                for j in range(i + 1, len(ev_list)):
                    t_curr = parse_iso(ev_list[j]["timestamp"])
                    if (t_curr - t_start).total_seconds() <= window:
                        window_evs.append(ev_list[j])

                if len(window_evs) >= threshold:
                    alerts.append({
                        "rule": "brute_force",
                        "severity": cfg.get("severity", "high"),
                        "ip": ip,
                        "count": len(window_evs),
                        "description": f"{len(window_evs)} failed logins in {window}s",
                        "event_ids": [e["id"] for e in window_evs],
                        "created_at": window_evs[-1]["timestamp"]
                    })
                    break
        return alerts

    # 2. قاعدة Password Spraying
    def _check_password_spraying(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("password_spraying", {})
        if not cfg.get("enabled", True):
            return []

        threshold = cfg.get("threshold", 5)
        window = cfg.get("window_seconds", 300)
        alerts = []

        by_ip = {}
        for ev in events:
            if ev.get("event_type") == "login_failed" and ev.get("user_id"):
                by_ip.setdefault(ev["ip"], []).append(ev)

        for ip, ev_list in by_ip.items():
            for i in range(len(ev_list)):
                window_evs = [ev_list[i]]
                distinct_users = {ev_list[i]["user_id"]}
                t_start = parse_iso(ev_list[i]["timestamp"])

                for j in range(i + 1, len(ev_list)):
                    t_curr = parse_iso(ev_list[j]["timestamp"])
                    if (t_curr - t_start).total_seconds() <= window:
                        window_evs.append(ev_list[j])
                        distinct_users.add(ev_list[j]["user_id"])

                if len(distinct_users) >= threshold:
                    alerts.append({
                        "rule": "password_spraying",
                        "severity": cfg.get("severity", "high"),
                        "ip": ip,
                        "count": len(distinct_users),
                        "description": f"Targeted {len(distinct_users)} distinct users in {window}s",
                        "event_ids": [e["id"] for e in window_evs],
                        "created_at": window_evs[-1]["timestamp"]
                    })
                    break
        return alerts

    # 3. قاعدة Success After Failures
    def _check_success_after_failures(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("success_after_failures", {})
        if not cfg.get("enabled", True):
            return []

        threshold = cfg.get("threshold_failures", 5)
        window = cfg.get("window_seconds", 300)
        alerts = []

        by_ip = {}
        for ev in events:
            if ev.get("event_type") in ["login_failed", "login_success"]:
                by_ip.setdefault(ev["ip"], []).append(ev)

        for ip, ev_list in by_ip.items():
            for i, ev in enumerate(ev_list):
                if ev.get("event_type") == "login_success":
                    t_success = parse_iso(ev["timestamp"])
                    prior_failures = [
                        e for e in ev_list[:i]
                        if e.get("event_type") == "login_failed"
                        and (t_success - parse_iso(e["timestamp"])).total_seconds() <= window
                    ]
                    if len(prior_failures) >= threshold:
                        alerts.append({
                            "rule": "success_after_failures",
                            "severity": cfg.get("severity", "critical"),
                            "ip": ip,
                            "count": len(prior_failures) + 1,
                            "description": f"Login success after {len(prior_failures)} failures in {window}s",
                            "event_ids": [e["id"] for e in prior_failures] + [ev["id"]],
                            "created_at": ev["timestamp"]
                        })
        return alerts

    # 4. قاعدة New Country
    def _check_new_country(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("new_country", {})
        if not cfg.get("enabled", True):
            return []

        alerts = []
        with get_db() as conn:
            cursor = conn.cursor()
            for ev in events:
                if ev.get("event_type") == "login_success" and ev.get("user_id") and ev.get("country"):
                    cursor.execute("SELECT 1 FROM user_country_history WHERE user_id = ?", (ev["user_id"],))
                    has_prior = cursor.fetchone() is not None

                    cursor.execute(
                        "SELECT 1 FROM user_country_history WHERE user_id = ? AND country = ?",
                        (ev["user_id"], ev["country"])
                    )
                    seen_country = cursor.fetchone() is not None

                    if has_prior and not seen_country:
                        alerts.append({
                            "rule": "new_country",
                            "severity": cfg.get("severity", "medium"),
                            "ip": ev["ip"],
                            "count": 1,
                            "description": f"User '{ev['user_id']}' logged in from new country: {ev['country']}",
                            "event_ids": [ev["id"]],
                            "created_at": ev["timestamp"]
                        })

                    # حفظ الدولة في الذاكرة/الداتا بيز
                    cursor.execute(
                        "INSERT OR IGNORE INTO user_country_history (user_id, country, first_seen) VALUES (?, ?, ?)",
                        (ev["user_id"], ev["country"], ev["timestamp"])
                    )
            conn.commit()
        return alerts

    # 5. قاعدة Off Hours Login
    def _check_off_hours_login(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("off_hours_login", {})
        if not cfg.get("enabled", True):
            return []

        s_h = cfg.get("start_hour", 1)
        e_h = cfg.get("end_hour", 5)
        alerts = []

        for ev in events:
            if ev.get("event_type") == "login_success":
                dt = parse_iso(ev["timestamp"])
                if s_h <= dt.hour < e_h:
                    alerts.append({
                        "rule": "off_hours_login",
                        "severity": cfg.get("severity", "low"),
                        "ip": ev["ip"],
                        "count": 1,
                        "description": f"Login occurred during off-hours ({dt.strftime('%H:%M')} UTC)",
                        "event_ids": [ev["id"]],
                        "created_at": ev["timestamp"]
                    })
        return alerts

    # 6. قاعدة Web Scan
    def _check_web_scan(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("web_scan", {})
        if not cfg.get("enabled", True):
            return []

        threshold = cfg.get("threshold", 20)
        window = cfg.get("window_seconds", 60)
        alerts = []

        by_ip = {}
        for ev in events:
            if ev.get("event_type") == "http_request" and ev.get("http_status") == 404:
                by_ip.setdefault(ev["ip"], []).append(ev)

        for ip, ev_list in by_ip.items():
            for i in range(len(ev_list)):
                window_evs = [ev_list[i]]
                t_start = parse_iso(ev_list[i]["timestamp"])
                for j in range(i + 1, len(ev_list)):
                    t_curr = parse_iso(ev_list[j]["timestamp"])
                    if (t_curr - t_start).total_seconds() <= window:
                        window_evs.append(ev_list[j])

                if len(window_evs) >= threshold:
                    alerts.append({
                        "rule": "web_scan",
                        "severity": cfg.get("severity", "medium"),
                        "ip": ip,
                        "count": len(window_evs),
                        "description": f"More than {threshold} 404 responses ({len(window_evs)}) in {window}s",
                        "event_ids": [e["id"] for e in window_evs],
                        "created_at": window_evs[-1]["timestamp"]
                    })
                    break
        return alerts

    # 7. قاعدة Injection Attempt
    def _check_injection_attempt(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        cfg = self.rules.get("injection_attempt", {})
        if not cfg.get("enabled", True):
            return []

        patterns = cfg.get("patterns", ["UNION SELECT", "../", "<script>"])
        alerts = []

        for ev in events:
            path = ev.get("http_path") or ""
            for pat in patterns:
                if pat.lower() in path.lower():
                    alerts.append({
                        "rule": "injection_attempt",
                        "severity": cfg.get("severity", "high"),
                        "ip": ev["ip"],
                        "count": 1,
                        "description": f"Detected injection pattern '{pat}' in path: {path}",
                        "event_ids": [ev["id"]],
                        "created_at": ev["timestamp"]
                    })
                    break
        return alerts
