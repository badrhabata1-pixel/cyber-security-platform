import json
from datetime import datetime, timedelta, timezone

def generate_events():
    events = []
    event_id = 1
    # استخدام توقيت UTC دائماً وفقاً للشروط
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    def add_event(time_offset_sec, event_type, ip, user_id=None, country="EG", http_status=None, http_path=None):
        nonlocal event_id
        t = base_time + timedelta(seconds=time_offset_sec)
        events.append({
            "id": event_id,
            "timestamp": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": event_type,
            "ip": ip,
            "user_id": user_id,
            "country": country,
            "http_status": http_status,
            "http_path": http_path
        })
        event_id += 1

    # --- 1. أحداث طبيعية (Normal Traffic) ---
    for i in range(10):
        add_event(i * 10, "login_success", "192.168.1.100", user_id="alice", country="EG")
        add_event(i * 10 + 2, "http_request", "192.168.1.100", http_status=200, http_path="/dashboard")

    # --- 2. هجوم Brute Force (6 محاولات فشل لنفس المستخدم من نفس الـ IP في 30 ثانية) ---
    ip_bf = "198.51.100.10"
    for i in range(6):
        add_event(100 + (i * 5), "login_failed", ip_bf, user_id="bob", country="US")

    # --- 3. هجوم Password Spraying (6 مستخدمين مختلفين من نفس الـ IP في دقيقتين) ---
    ip_spray = "198.51.100.20"
    users = ["user1", "user2", "user3", "user4", "user5", "user6"]
    for i, u in enumerate(users):
        add_event(200 + (i * 15), "login_failed", ip_spray, user_id=u, country="RU")

    # --- 4. هجوم Success After Failures (5 فشل ثم دخول ناجح لنفس الـ IP) ---
    ip_saf = "198.51.100.30"
    for i in range(5):
        add_event(300 + (i * 4), "login_failed", ip_saf, user_id="admin", country="DE")
    add_event(325, "login_success", ip_saf, user_id="admin", country="DE")

    # --- 5. هجوم Web Scan (25 طلب 404 في 40 ثانية) ---
    ip_scan = "198.51.100.40"
    for i in range(25):
        add_event(400 + i, "http_request", ip_scan, http_status=404, http_path=f"/test-{i}.php")

    # --- 6. هجوم Injection (طلب مسار يحتوي على UNION SELECT أو ../) ---
    ip_inj = "198.51.100.50"
    add_event(500, "http_request", ip_inj, http_status=500, http_path="/products?id=1 UNION SELECT * FROM users")
    add_event(505, "http_request", ip_inj, http_status=403, http_path="/static/../../etc/passwd")

    # --- 7. دخول في أوقات غير رسمية (Off Hours Login بين 1 و 5 فجراً UTC) ---
    ip_off = "198.51.100.60"
    off_hours_time = datetime(2026, 10, 15, 3, 15, 0, tzinfo=timezone.utc)
    events.append({
        "id": event_id,
        "timestamp": off_hours_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": "login_success",
        "ip": ip_off,
        "user_id": "charlie",
        "country": "EG",
        "http_status": None,
        "http_path": None
    })

    return events

if __name__ == "__main__":
    generated = generate_events()
    output_path = "p3_detection/mock_events.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(generated, f, indent=2)
    print(f"✅ Generated {len(generated)} events successfully into {output_path}!")
