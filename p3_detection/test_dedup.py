import os
import sys

sys.path.insert(0, os.path.abspath("."))

from p3_detection.database import save_or_dedup_alert

mock_alert = {
    "rule": "injection_attempt",
    "severity": "high",
    "ip": "203.0.113.99",
    "count": 1,
    "description": "SQL injection detected",
    "event_ids": [101]
}

print("1️⃣ إرسال التنبيه للمرة الأولى:")
alert1, is_new1 = save_or_dedup_alert(mock_alert)
print(f" -> Alert ID: {alert1['id']}, Count: {alert1['count']}, Is New: {is_new1}")

print("\n2️⃣ إرسال نفس التنبيه لنفس الـ IP بعد ثوانٍ:")
mock_alert["event_ids"] = [102]
alert2, is_new2 = save_or_dedup_alert(mock_alert)
print(f" -> Alert ID: {alert2['id']}, Count: {alert2['count']}, Is New: {is_new2}")

if alert1["id"] == alert2["id"] and alert2["count"] == 2 and not is_new2:
    print("\n🎉 SUCCESS! الـ Deduplication شغال بنجاح وتم زيادة العداد في نفس التنبيه!")
else:
    print("\n❌ فشل في دمج التنبيه!")
