import sqlite3
import json
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "detection.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # 1. جدول التنبيهات المطابق للعقد
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip TEXT NOT NULL,
                count INTEGER NOT NULL,
                description TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)
        
        # 2. جدول لتتبع آخر ID تم سحبه من شخص 2
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                last_processed_id INTEGER NOT NULL
            )
        """)
        
        # 3. جدول لتاريخ دخول المستخدمين والدول (لقاعدة new_country)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_country_history (
                user_id TEXT NOT NULL,
                country TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                PRIMARY KEY (user_id, country)
            )
        """)
        conn.commit()

init_db()

def save_or_dedup_alert(raw_alert: dict, dedup_window_sec: int = 600) -> tuple[dict, bool]:
    """
    تقوم بحفظ التنبيه أو دمجه إذا كان لنفس الـ IP والقاعدة خلال 10 دقائق.
    ترجع (Alert_Dict, is_new: bool)
    """
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    with get_db() as conn:
        cursor = conn.cursor()

        # ابحث عن تنبيه مفتوح لنفس الـ IP والقاعدة
        cursor.execute("""
            SELECT * FROM alerts 
            WHERE ip = ? AND rule = ? AND status = 'open'
            ORDER BY updated_at DESC LIMIT 1
        """, (raw_alert["ip"], raw_alert["rule"]))
        
        row = cursor.fetchone()

        if row:
            # حساب الفرق الزمني
            last_updated = datetime.fromisoformat(row["updated_at"].replace("Z", "+00:00"))
            diff_sec = (now_utc - last_updated).total_seconds()

            if diff_sec <= dedup_window_sec:
                # --- حالة الدمج (Deduplication) ---
                new_count = row["count"] + raw_alert.get("count", 1)
                
                # دمج أرقام الأحداث بدون تكرار
                existing_evs = json.loads(row["event_ids"])
                merged_evs = list(set(existing_evs + raw_alert.get("event_ids", [])))

                new_desc = f"{new_count} occurrences of {raw_alert['rule']} detected"

                cursor.execute("""
                    UPDATE alerts 
                    SET count = ?, event_ids = ?, description = ?, updated_at = ?
                    WHERE id = ?
                """, (new_count, json.dumps(merged_evs), new_desc, now_iso, row["id"]))
                conn.commit()

                # استرجاع السجل المحدث
                cursor.execute("SELECT * FROM alerts WHERE id = ?", (row["id"],))
                updated = dict(cursor.fetchone())
                updated["event_ids"] = json.loads(updated["event_ids"])
                return updated, False

        # --- حالة تنبيه جديد كلياً ---
        initial_created = raw_alert.get("created_at") or now_iso
        cursor.execute("""
            INSERT INTO alerts (created_at, updated_at, rule, severity, ip, count, description, event_ids, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')
        """, (
            initial_created,
            now_iso,
            raw_alert["rule"],
            raw_alert["severity"],
            raw_alert["ip"],
            raw_alert.get("count", 1),
            raw_alert["description"],
            json.dumps(raw_alert.get("event_ids", []))
        ))
        conn.commit()
        alert_id = cursor.lastrowid

        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        new_row = dict(cursor.fetchone())
        new_row["event_ids"] = json.loads(new_row["event_ids"])
        return new_row, True
