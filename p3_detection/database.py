import sqlite3
import json
from datetime import datetime, timezone

DB_PATH = "p3_detection/detection.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        
        # جدول التنبيهات الرئيسي
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
        
        # جدول تتبع حالة السحب (Checkpoint) لمعرفة آخر ID سحبناه من شخص 2
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                last_processed_id INTEGER NOT NULL
            )
        """)
        
        # جدول لتاريخ تسجيل دخول المستخدمين والدول (لقاعدة new_country)
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
