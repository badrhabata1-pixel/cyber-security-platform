import asyncio
import json
import os
import httpx
from datetime import datetime, timezone

from p3_detection.config import settings
from p3_detection.database import get_db, save_or_dedup_alert
from p3_detection.engine import DetectionEngine

engine = DetectionEngine()

def get_last_processed_id() -> int:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT last_processed_id FROM sync_state WHERE key = 'logs_sync'")
        row = cursor.fetchone()
        return row["last_processed_id"] if row else 0

def update_last_processed_id(last_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO sync_state (key, last_processed_id) VALUES ('logs_sync', ?)
            ON CONFLICT(key) DO UPDATE SET last_processed_id = excluded.last_processed_id
        """, (last_id,))
        conn.commit()

async def notify_platform_critical(alert: dict):
    """إرسال التنبيهات الـ critical إلى شخص 4 بأسلوب Fire-and-Forget"""
    if alert.get("severity") != "critical":
        return
    
    url = f"{settings.PLATFORM_SERVICE_URL}/history"
    payload = {
        "source": "p3_detection",
        "type": "security_alert",
        "severity": alert["severity"],
        "details": alert["description"],
        "timestamp": alert.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            await client.post(url, json=payload)
    except Exception:
        # Fire-and-forget: لو شخص 4 غير متاح لا نوقف خدمتنا
        pass

async def fetch_and_process_events(broadcast_func=None):
    """جلب الأحداث الجديدة إما من شخص 2 أو من المحاكي"""
    last_id = get_last_processed_id()
    new_events = []

    # 1. إذا كان وضع المحاكاة مفعلاً USE_MOCKS=True
    if settings.USE_MOCKS:
        mock_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mock_events.json")
        if os.path.exists(mock_file):
            try:
                with open(mock_file, "r", encoding="utf-8") as f:
                    all_mocks = json.load(f)
                    # نجلب فقط الأحداث التي لم نعالجها بعد
                    new_events = [e for e in all_mocks if e.get("id", 0) > last_id]
            except Exception as e:
                print(f"Error reading mocks: {e}")

    # 2. إذا كنا سنربط فعلياً مع خدمة شخص 2
    else:
        url = f"{settings.LOGS_SERVICE_URL}/events?since_id={last_id}"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    new_events = resp.json()
        except Exception:
            # Fallback: لو شخص 2 واقع، ننتظر الدورة القادمة بدون أي كراش
            return

    # 3. معالجة الأحداث المكتشفة وتطبيق القواعد
    if new_events:
        max_id = max(e["id"] for e in new_events)
        detected_alerts = engine.analyze(new_events)

        for raw_alert in detected_alerts:
            # حفظ مع الـ Deduplication
            saved_alert, is_new = save_or_dedup_alert(raw_alert)

            # إرسال لحظي للـ WebSocket إذا توفرت الدالة
            if broadcast_func:
                await broadcast_func({
                    "event": "alert_created" if is_new else "alert_updated",
                    "data": saved_alert
                })

            # إشعار شخص 4 إذا كان critical
            if saved_alert.get("severity") == "critical":
                await notify_platform_critical(saved_alert)

        # تحديث آخر ID تمت معالجته
        update_last_processed_id(max_id)

async def start_polling_worker(broadcast_func):
    """حلقة تكرارية تعمل كل 5 ثوانٍ في الخلفية"""
    while True:
        try:
            await fetch_and_process_events(broadcast_func)
        except Exception as e:
            print(f"[Polling Worker Error]: {e}")
        await asyncio.sleep(5)
