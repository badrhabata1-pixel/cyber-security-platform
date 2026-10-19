import json
import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware

from p3_detection.auth import verify_token
from p3_detection.config import settings
from p3_detection.database import get_db, save_or_dedup_alert
from p3_detection.engine import load_rules_config
from p3_detection.models import AlertContract, AlertStatusUpdate
from p3_detection.clients.logs_client import start_polling_worker

app = FastAPI(
    title="P3 - Intrusion Detection & Smart Alerts",
    version="1.0.0",
    docs_url="/docs"
)

# السماح للاتصال من الـ Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- إدارة اتصالات الـ WebSocket للبث اللحظي ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                pass

manager = ConnectionManager()
worker_task = None

# تشغيل الـ Worker في الخلفية بطريقة متوافقة 100%
@app.on_event("startup")
async def startup_event():
    global worker_task
    worker_task = asyncio.create_task(start_polling_worker(manager.broadcast))

@app.on_event("shutdown")
async def shutdown_event():
    global worker_task
    if worker_task:
        worker_task.cancel()

# --- 1. فحص صحة الخدمة Health Check ---
@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok"}

# --- 2. جلب القواعد المفعلة ---
@app.get("/rules", tags=["Rules"])
def get_rules(user: dict = Depends(verify_token)):
    return {"rules": load_rules_config()}

# --- 3. جلب التنبيهات مع فلاتر (لشخص 5 والـ UI) ---
@app.get("/alerts", response_model=List[AlertContract], tags=["Alerts"])
def get_alerts(
    status: Optional[str] = Query(None, description="open, acknowledged, resolved"),
    severity: Optional[str] = Query(None, description="low, medium, high, critical"),
    from_date: Optional[str] = Query(None, alias="from", description="ISO 8601 UTC"),
    to_date: Optional[str] = Query(None, alias="to", description="ISO 8601 UTC"),
    user: dict = Depends(verify_token)
):
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if from_date:
        query += " AND created_at >= ?"
        params.append(from_date)
    if to_date:
        query += " AND created_at <= ?"
        params.append(to_date)

    query += " ORDER BY created_at DESC"

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        result = []
        for r in rows:
            d = dict(r)
            d["event_ids"] = json.loads(d["event_ids"])
            result.append(d)
        return result

# --- 4. تحديث حالة التنبيه ---
@app.patch("/alerts/{alert_id}", response_model=AlertContract, tags=["Alerts"])
def update_alert_status(
    alert_id: int, 
    update: AlertStatusUpdate, 
    user: dict = Depends(verify_token)
):
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        cursor.execute("""
            UPDATE alerts 
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, (update.status.value, now_iso, alert_id))
        conn.commit()

        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        updated = dict(cursor.fetchone())
        updated["event_ids"] = json.loads(updated["event_ids"])
        return updated

# --- 5. ملخص وإحصائيات التنبيهات (لشخص 5) ---
@app.get("/alerts/summary", tags=["Alerts"])
def get_alerts_summary(user: dict = Depends(verify_token)):
    with get_db() as conn:
        cursor = conn.cursor()
        
        # حسب درجة الخطورة
        cursor.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
        by_severity = {r["severity"]: r["cnt"] for r in cursor.fetchall()}

        # حسب القاعدة
        cursor.execute("SELECT rule, COUNT(*) as cnt FROM alerts GROUP BY rule")
        by_rule = {r["rule"]: r["cnt"] for r in cursor.fetchall()}

        # حسب الحالة
        cursor.execute("SELECT status, COUNT(*) as cnt FROM alerts GROUP BY status")
        by_status = {r["status"]: r["cnt"] for r in cursor.fetchall()}

        cursor.execute("SELECT COUNT(*) as total FROM alerts")
        total = cursor.fetchone()["total"]

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_rule": by_rule,
            "by_status": by_status
        }

# --- 6. قناة البث اللحظي عبر WebSocket ---
@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
