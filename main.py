"""
SecureView - Threat Intelligence Dashboard
Backend: FastAPI + WebSocket + REST API
Author: Portfolio Project for Palo Alto Networks ASE Role
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import asyncio
import json
import random
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
from contextlib import asynccontextmanager
import uvicorn

from models import (
    Alert, Endpoint, Vulnerability, LogEntry,
    ThreatStats, NetworkTraffic, ProtocolData,
    AlertAction, PatchRequest
)
from data_store import DataStore
from threat_engine import ThreatEngine


# ─── Lifespan ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: seed data & launch background threat simulator."""
    DataStore.seed()
    task = asyncio.create_task(threat_engine.simulate_loop())
    yield
    task.cancel()


# ─── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureView API",
    description="Threat Intelligence Dashboard API",
    version="2.4.1",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

threat_engine = ThreatEngine()


# ─── WebSocket Manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)


manager = ConnectionManager()


# ─── REST Endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"message": "SecureView API v2.4.1", "status": "online"}


@app.get("/api/stats", response_model=ThreatStats)
async def get_stats():
    """Live KPI statistics."""
    return DataStore.get_stats()


@app.get("/api/alerts", response_model=List[Alert])
async def get_alerts(limit: int = 20, severity: str = None):
    """Get active alerts, optionally filtered by severity."""
    alerts = DataStore.get_alerts()
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    return alerts[:limit]


@app.get("/api/alerts/{alert_id}", response_model=Alert)
async def get_alert(alert_id: str):
    """Get single alert details."""
    alert = DataStore.get_alert(alert_id)
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.post("/api/alerts/{alert_id}/action")
async def alert_action(alert_id: str, action: AlertAction):
    """Perform action on an alert: resolve, block, escalate."""
    result = DataStore.update_alert_status(alert_id, action.action)
    # Broadcast update to all WS clients
    await manager.broadcast({
        "type": "alert_update",
        "alert_id": alert_id,
        "action": action.action,
        "timestamp": datetime.utcnow().isoformat()
    })
    return {"success": True, "alert_id": alert_id, "action": action.action, "result": result}


@app.get("/api/endpoints", response_model=List[Endpoint])
async def get_endpoints():
    """XDR endpoint health status."""
    return DataStore.get_endpoints()


@app.get("/api/vulnerabilities", response_model=List[Vulnerability])
async def get_vulnerabilities(status: str = None):
    """CVE vulnerability list."""
    vulns = DataStore.get_vulnerabilities()
    if status:
        vulns = [v for v in vulns if v.status == status]
    return vulns


@app.post("/api/vulnerabilities/{cve_id}/patch")
async def patch_vulnerability(cve_id: str, req: PatchRequest):
    """Trigger automated patch workflow for a CVE."""
    result = DataStore.patch_vulnerability(cve_id)
    await manager.broadcast({
        "type": "patch_initiated",
        "cve_id": cve_id,
        "playbook": "cortex-xsoar-patch-v2",
        "timestamp": datetime.utcnow().isoformat()
    })
    return {
        "success": True,
        "cve_id": cve_id,
        "playbook": "cortex-xsoar-patch-v2",
        "eta_minutes": random.randint(5, 20),
        "message": f"Patch workflow initiated for {cve_id}"
    }


@app.get("/api/traffic", response_model=List[NetworkTraffic])
async def get_traffic():
    """Network traffic data for last 24 hours."""
    return DataStore.get_traffic_data()


@app.get("/api/protocols", response_model=List[ProtocolData])
async def get_protocols():
    """Protocol breakdown (SASE analysis)."""
    return DataStore.get_protocol_data()


@app.get("/api/logs", response_model=List[LogEntry])
async def get_logs(limit: int = 50):
    """Recent firewall/IDS event logs."""
    return DataStore.get_logs(limit)


@app.get("/api/geo-threats")
async def get_geo_threats():
    """Geographic threat origin data for map visualization."""
    return DataStore.get_geo_threats()


# ─── WebSocket: Live Feed ─────────────────────────────────────────────────────
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat feed.
    Pushes: new alerts, log entries, KPI updates every ~2 seconds.
    """
    await manager.connect(websocket)
    try:
        # Send initial state snapshot
        await websocket.send_json({
            "type": "snapshot",
            "stats": DataStore.get_stats().model_dump(),
            "alerts": [a.model_dump() for a in DataStore.get_alerts()[:5]],
        })

        while True:
            # Wait for either client message or timeout
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=2.0)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                pass

            # Push live event
            event = threat_engine.generate_event()
            if event:
                await websocket.send_json(event)

    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─── Background Threat Simulator ─────────────────────────────────────────────
# (Runs in ThreatEngine, broadcasts via manager)
async def broadcast_loop():
    while True:
        await asyncio.sleep(3)
        event = threat_engine.generate_event()
        if event:
            await manager.broadcast(event)


# ─── Entry Point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
