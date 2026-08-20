from __future__ import annotations
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .mission import ROOT, run_mission
from .models import MissionRequest, MissionResult

app = FastAPI(title="Sentinel Swarm", version="0.1.0")
STATIC = ROOT / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")

@app.get("/api/status")
def status():
    return {
        "name": "Sentinel Swarm",
        "version": "0.1.0",
        "mode": "local-safe-demo",
        "agents": ["RECON","EXPLOIT-ANALYSIS","THREAT-MODEL","SECURE-CODING","REPORT-WRITER"],
        "truth": {"network_scan": False, "shell": False, "fixture_analysis": True, "remediation": True, "verification": True},
    }

@app.post("/api/missions", response_model=MissionResult)
def mission(req: MissionRequest):
    return run_mission(req.task)

@app.websocket("/ws/mission")
async def mission_ws(ws: WebSocket):
    await ws.accept()
    try:
        payload = await ws.receive_json()
        result = run_mission(str(payload.get("task") or "Audit the built-in SSH misconfiguration demo"))
        for event in result.events:
            await ws.send_json({"type":"event", "mission_id": result.mission_id, "event": event.model_dump()})
            await asyncio.sleep(0.25)
        await ws.send_json({"type":"complete", "mission_id":result.mission_id,"report_path":result.report_path})
    except WebSocketDisconnect:
        return
