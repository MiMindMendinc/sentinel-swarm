from __future__ import annotations

import asyncio

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from .mission import ROOT, run_mission
from .models import MissionRequest, MissionResult

app = FastAPI(
    title="Sentinel Swarm",
    version="0.1.0",
    description="Evidence-first local multi-agent cybersecurity lab.",
)
STATIC = ROOT / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get("/api/status", tags=["system"])
def status() -> dict[str, object]:
    return {
        "name": "Sentinel Swarm",
        "version": app.version,
        "mode": "local-safe-demo",
        "agents": [
            "RECON",
            "EXPLOIT-ANALYSIS",
            "THREAT-MODEL",
            "SECURE-CODING",
            "REPORT-WRITER",
        ],
        "truth": {
            "network_scan": False,
            "shell": False,
            "fixture_analysis": True,
            "remediation": True,
            "verification": True,
        },
    }


@app.post("/api/missions", response_model=MissionResult, tags=["missions"])
def mission(req: MissionRequest) -> MissionResult:
    return run_mission(req.task)


@app.websocket("/ws/mission")
async def mission_ws(ws: WebSocket) -> None:
    await ws.accept()
    try:
        payload = await ws.receive_json()
        request = MissionRequest(task=str(payload.get("task") or "Audit the built-in SSH misconfiguration demo"))
        result = run_mission(request.task)
        for event in result.events:
            await ws.send_json(
                {
                    "type": "event",
                    "mission_id": result.mission_id,
                    "event": event.model_dump(),
                }
            )
            await asyncio.sleep(0.20)
        await ws.send_json(
            {
                "type": "complete",
                "mission_id": result.mission_id,
                "report_path": result.report_path,
            }
        )
    except ValidationError as exc:
        await ws.send_json({"type": "error", "message": "Invalid mission request", "details": exc.errors()})
        await ws.close(code=1008)
    except WebSocketDisconnect:
        return
    except Exception:
        await ws.send_json({"type": "error", "message": "Mission failed safely. Check server logs."})
        await ws.close(code=1011)
