from __future__ import annotations

import asyncio
import json
import logging

from fastapi import FastAPI, HTTPException, Path, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .mission import (
    MISSION_WAIT_SECONDS,
    ROOT,
    MissionBusyError,
    MissionCapacityError,
    MissionIntegrityError,
    mission_capacity,
    mission_exists,
    run_mission,
    verify_mission,
)
from .models import MissionRequest, MissionResult, VerificationResult
from .security import (
    ALLOWED_HOSTS,
    MAX_HTTP_BODY_BYTES,
    MAX_WS_MESSAGE_BYTES,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW_SECONDS,
    BoundedMissionBodyMiddleware,
    SecurityHeadersMiddleware,
    client_key,
    mission_rate_limiter,
    strict_json_loads,
    websocket_origin_allowed,
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sentinel Swarm",
    version=__version__,
    description="Evidence-first local multi-agent cybersecurity lab.",
    docs_url=None,
    redoc_url=None,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(ALLOWED_HOSTS))
app.add_middleware(BoundedMissionBodyMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

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
        "scenario": {
            "id": "ssh-misconfig",
            "execution": "fixed-built-in-only",
            "task_semantics": "operator-note-only",
        },
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
            "remote_targets": False,
            "fixture_analysis": True,
            "remediation": True,
            "post_change_verification": True,
            "tamper_evident_ledger": True,
            "cryptographic_signature": False,
        },
        "storage": mission_capacity(),
        "limits": {
            "http_body_bytes": MAX_HTTP_BODY_BYTES,
            "websocket_message_bytes": MAX_WS_MESSAGE_BYTES,
            "requests_per_window": RATE_LIMIT_REQUESTS,
            "rate_window_seconds": RATE_LIMIT_WINDOW_SECONDS,
        },
    }


@app.post("/api/missions", response_model=MissionResult, tags=["missions"])
def mission(req: MissionRequest, request: Request) -> MissionResult | JSONResponse:
    if not mission_rate_limiter.allow(client_key(request.scope)):
        return JSONResponse(
            {"detail": "Mission rate limit exceeded"},
            status_code=429,
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )
    try:
        return run_mission(req)
    except MissionBusyError as exc:
        return JSONResponse(
            {"detail": str(exc)},
            status_code=503,
            headers={"Retry-After": str(max(1, MISSION_WAIT_SECONDS))},
        )
    except MissionCapacityError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=507)
    except MissionIntegrityError:
        logger.exception("Mission failed its integrity check")
        return JSONResponse(
            {"detail": "Mission failed its integrity check; no result was returned."},
            status_code=500,
        )


@app.get(
    "/api/missions/{mission_id}/verify",
    response_model=VerificationResult,
    tags=["missions"],
)
def verify(
    mission_id: str = Path(pattern=r"^[a-f0-9]{32}$"),
) -> VerificationResult:
    if not mission_exists(mission_id):
        raise HTTPException(status_code=404, detail="Mission workspace not found")
    return verify_mission(mission_id)


async def _receive_mission_request(ws: WebSocket) -> MissionRequest:
    message = await ws.receive()
    if message["type"] == "websocket.disconnect":
        raise WebSocketDisconnect(code=message.get("code", 1000))

    if message.get("text") is not None:
        raw_bytes = message["text"].encode("utf-8")
    elif message.get("bytes") is not None:
        raw_bytes = message["bytes"]
    else:
        raise ValueError("WebSocket mission request must contain JSON text")

    if len(raw_bytes) > MAX_WS_MESSAGE_BYTES:
        raise OverflowError("WebSocket mission request is too large")
    try:
        payload = strict_json_loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("WebSocket mission request must be valid UTF-8 JSON") from exc
    return MissionRequest.model_validate(payload)


@app.websocket("/ws/mission")
async def mission_ws(ws: WebSocket) -> None:
    if not websocket_origin_allowed(ws.scope):
        await ws.close(code=1008, reason="WebSocket origin is not allowed")
        return
    if not mission_rate_limiter.allow(client_key(ws.scope)):
        await ws.close(code=1013, reason="Mission rate limit exceeded")
        return

    await ws.accept()
    try:
        request = await _receive_mission_request(ws)
        result = await asyncio.to_thread(run_mission, request)
        for event in result.events:
            await ws.send_json(
                {
                    "type": "event",
                    "mission_id": result.mission_id,
                    "event": event.model_dump(mode="json"),
                }
            )
            await asyncio.sleep(0.05)
        await ws.send_json(
            {
                "type": "complete",
                "mission_id": result.mission_id,
                "scenario_id": result.scenario_id,
                "report_path": result.report_path,
                "manifest_path": result.manifest_path,
                "manifest_sha256": result.manifest_sha256,
                "ledger_head_sha256": result.ledger_head_sha256,
                "verified": result.verification.valid,
            }
        )
    except OverflowError as exc:
        await ws.send_json({"type": "error", "message": str(exc)})
        await ws.close(code=1009)
    except (ValidationError, ValueError) as exc:
        details = (
            exc.errors(include_input=False, include_context=False)
            if isinstance(exc, ValidationError)
            else []
        )
        await ws.send_json(
            {"type": "error", "message": "Invalid mission request", "details": details}
        )
        await ws.close(code=1008)
    except MissionBusyError as exc:
        await ws.send_json({"type": "error", "message": str(exc)})
        await ws.close(code=1013)
    except MissionCapacityError as exc:
        await ws.send_json({"type": "error", "message": str(exc)})
        await ws.close(code=1013)
    except MissionIntegrityError:
        logger.exception("WebSocket mission failed its integrity check")
        await ws.send_json(
            {"type": "error", "message": "Mission failed its integrity check safely."}
        )
        await ws.close(code=1011)
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001
        logger.exception("Unexpected WebSocket mission failure")
        await ws.send_json({"type": "error", "message": "Mission failed safely."})
        await ws.close(code=1011)
