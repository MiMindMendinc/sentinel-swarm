import hashlib

from fastapi.testclient import TestClient

from app.main import app
from app.mission import RANGE, ROOT, run_mission

FIXTURE_SHA256_BEFORE = "846a4fa9f53987da218fbda4e242eb07cdbf154c0ff1f027d94cd1fda554fdfa"
FIXTURE_SHA256_AFTER = "a144438e493b12fa3c265a4fa87bd762de2d51dfdc1333ccf0dfa376105bba46"

client = TestClient(app)


def test_health_and_status_truthful():
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    response = client.get("/api/status")
    assert response.status_code == 200
    truth = response.json()["truth"]
    assert truth["fixture_analysis"] is True
    assert truth["network_scan"] is False
    assert truth["shell"] is False


def test_mission_real_patch_report_and_ledger():
    out = run_mission("test fixture")
    assert out.status == "completed"
    assert [event.agent for event in out.events] == [
        "RECON",
        "EXPLOIT-ANALYSIS",
        "THREAT-MODEL",
        "SECURE-CODING",
        "RECON",
        "REPORT-WRITER",
    ]

    report = ROOT / out.report_path
    target = report.parent / "sshd_config"
    ledger = report.parent / "events.jsonl"
    assert report.exists() and target.exists() and ledger.exists()

    text = target.read_text(encoding="utf-8")
    assert "PermitRootLogin no" in text
    assert "PasswordAuthentication no" in text
    assert "PermitRootLogin yes" not in text
    assert hashlib.sha256(RANGE.read_bytes()).hexdigest() == FIXTURE_SHA256_BEFORE
    assert hashlib.sha256(target.read_bytes()).hexdigest() == FIXTURE_SHA256_AFTER
    assert len(ledger.read_text(encoding="utf-8").splitlines()) == 6
    assert FIXTURE_SHA256_BEFORE in report.read_text(encoding="utf-8")
    assert FIXTURE_SHA256_AFTER in report.read_text(encoding="utf-8")


def test_http_validation_rejects_empty_task():
    response = client.post("/api/missions", json={"task": ""})
    assert response.status_code == 422


def test_websocket_streams_real_mission():
    with client.websocket_connect("/ws/mission") as ws:
        ws.send_json({"task": "websocket test"})
        events = []
        while True:
            message = ws.receive_json()
            if message["type"] == "event":
                events.append(message["event"])
            elif message["type"] == "complete":
                assert message["report_path"].endswith("/report.md")
                break
        assert len(events) == 6
        assert events[-1]["agent"] == "REPORT-WRITER"


def test_websocket_rejects_oversized_task():
    with client.websocket_connect("/ws/mission") as ws:
        ws.send_json({"task": "x" * 501})
        message = ws.receive_json()
        assert message["type"] == "error"
