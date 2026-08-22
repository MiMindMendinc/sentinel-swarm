from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.main as main_module
import app.mission as mission_module
import app.security as security_module
from app.main import app
from app.mission import (
    RANGE,
    ZERO_HASH,
    MissionBusyError,
    MissionCapacityError,
    MissionIntegrityError,
    run_mission,
    verify_mission,
)
from app.security import (
    BoundedMissionBodyMiddleware,
    FixedWindowRateLimiter,
    client_key,
    mission_rate_limiter,
    websocket_origin_allowed,
)

FIXTURE_SHA256_BEFORE = "846a4fa9f53987da218fbda4e242eb07cdbf154c0ff1f027d94cd1fda554fdfa"
FIXTURE_SHA256_AFTER = "a144438e493b12fa3c265a4fa87bd762de2d51dfdc1333ccf0dfa376105bba46"

client = TestClient(app)


@pytest.fixture(autouse=True)
def isolated_mission_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data = (tmp_path / "mission-data").resolve()
    monkeypatch.setattr(mission_module, "DATA", data)
    mission_rate_limiter.reset()
    yield data
    if data.exists():
        for path in sorted(data.rglob("*"), reverse=True):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
        os.chmod(data, 0o700)


def workspace_for(result) -> Path:
    return mission_module.DATA / result.mission_id


def test_health_status_and_openapi_are_truthful_and_hardened():
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "version": "0.1.1"}

    response = client.get("/api/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["scenario"] == {
        "id": "ssh-misconfig",
        "execution": "fixed-built-in-only",
        "task_semantics": "operator-note-only",
    }
    assert payload["truth"]["fixture_analysis"] is True
    assert payload["truth"]["tamper_evident_ledger"] is True
    assert payload["truth"]["cryptographic_signature"] is False
    assert payload["truth"]["network_scan"] is False
    assert payload["truth"]["shell"] is False
    assert payload["storage"] == {"used": 0, "maximum": 500, "remaining": 500}

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 200


def test_security_headers_and_host_boundary_apply_to_success_and_errors():
    for path in ("/", "/api/status", "/not-found"):
        response = client.get(path)
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cross-origin-opener-policy"] == "same-origin"
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert "'unsafe-inline'" not in response.headers["content-security-policy"]

    hostile = client.get("/api/health", headers={"host": "evil.example"})
    assert hostile.status_code == 400
    assert hostile.headers["x-frame-options"] == "DENY"


def test_mission_preserves_before_and_writes_verified_read_only_artifacts():
    result = run_mission('regression test <img src=x onerror="alert(1)"> & evidence')
    workspace = workspace_for(result)
    before = workspace / "before" / "sshd_config"
    after = workspace / "after" / "sshd_config"
    report = workspace / "report.md"
    ledger = workspace / "events.jsonl"
    manifest = workspace / "manifest.json"
    anchor = workspace / "manifest.sha256"

    assert result.status == "completed"
    assert result.scenario_id == "ssh-misconfig"
    assert result.verification.valid is True
    assert [event.agent for event in result.events] == [
        "RECON",
        "EXPLOIT-ANALYSIS",
        "THREAT-MODEL",
        "SECURE-CODING",
        "RECON",
        "REPORT-WRITER",
    ]
    assert all(path.is_file() for path in (before, after, report, ledger, manifest, anchor))

    assert hashlib.sha256(RANGE.read_bytes()).hexdigest() == FIXTURE_SHA256_BEFORE
    assert hashlib.sha256(before.read_bytes()).hexdigest() == FIXTURE_SHA256_BEFORE
    assert hashlib.sha256(after.read_bytes()).hexdigest() == FIXTURE_SHA256_AFTER
    assert result.events[0].evidence.sha256 == hashlib.sha256(before.read_bytes()).hexdigest()
    assert result.events[3].evidence.sha256 == hashlib.sha256(after.read_bytes()).hexdigest()
    assert "PermitRootLogin yes" in before.read_text(encoding="utf-8")
    assert "PermitRootLogin no" in after.read_text(encoding="utf-8")
    assert "PermitRootLogin yes" not in after.read_text(encoding="utf-8")
    assert FIXTURE_SHA256_BEFORE in report.read_text(encoding="utf-8")
    assert FIXTURE_SHA256_AFTER in report.read_text(encoding="utf-8")
    assert "<img" not in report.read_text(encoding="utf-8")
    assert r"\u003cimg" in report.read_text(encoding="utf-8")

    assert anchor.read_text(encoding="utf-8").split()[0] == result.manifest_sha256
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == result.manifest_sha256
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o500
    assert stat.S_IMODE((workspace / "before").stat().st_mode) == 0o500
    assert stat.S_IMODE((workspace / "after").stat().st_mode) == 0o500
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in (before, after, report, ledger, manifest, anchor))


def test_ledger_is_hash_chained_and_manifested():
    result = run_mission("ledger chain test")
    workspace = workspace_for(result)
    previous = ZERO_HASH
    lines = (workspace / "events.jsonl").read_text(encoding="utf-8").splitlines()

    assert len(lines) == 6
    for sequence, line in enumerate(lines, start=1):
        record = json.loads(line)
        recorded_hash = record.pop("entry_sha256")
        assert record["seq"] == sequence
        assert record["previous_sha256"] == previous
        canonical = json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        assert hashlib.sha256(canonical.encode()).hexdigest() == recorded_hash
        previous = recorded_hash

    manifest = json.loads((workspace / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["ledger_head_sha256"] == previous == result.ledger_head_sha256
    assert manifest["event_count"] == 6
    assert {item["path"] for item in manifest["artifacts"]} == {
        "before/sshd_config",
        "after/sshd_config",
        "report.md",
        "events.jsonl",
    }


@pytest.mark.parametrize(
    ("relative_path", "replacement", "expected_error"),
    [
        ("events.jsonl", "Root SSH login", "ledger"),
        ("before/sshd_config", "PermitRootLogin yes", "Evidence hash mismatch"),
    ],
)
def test_verifier_detects_artifact_tampering(relative_path, replacement, expected_error):
    result = run_mission("tamper test")
    workspace = workspace_for(result)
    target = workspace / relative_path
    os.chmod(workspace, 0o700)
    os.chmod(target, 0o600)
    original = target.read_text(encoding="utf-8")
    target.write_text(original.replace(replacement, replacement + " TAMPERED", 1), encoding="utf-8")

    verification = verify_mission(result.mission_id)
    assert verification.valid is False
    assert any(expected_error.lower() in error.lower() for error in verification.errors)


def test_verifier_rejects_manifest_path_escape_even_with_reanchored_manifest():
    result = run_mission("path traversal test")
    workspace = workspace_for(result)
    manifest = workspace / "manifest.json"
    anchor = workspace / "manifest.sha256"
    os.chmod(workspace, 0o700)
    os.chmod(manifest, 0o600)
    os.chmod(anchor, 0o600)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["artifacts"][0]["path"] = "../../etc/passwd"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    anchor.write_text(f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  manifest.json\n")

    verification = verify_mission(result.mission_id)
    assert verification.valid is False
    assert any("escapes mission workspace" in error for error in verification.errors)


def test_verifier_rejects_invalid_missing_and_malformed_manifests():
    invalid = verify_mission("../escape")
    missing = verify_mission("0" * 32)
    assert invalid.valid is False and invalid.errors == ["Invalid mission identifier"]
    assert missing.valid is False and missing.errors == ["Mission workspace does not exist"]

    result = run_mission("malformed manifest test")
    workspace = workspace_for(result)
    manifest = workspace / "manifest.json"
    os.chmod(workspace, 0o700)
    os.chmod(manifest, 0o600)
    manifest.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
    verification = verify_mission(result.mission_id)
    assert verification.valid is False
    assert any("duplicate JSON key" in error for error in verification.errors)


@pytest.mark.parametrize(
    "payload",
    [
        {"task": ""},
        {"task": " \r\n\t "},
        {"task": 7},
        {"task": ["not", "a", "string"]},
        {"task": "ok", "unexpected": True},
        {"scenario_id": "arbitrary-target", "task": "scan it"},
    ],
)
def test_http_mission_validation_is_strict(payload):
    response = client.post("/api/missions", json=payload)
    assert response.status_code == 422


def test_http_body_limit_runs_before_json_parsing():
    body = b'{"task":"' + (b"x" * 5000) + b'"}'
    response = client.post("/api/missions", content=body, headers={"content-type": "application/json"})
    assert response.status_code == 413
    assert response.json()["detail"] == "Mission request body is too large"

    duplicate = client.post(
        "/api/missions",
        content=b'{"task":"first","task":"second"}',
        headers={"content-type": "application/json"},
    )
    assert duplicate.status_code == 400
    assert "duplicate keys" in duplicate.json()["detail"]

    nonstandard = client.post(
        "/api/missions",
        content=b'{"task":NaN}',
        headers={"content-type": "application/json"},
    )
    assert nonstandard.status_code == 400


def test_http_mission_and_verifier_endpoint_keep_operator_note_non_executable():
    note = "scan 10.0.0.0/8 && curl https://example.invalid"
    response = client.post("/api/missions", json={"task": note})
    assert response.status_code == 200
    payload = response.json()
    assert payload["scenario_id"] == "ssh-misconfig"
    assert payload["verification"]["valid"] is True
    assert "built-in ssh-misconfig scenario" in payload["events"][0]["message"]
    assert "Operator note:" in payload["events"][0]["message"]

    verified = client.get(f"/api/missions/{payload['mission_id']}/verify")
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert client.get(f"/api/missions/{'f' * 32}/verify").status_code == 404


def test_http_rate_limit_is_bounded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(mission_rate_limiter, "limit", 1)
    first = client.post("/api/missions", json={"task": "first"})
    second = client.post("/api/missions", json={"task": "second"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == "60"


@pytest.mark.parametrize(
    ("failure", "status_code"),
    [
        (MissionBusyError("workers busy"), 503),
        (MissionCapacityError("storage full"), 507),
        (MissionIntegrityError("integrity failed"), 500),
    ],
)
def test_http_mission_failures_return_safe_statuses(monkeypatch, failure, status_code):
    def fail_safely(_request):
        raise failure

    monkeypatch.setattr(main_module, "run_mission", fail_safely)
    response = client.post("/api/missions", json={"task": "safe failure test"})
    assert response.status_code == status_code
    assert "traceback" not in response.text.lower()


def test_websocket_streams_verified_mission():
    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_json({"scenario_id": "ssh-misconfig", "task": "websocket test"})
        events = []
        while True:
            message = websocket.receive_json()
            if message["type"] == "event":
                events.append(message["event"])
            elif message["type"] == "complete":
                assert message["scenario_id"] == "ssh-misconfig"
                assert message["report_path"].endswith("/report.md")
                assert len(message["manifest_sha256"]) == 64
                assert len(message["ledger_head_sha256"]) == 64
                assert message["verified"] is True
                break
        assert len(events) == 6
        assert events[-1]["agent"] == "REPORT-WRITER"


@pytest.mark.parametrize(
    "payload",
    [
        {"task": " "},
        {"task": 3},
        {"task": {"nested": "value"}},
        {"task": "valid", "extra": "rejected"},
        {"scenario_id": "unknown", "task": "valid"},
    ],
)
def test_websocket_validation_matches_http(payload):
    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_json(payload)
        message = websocket.receive_json()
        assert message["type"] == "error"
        assert message["message"] == "Invalid mission request"


def test_websocket_rejects_malformed_and_oversized_messages():
    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_text("{")
        assert websocket.receive_json()["type"] == "error"

    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_json({"task": "x" * 5000})
        message = websocket.receive_json()
        assert message == {"type": "error", "message": "WebSocket mission request is too large"}

    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_text('{"task":"first","task":"second"}')
        assert websocket.receive_json()["type"] == "error"

    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_text('{"task":NaN}')
        assert websocket.receive_json()["type"] == "error"


def test_websocket_rejects_cross_origin_before_creating_a_mission():
    with pytest.raises(WebSocketDisconnect) as disconnected:
        with client.websocket_connect(
            "/ws/mission", headers={"origin": "https://evil.example"}
        ):
            pass
    assert disconnected.value.code == 1008
    assert not mission_module.DATA.exists()


def test_websocket_accepts_binary_json_and_rejects_rate_excess(monkeypatch):
    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_bytes(json.dumps({"task": "binary JSON"}).encode())
        while websocket.receive_json()["type"] != "complete":
            pass

    mission_rate_limiter.reset()
    monkeypatch.setattr(mission_rate_limiter, "limit", 0)
    with pytest.raises(WebSocketDisconnect) as disconnected:
        with client.websocket_connect("/ws/mission"):
            pass
    assert disconnected.value.code == 1013


@pytest.mark.parametrize(
    ("failure", "close_code"),
    [
        (MissionBusyError("workers busy"), 1013),
        (MissionCapacityError("storage full"), 1013),
        (MissionIntegrityError("integrity failed"), 1011),
        (RuntimeError("unexpected"), 1011),
    ],
)
def test_websocket_mission_failures_close_safely(monkeypatch, failure, close_code):
    def fail_safely(_request):
        raise failure

    monkeypatch.setattr(main_module, "run_mission", fail_safely)
    with client.websocket_connect("/ws/mission") as websocket:
        websocket.send_json({"task": "safe failure"})
        message = websocket.receive_json()
        assert message["type"] == "error"
        with pytest.raises(WebSocketDisconnect) as disconnected:
            websocket.receive_json()
        assert disconnected.value.code == close_code


def test_capacity_is_bounded_without_deleting_evidence(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(mission_module, "MAX_MISSIONS", 1)
    first = run_mission("retained")
    with pytest.raises(MissionCapacityError):
        run_mission("must not delete first")
    assert workspace_for(first).is_dir()
    assert verify_mission(first.mission_id).valid is True


def test_concurrent_missions_get_unique_verified_workspaces():
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda number: run_mission(f"concurrent {number}"), range(20)))
    assert len({result.mission_id for result in results}) == 20
    assert all(result.verification.valid for result in results)


def test_rate_limiter_reset_clears_fixed_window():
    limiter = FixedWindowRateLimiter(limit=2, window_seconds=60)
    assert limiter.allow("client") is True
    assert limiter.allow("client") is True
    assert limiter.allow("client") is False
    limiter.reset()
    assert limiter.allow("client") is True


def test_security_helpers_cover_environment_origin_and_unknown_client(monkeypatch):
    monkeypatch.setenv("TEST_SENTINEL_INT", "not-an-integer")
    with pytest.raises(RuntimeError, match="must be an integer"):
        security_module._env_int("TEST_SENTINEL_INT", 1, 1, 2)
    monkeypatch.setenv("TEST_SENTINEL_INT", "3")
    with pytest.raises(RuntimeError, match="between 1 and 2"):
        security_module._env_int("TEST_SENTINEL_INT", 1, 1, 2)

    assert client_key({"type": "http"}) == "mission:unknown"
    assert websocket_origin_allowed(
        {"headers": [(b"host", b"testserver"), (b"origin", b"http://testserver")]}
    )
    assert websocket_origin_allowed(
        {"headers": [(b"host", b"localhost:7777"), (b"origin", b"http://localhost:7777")]}
    )
    assert not websocket_origin_allowed(
        {"headers": [(b"host", b"testserver"), (b"origin", b"http://[")]}
    )


def test_bounded_body_middleware_handles_bad_length_stream_overflow_and_disconnect():
    base_scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/missions",
        "raw_path": b"/api/missions",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("client", 1234),
    }

    async def invoke(headers, inbound, maximum=5):
        sent = []
        inbound_messages = iter(inbound)

        async def receive():
            return next(inbound_messages)

        async def send(message):
            sent.append(message)

        async def downstream(_scope, downstream_receive, downstream_send):
            first = await downstream_receive()
            second = await downstream_receive()
            assert first["type"] == "http.request"
            assert second["type"] == "http.disconnect"
            await downstream_send(
                {"type": "http.response.start", "status": 204, "headers": []}
            )
            await downstream_send({"type": "http.response.body", "body": b""})

        middleware = BoundedMissionBodyMiddleware(downstream, maximum_bytes=maximum)
        scope = {**base_scope, "headers": headers}
        await middleware(scope, receive, send)
        return sent

    invalid_length = asyncio.run(
        invoke([(b"content-length", b"invalid")], [{"type": "http.request", "body": b""}])
    )
    assert invalid_length[0]["status"] == 400

    streamed_overflow = asyncio.run(
        invoke(
            [],
            [
                {"type": "http.request", "body": b"123", "more_body": True},
                {"type": "http.request", "body": b"456", "more_body": False},
            ],
        )
    )
    assert streamed_overflow[0]["status"] == 413

    disconnected = asyncio.run(invoke([], [{"type": "http.disconnect"}]))
    assert disconnected[0]["status"] == 400

    replayed = asyncio.run(
        invoke(
            [(b"content-length", b"2")],
            [{"type": "http.request", "body": b"{}", "more_body": False}],
        )
    )
    assert replayed[0]["status"] == 204


def test_verifier_reports_structural_manifest_and_ledger_failures():
    result = run_mission("structural tamper test")
    workspace = workspace_for(result)
    manifest = workspace / "manifest.json"
    anchor = workspace / "manifest.sha256"
    os.chmod(workspace, 0o700)
    os.chmod(manifest, 0o600)
    os.chmod(anchor, 0o600)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    first = payload["artifacts"][0]
    report_entry = next(item for item in payload["artifacts"] if item["path"] == "report.md")
    payload.update(
        {
            "schema_version": 99,
            "mission_id": "f" * 32,
            "scenario_id": "unknown",
            "operator_note": 7,
            "completed_at": "not-a-timestamp",
            "event_count": 99,
            "ledger_head_sha256": "0" * 64,
            "unexpected": True,
            "artifacts": [
                None,
                first,
                dict(first),
                {
                    **report_entry,
                    "role": "wrong-role",
                    "sha256": "bad",
                    "size": -1,
                    "unexpected": True,
                },
                {"path": "missing.txt", "sha256": "0" * 64, "size": 0},
            ],
        }
    )
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    anchor.write_text(f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  manifest.json\n")

    verification = verify_mission(result.mission_id)
    combined = "\n".join(verification.errors)
    assert verification.valid is False
    assert "Unsupported manifest schema" in combined
    assert "mission identifier" in combined
    assert "scenario identifier" in combined
    assert "operator note is invalid" in combined
    assert "completion time is invalid" in combined
    assert "Manifest schema mismatch" in combined
    assert "artifact entry must be an object" in combined
    assert "artifact schema mismatch" in combined
    assert "Duplicate manifest artifact" in combined
    assert "artifact role is invalid" in combined
    assert "unexpected artifact" in combined
    assert "invalid SHA-256" in combined
    assert "invalid size" in combined
    assert "artifact is missing" in combined
    assert "event count" in combined
    assert "ledger head" in combined


def test_verifier_handles_missing_anchor_empty_ledger_and_non_object_manifest():
    orphan_id = "a" * 32
    orphan = mission_module.DATA / orphan_id
    orphan.mkdir(parents=True)
    assert verify_mission(orphan_id).errors == ["Manifest or manifest anchor is missing"]

    result = run_mission("additional verifier failures")
    workspace = workspace_for(result)
    os.chmod(workspace, 0o700)
    ledger = workspace / "events.jsonl"
    os.chmod(ledger, 0o600)
    ledger.write_text("", encoding="utf-8")
    verification = verify_mission(result.mission_id)
    assert any("events.jsonl is empty" in error for error in verification.errors)

    record = {
        "schema_version": 2,
        **result.events[0].model_dump(mode="json"),
        "previous_sha256": ZERO_HASH,
    }
    canonical = json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    record["entry_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
    ledger.write_text(
        json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    verification = verify_mission(result.mission_id)
    assert any("unsupported schema version" in error for error in verification.errors)

    manifest = workspace / "manifest.json"
    anchor = workspace / "manifest.sha256"
    os.chmod(manifest, 0o600)
    os.chmod(anchor, 0o600)
    manifest.write_text("[]", encoding="utf-8")
    anchor.write_text(f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  manifest.json\n")
    verification = verify_mission(result.mission_id)
    assert any("manifest must be an object" in error for error in verification.errors)


def test_mission_worker_limit_fails_closed(monkeypatch):
    class NoSlots:
        def acquire(self, timeout):
            assert timeout == mission_module.MISSION_WAIT_SECONDS
            return False

    monkeypatch.setattr(mission_module, "_MISSION_SLOTS", NoSlots())
    with pytest.raises(MissionBusyError):
        run_mission("no worker slot")


def test_mission_configuration_and_safe_path_helpers_fail_closed(monkeypatch):
    monkeypatch.setenv("TEST_MISSION_INT", "invalid")
    with pytest.raises(RuntimeError, match="must be an integer"):
        mission_module._env_int("TEST_MISSION_INT", 1, 1, 2)
    monkeypatch.setenv("TEST_MISSION_INT", "3")
    with pytest.raises(RuntimeError, match="between 1 and 2"):
        mission_module._env_int("TEST_MISSION_INT", 1, 1, 2)

    result = run_mission("path helper test")
    workspace = workspace_for(result)
    os.chmod(workspace, 0o700)
    with pytest.raises(ValueError, match="non-empty string"):
        mission_module._safe_workspace_path(workspace, None)
    link = workspace / "report-link"
    link.symlink_to("report.md")
    with pytest.raises(ValueError, match="must not contain a symlink"):
        mission_module._safe_workspace_path(workspace, "report-link")
    with pytest.raises(ValueError, match="not canonical"):
        mission_module._safe_workspace_path(workspace, "before//sshd_config")


def test_verifier_rejects_empty_manifest_anchor():
    result = run_mission("empty anchor test")
    workspace = workspace_for(result)
    anchor = workspace / "manifest.sha256"
    os.chmod(workspace, 0o700)
    os.chmod(anchor, 0o600)
    anchor.write_text("", encoding="utf-8")
    verification = verify_mission(result.mission_id)
    assert verification.valid is False
    assert "Manifest anchor is malformed" in verification.errors


def test_verifier_rejects_symlinked_workspace_metadata_and_ledger(tmp_path):
    symlink_id = "b" * 32
    external = tmp_path / "external"
    external.mkdir()
    mission_module.DATA.mkdir()
    (mission_module.DATA / symlink_id).symlink_to(external, target_is_directory=True)
    assert verify_mission(symlink_id).errors == ["Mission workspace must not be a symlink"]

    result = run_mission("symlink metadata test")
    workspace = workspace_for(result)
    os.chmod(workspace, 0o700)
    anchor = workspace / "manifest.sha256"
    anchor.unlink()
    anchor.symlink_to("manifest.json")
    assert verify_mission(result.mission_id).errors == [
        "Manifest and manifest anchor must not be symlinks"
    ]

    anchor.unlink()
    manifest = workspace / "manifest.json"
    anchor.write_text(f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  manifest.json\n")
    ledger = workspace / "events.jsonl"
    ledger.unlink()
    ledger.symlink_to("report.md")
    verification = verify_mission(result.mission_id)
    assert any("events.jsonl must not be a symlink" in error for error in verification.errors)


def test_runtime_ui_has_no_dynamic_html_sink_or_external_dependency():
    html = (mission_module.ROOT / "static" / "index.html").read_text(encoding="utf-8")
    script = (mission_module.ROOT / "static" / "sentinel-live.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script
    assert "outerHTML" not in script
    assert "<style" not in html
    assert 'style="' not in html
    assert "http://" not in html and "https://" not in html
    assert 'role="log"' in html
    assert 'tabindex="0"' in html
    assert 'aria-live="polite"' in html
    assert 'maxlength="500"' in html
