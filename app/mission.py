from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import ValidationError

from .models import Event, Evidence, MissionRequest, MissionResult, VerificationResult

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / "range" / "ssh-misconfig" / "sshd_config"
DATA = Path(os.environ.get("SENTINEL_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
SCENARIO_ID = "ssh-misconfig"
ZERO_HASH = "0" * 64
MISSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
MANIFEST_KEYS = {
    "schema_version",
    "mission_id",
    "scenario_id",
    "operator_note",
    "completed_at",
    "event_count",
    "ledger_head_sha256",
    "artifacts",
}
ARTIFACT_KEYS = {"path", "role", "sha256", "size"}
REQUIRED_ARTIFACT_ROLES = {
    "before/sshd_config": "input-before",
    "after/sshd_config": "output-after",
    "report.md": "report",
    "events.jsonl": "hash-chained-ledger",
}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


MAX_MISSIONS = _env_int("SENTINEL_MAX_MISSIONS", 500, 1, 100_000)
MAX_CONCURRENT_MISSIONS = _env_int("SENTINEL_MAX_CONCURRENT_MISSIONS", 4, 1, 64)
MISSION_WAIT_SECONDS = _env_int("SENTINEL_MISSION_WAIT_SECONDS", 5, 0, 60)
_MISSION_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_MISSIONS)
_CAPACITY_LOCK = threading.Lock()


class MissionError(RuntimeError):
    """Base class for safe mission failures."""


class MissionBusyError(MissionError):
    """Raised when the bounded mission worker pool is saturated."""


class MissionCapacityError(MissionError):
    """Raised instead of deleting retained evidence when storage is at capacity."""


class MissionIntegrityError(MissionError):
    """Raised when a newly produced mission cannot verify its own evidence."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _markdown_safe_json(value: str) -> str:
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("&", r"\u0026")
        .replace("<", r"\u003c")
        .replace(">", r"\u003e")
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(value: str) -> Any:
    return json.loads(value, object_pairs_hook=_reject_duplicate_keys)


def _atomic_private_write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            os.chmod(temporary, 0o600)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if temporary.exists():
            temporary.unlink()


def _make_read_only(*paths: Path) -> None:
    for path in paths:
        os.chmod(path, 0o400)


def _safe_workspace_path(workspace: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str) or not relative_path or "\x00" in relative_path:
        raise ValueError("artifact path must be a non-empty string")
    normalized = PurePosixPath(relative_path)
    if normalized.is_absolute() or ".." in normalized.parts:
        raise ValueError(f"artifact escapes mission workspace: {relative_path}")
    if normalized.as_posix() != relative_path or "." in normalized.parts:
        raise ValueError(f"artifact path is not canonical: {relative_path}")
    candidate = workspace.joinpath(*normalized.parts)
    workspace_root = workspace.resolve()
    resolved = candidate.resolve(strict=False)
    if resolved == workspace_root or not resolved.is_relative_to(workspace_root):
        raise ValueError(f"artifact escapes mission workspace: {relative_path}")
    current = workspace
    for part in normalized.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"artifact path must not contain a symlink: {relative_path}")
    return candidate


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return (Path(DATA.name) / path.relative_to(DATA)).as_posix()


def ev(seq: int, agent: str, kind: str, message: str, evidence: Evidence | None = None) -> Event:
    return Event(seq=seq, agent=agent, kind=kind, message=message, evidence=evidence)


def _prepare_data_root() -> None:
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DATA, 0o700)


def mission_capacity() -> dict[str, int]:
    _prepare_data_root()
    used = sum(1 for item in DATA.iterdir() if item.is_dir() and MISSION_ID_RE.fullmatch(item.name))
    return {"used": used, "maximum": MAX_MISSIONS, "remaining": max(0, MAX_MISSIONS - used)}


def mission_exists(mission_id: str) -> bool:
    workspace = DATA / mission_id
    return (
        bool(MISSION_ID_RE.fullmatch(mission_id))
        and workspace.is_dir()
        and not workspace.is_symlink()
    )


def _create_workspace() -> tuple[str, Path]:
    _prepare_data_root()
    with _CAPACITY_LOCK:
        capacity = mission_capacity()
        if capacity["remaining"] == 0:
            raise MissionCapacityError(
                "Mission evidence capacity reached; archive or remove old missions before continuing."
            )
        for _ in range(5):
            mission_id = uuid.uuid4().hex
            workspace = DATA / mission_id
            try:
                workspace.mkdir(mode=0o700)
            except FileExistsError:
                continue
            os.chmod(workspace, 0o700)
            return mission_id, workspace
    raise MissionError("Unable to allocate a unique mission workspace")


def _artifact(path: Path, workspace: Path, role: str) -> dict[str, object]:
    return {
        "path": path.relative_to(workspace).as_posix(),
        "role": role,
        "sha256": sha256(path),
        "size": path.stat().st_size,
    }


def _write_ledger(events: list[Event], ledger: Path) -> str:
    previous = ZERO_HASH
    lines: list[str] = []
    for event in events:
        record: dict[str, object] = {
            "schema_version": 1,
            **event.model_dump(mode="json"),
            "previous_sha256": previous,
        }
        entry_sha256 = _sha256_text(_canonical_json(record))
        record["entry_sha256"] = entry_sha256
        lines.append(_canonical_json(record))
        previous = entry_sha256
    _atomic_private_write(ledger, "\n".join(lines) + "\n")
    return previous


def _verify_ledger(ledger: Path, workspace: Path) -> tuple[list[str], int, str | None, set[str]]:
    errors: list[str] = []
    checked_entries = 0
    expected_previous = ZERO_HASH
    head: str | None = None
    evidence_paths: set[str] = set()
    allowed_keys = {
        "schema_version",
        "seq",
        "agent",
        "kind",
        "message",
        "evidence",
        "previous_sha256",
        "entry_sha256",
    }
    if ledger.is_symlink():
        return ["events.jsonl must not be a symlink"], 0, None, evidence_paths
    try:
        lines = ledger.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return [f"Unable to read events.jsonl: {exc}"], 0, None, evidence_paths

    if not lines:
        return ["events.jsonl is empty"], 0, None, evidence_paths

    for number, line in enumerate(lines, start=1):
        try:
            record = _load_json(line)
            if not isinstance(record, dict):
                raise ValueError("ledger entry must be an object")
        except (json.JSONDecodeError, ValueError) as exc:
            errors.append(f"Ledger line {number} is invalid JSON: {exc}")
            continue

        checked_entries += 1
        unexpected = set(record) - allowed_keys
        missing = allowed_keys - set(record)
        if unexpected or missing:
            errors.append(
                f"Ledger line {number} has schema mismatch; missing={sorted(missing)}, unexpected={sorted(unexpected)}"
            )
        if record.get("schema_version") != 1:
            errors.append(f"Ledger line {number} has an unsupported schema version")

        recorded_hash = record.get("entry_sha256")
        previous_hash = record.get("previous_sha256")
        hash_payload = dict(record)
        hash_payload.pop("entry_sha256", None)
        calculated_hash = _sha256_text(_canonical_json(hash_payload))
        if not isinstance(recorded_hash, str) or not SHA256_RE.fullmatch(recorded_hash):
            errors.append(f"Ledger line {number} has an invalid entry hash")
        elif not hmac.compare_digest(recorded_hash, calculated_hash):
            errors.append(f"Ledger line {number} entry hash does not match its contents")
        if previous_hash != expected_previous:
            errors.append(f"Ledger line {number} does not link to the previous entry")

        event_payload = {
            key: record.get(key) for key in ("seq", "agent", "kind", "message", "evidence")
        }
        try:
            event = Event.model_validate(event_payload)
        except ValidationError as exc:
            errors.append(f"Ledger line {number} contains an invalid event: {exc.errors(include_input=False)}")
        else:
            if event.seq != number:
                errors.append(f"Ledger line {number} has non-contiguous event sequence {event.seq}")
            if event.evidence:
                evidence_paths.add(event.evidence.path)
                try:
                    artifact = _safe_workspace_path(workspace, event.evidence.path)
                except ValueError as exc:
                    errors.append(str(exc))
                else:
                    if not artifact.is_file():
                        errors.append(f"Evidence artifact is missing: {event.evidence.path}")
                    elif not hmac.compare_digest(sha256(artifact), event.evidence.sha256):
                        errors.append(f"Evidence hash mismatch: {event.evidence.path}")

        if isinstance(recorded_hash, str) and SHA256_RE.fullmatch(recorded_hash):
            expected_previous = recorded_hash
            head = recorded_hash

    return errors, checked_entries, head, evidence_paths


def verify_mission(mission_id: str) -> VerificationResult:
    errors: list[str] = []
    checked_artifacts = 0
    checked_entries = 0
    manifest_sha256: str | None = None
    ledger_head: str | None = None

    if not MISSION_ID_RE.fullmatch(mission_id):
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=["Invalid mission identifier"],
        )

    workspace = DATA / mission_id
    manifest_path = workspace / "manifest.json"
    anchor_path = workspace / "manifest.sha256"
    if not workspace.is_dir():
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=["Mission workspace does not exist"],
        )
    if workspace.is_symlink():
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=["Mission workspace must not be a symlink"],
        )
    if not manifest_path.is_file() or not anchor_path.is_file():
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=["Manifest or manifest anchor is missing"],
        )
    if manifest_path.is_symlink() or anchor_path.is_symlink():
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=["Manifest and manifest anchor must not be symlinks"],
        )

    manifest_sha256 = sha256(manifest_path)
    try:
        anchored_sha256 = anchor_path.read_text(encoding="utf-8").split()[0]
    except (OSError, IndexError):
        anchored_sha256 = ""
    if not SHA256_RE.fullmatch(anchored_sha256):
        errors.append("Manifest anchor is malformed")
    elif not hmac.compare_digest(anchored_sha256, manifest_sha256):
        errors.append("Manifest hash does not match manifest.sha256")

    try:
        manifest = _load_json(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"Manifest is invalid: {exc}")
        return VerificationResult(
            mission_id=mission_id,
            valid=False,
            checked_artifacts=0,
            checked_ledger_entries=0,
            errors=errors,
            manifest_sha256=manifest_sha256,
        )

    unexpected_manifest_keys = set(manifest) - MANIFEST_KEYS
    missing_manifest_keys = MANIFEST_KEYS - set(manifest)
    if unexpected_manifest_keys or missing_manifest_keys:
        errors.append(
            "Manifest schema mismatch; "
            f"missing={sorted(missing_manifest_keys)}, "
            f"unexpected={sorted(unexpected_manifest_keys)}"
        )

    if manifest.get("schema_version") != 1:
        errors.append("Unsupported manifest schema version")
    if manifest.get("mission_id") != mission_id:
        errors.append("Manifest mission identifier does not match its workspace")
    if manifest.get("scenario_id") != SCENARIO_ID:
        errors.append("Manifest scenario identifier is invalid")
    try:
        normalized_request = MissionRequest(task=manifest.get("operator_note"))
    except ValidationError as exc:
        errors.append(
            "Manifest operator note is invalid: "
            f"{exc.errors(include_input=False, include_context=False)}"
        )
    else:
        if normalized_request.task != manifest.get("operator_note"):
            errors.append("Manifest operator note is not canonical")
    try:
        completed_at = datetime.fromisoformat(manifest.get("completed_at"))
    except (TypeError, ValueError):
        errors.append("Manifest completion time is invalid")
    else:
        if completed_at.tzinfo is None:
            errors.append("Manifest completion time must include a timezone")

    artifacts = manifest.get("artifacts")
    artifact_paths: set[str] = set()
    if not isinstance(artifacts, list):
        errors.append("Manifest artifacts must be a list")
        artifacts = []
    for item in artifacts:
        if not isinstance(item, dict):
            errors.append("Manifest artifact entry must be an object")
            continue
        unexpected_artifact_keys = set(item) - ARTIFACT_KEYS
        missing_artifact_keys = ARTIFACT_KEYS - set(item)
        if unexpected_artifact_keys or missing_artifact_keys:
            errors.append(
                "Manifest artifact schema mismatch; "
                f"missing={sorted(missing_artifact_keys)}, "
                f"unexpected={sorted(unexpected_artifact_keys)}"
            )
        relative_path = item.get("path")
        recorded_sha256 = item.get("sha256")
        recorded_size = item.get("size")
        try:
            artifact = _safe_workspace_path(workspace, relative_path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if relative_path in artifact_paths:
            errors.append(f"Duplicate manifest artifact: {relative_path}")
            continue
        artifact_paths.add(relative_path)
        expected_role = REQUIRED_ARTIFACT_ROLES.get(relative_path)
        if expected_role is None:
            errors.append(f"Manifest contains an unexpected artifact: {relative_path}")
        elif item.get("role") != expected_role:
            errors.append(f"Manifest artifact role is invalid: {relative_path}")
        checked_artifacts += 1
        if not artifact.is_file():
            errors.append(f"Manifest artifact is missing: {relative_path}")
            continue
        if not isinstance(recorded_sha256, str) or not SHA256_RE.fullmatch(recorded_sha256):
            errors.append(f"Manifest artifact has invalid SHA-256: {relative_path}")
        elif not hmac.compare_digest(sha256(artifact), recorded_sha256):
            errors.append(f"Manifest artifact hash mismatch: {relative_path}")
        if not isinstance(recorded_size, int) or recorded_size < 0:
            errors.append(f"Manifest artifact has invalid size: {relative_path}")
        elif artifact.stat().st_size != recorded_size:
            errors.append(f"Manifest artifact size mismatch: {relative_path}")

    required_artifacts = set(REQUIRED_ARTIFACT_ROLES)
    missing_artifacts = required_artifacts - artifact_paths
    if missing_artifacts:
        errors.append(f"Manifest is missing required artifacts: {sorted(missing_artifacts)}")

    ledger = workspace / "events.jsonl"
    ledger_errors, checked_entries, ledger_head, evidence_paths = _verify_ledger(ledger, workspace)
    errors.extend(ledger_errors)
    if manifest.get("event_count") != checked_entries:
        errors.append("Manifest event count does not match events.jsonl")
    if manifest.get("ledger_head_sha256") != ledger_head:
        errors.append("Manifest ledger head does not match events.jsonl")
    unmanifested_evidence = evidence_paths - artifact_paths
    if unmanifested_evidence:
        errors.append(f"Ledger references unmanifested evidence: {sorted(unmanifested_evidence)}")

    return VerificationResult(
        mission_id=mission_id,
        valid=not errors,
        checked_artifacts=checked_artifacts,
        checked_ledger_entries=checked_entries,
        errors=errors,
        manifest_sha256=manifest_sha256,
        ledger_head_sha256=ledger_head,
    )


def run_mission(request: MissionRequest | str) -> MissionResult:
    if isinstance(request, str):
        request = MissionRequest(task=request)
    if not _MISSION_SLOTS.acquire(timeout=MISSION_WAIT_SECONDS):
        raise MissionBusyError("Mission worker limit reached; retry shortly.")

    try:
        mission_id, workspace = _create_workspace()
        before_dir = workspace / "before"
        after_dir = workspace / "after"
        before_dir.mkdir(mode=0o700)
        after_dir.mkdir(mode=0o700)
        before = before_dir / "sshd_config"
        after = after_dir / "sshd_config"
        shutil.copyfile(RANGE, before)
        _make_read_only(before)

        lines = before.read_text(encoding="utf-8").splitlines()
        root_line = next(
            (i + 1 for i, value in enumerate(lines) if value.strip().lower() == "permitrootlogin yes"),
            None,
        )
        pass_line = next(
            (
                i + 1
                for i, value in enumerate(lines)
                if value.strip().lower() == "passwordauthentication yes"
            ),
            None,
        )
        if root_line is None or pass_line is None:
            raise MissionIntegrityError("Built-in fixture is not in the expected vulnerable state")

        digest_before = sha256(before)
        before_evidence = Evidence(
            path="before/sshd_config",
            line=root_line,
            sha256=digest_before,
            excerpt=(
                f"PermitRootLogin yes (line {root_line}); "
                f"PasswordAuthentication yes (line {pass_line})"
            ),
        )
        events = [
            ev(
                1,
                "RECON",
                "observed",
                (
                    "Inspected the read-only before/ copy of the built-in ssh-misconfig scenario. "
                    f"Operator note: {request.task}"
                ),
                before_evidence,
            ),
            ev(
                2,
                "EXPLOIT-ANALYSIS",
                "analysis",
                "Root SSH login and password authentication are enabled in the supplied demo configuration. This increases credential and remote-access risk.",
            ),
            ev(
                3,
                "THREAT-MODEL",
                "challenge",
                "Finding accepted because it is backed by configuration evidence, not a version guess, CVE claim, simulated network result, or interpretation of the operator note.",
            ),
        ]

        patched: list[str] = []
        for line in lines:
            normalized = line.strip().lower()
            if normalized == "permitrootlogin yes":
                patched.append("PermitRootLogin no")
            elif normalized == "passwordauthentication yes":
                patched.append("PasswordAuthentication no")
            else:
                patched.append(line)
        _atomic_private_write(after, "\n".join(patched) + "\n")

        digest_after = sha256(after)
        after_evidence = Evidence(
            path="after/sshd_config",
            line=root_line,
            sha256=digest_after,
            excerpt="PermitRootLogin no; PasswordAuthentication no",
        )
        events.append(
            ev(
                4,
                "SECURE-CODING",
                "remediation",
                "Wrote a minimal hardening patch to a separate after/ artifact; the before/ evidence was not modified.",
                after_evidence,
            )
        )

        new_lines = after.read_text(encoding="utf-8").splitlines()
        normalized_lines = {line.strip().lower() for line in new_lines}
        verified = {
            "permitrootlogin no",
            "passwordauthentication no",
        }.issubset(normalized_lines) and not {
            "permitrootlogin yes",
            "passwordauthentication yes",
        }.intersection(normalized_lines)
        if not verified:
            raise MissionIntegrityError("Post-change verification failed")
        _make_read_only(after)
        events.append(
            ev(
                5,
                "RECON",
                "verified",
                "Re-read the after/ artifact and verified both hardened settings are present and both unsafe settings are absent.",
                after_evidence,
            )
        )

        report = workspace / "report.md"
        task_json = _markdown_safe_json(request.task)
        _atomic_private_write(
            report,
            "# Sentinel Swarm Mission Report\n\n"
            f"Mission: `{mission_id}`\n\n"
            f"Scenario: `{SCENARIO_ID}`\n\n"
            f"Operator note (JSON): {task_json}\n\n"
            "## Verified finding\n"
            f"- `PermitRootLogin yes` observed at line {root_line} in `before/sshd_config`.\n"
            f"- `PasswordAuthentication yes` observed at line {pass_line} in `before/sshd_config`.\n\n"
            "## Remediation\n"
            "- Wrote `PermitRootLogin no` to `after/sshd_config`.\n"
            "- Wrote `PasswordAuthentication no` to `after/sshd_config`.\n"
            "- Preserved the original `before/sshd_config` unchanged.\n\n"
            "## Verification\n"
            f"- Before SHA-256: `{digest_before}`\n"
            f"- After SHA-256: `{digest_after}`\n"
            "- Re-read the after artifact and confirmed unsafe directives are absent.\n",
        )
        events.append(
            ev(
                6,
                "REPORT-WRITER",
                "report",
                "Wrote an evidence-backed Markdown report for this fixed built-in scenario.",
                Evidence(
                    path="report.md",
                    sha256=sha256(report),
                    excerpt="Sentinel Swarm Mission Report",
                ),
            )
        )
        _make_read_only(report)

        ledger = workspace / "events.jsonl"
        ledger_head = _write_ledger(events, ledger)
        _make_read_only(ledger)
        manifest = workspace / "manifest.json"
        manifest_payload = {
            "schema_version": 1,
            "mission_id": mission_id,
            "scenario_id": SCENARIO_ID,
            "operator_note": request.task,
            "completed_at": datetime.now(UTC).isoformat(),
            "event_count": len(events),
            "ledger_head_sha256": ledger_head,
            "artifacts": [
                _artifact(before, workspace, "input-before"),
                _artifact(after, workspace, "output-after"),
                _artifact(report, workspace, "report"),
                _artifact(ledger, workspace, "hash-chained-ledger"),
            ],
        }
        _atomic_private_write(manifest, json.dumps(manifest_payload, indent=2, ensure_ascii=False) + "\n")
        manifest_digest = sha256(manifest)
        _atomic_private_write(
            workspace / "manifest.sha256",
            f"{manifest_digest}  manifest.json\n",
        )
        _make_read_only(manifest, workspace / "manifest.sha256")

        verification = verify_mission(mission_id)
        if not verification.valid:
            raise MissionIntegrityError(
                "New mission failed self-verification: " + "; ".join(verification.errors)
            )
        os.chmod(before_dir, 0o500)
        os.chmod(after_dir, 0o500)
        os.chmod(workspace, 0o500)

        return MissionResult(
            mission_id=mission_id,
            scenario_id=SCENARIO_ID,
            events=events,
            report_path=_display_path(report),
            manifest_path=_display_path(manifest),
            manifest_sha256=manifest_digest,
            ledger_path=_display_path(ledger),
            ledger_head_sha256=ledger_head,
            verification=verification,
        )
    finally:
        _MISSION_SLOTS.release()
