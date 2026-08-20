from __future__ import annotations
import hashlib
import json
import shutil
import uuid
from pathlib import Path
from .models import Event, Evidence, MissionResult

ROOT = Path(__file__).resolve().parents[1]
RANGE = ROOT / "range" / "ssh-misconfig" / "sshd_config"
DATA = ROOT / "data"

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()

def ev(seq, agent, kind, message, evidence=None):
    return Event(seq=seq, agent=agent, kind=kind, message=message, evidence=evidence)

def run_mission(task: str) -> MissionResult:
    mission_id = uuid.uuid4().hex[:12]
    ws = DATA / mission_id
    ws.mkdir(parents=True, exist_ok=False)
    target = ws / "sshd_config"
    shutil.copy2(RANGE, target)

    lines = target.read_text().splitlines()
    root_line = next((i+1 for i,v in enumerate(lines) if v.strip().lower()=="permitrootlogin yes"), None)
    pass_line = next((i+1 for i,v in enumerate(lines) if v.strip().lower()=="passwordauthentication yes"), None)
    digest_before = sha256(target)

    evidence = Evidence(path=str(target.relative_to(ROOT)), line=root_line, sha256=digest_before, excerpt="PermitRootLogin yes")
    events = [
        ev(1, "RECON", "observed", f"Inspected the mission copy of sshd_config for task: {task}", evidence),
        ev(2, "EXPLOIT-ANALYSIS", "analysis", "Root SSH login and password authentication are both enabled in the supplied demo configuration. This increases credential and remote-access risk."),
        ev(3, "THREAT-MODEL", "challenge", "Finding accepted because it is backed by configuration evidence, not a version guess or simulated network result."),
    ]

    patched=[]
    for line in lines:
        s=line.strip().lower()
        if s=="permitrootlogin yes": patched.append("PermitRootLogin no")
        elif s=="passwordauthentication yes": patched.append("PasswordAuthentication no")
        else: patched.append(line)
    target.write_text("\n".join(patched)+"\n")
    digest_after = sha256(target)
    patch_evidence = Evidence(path=str(target.relative_to(ROOT)), sha256=digest_after, excerpt="PermitRootLogin no; PasswordAuthentication no")
    events.append(ev(4, "SECURE-CODING", "remediation", "Applied a minimal hardening patch to the isolated mission copy only.", patch_evidence))

    new = target.read_text().splitlines()
    ok = "PermitRootLogin no" in new and "PasswordAuthentication no" in new
    if not ok:
        raise RuntimeError("Verification failed")
    events.append(ev(5, "RECON", "verified", "Re-read the patched file and verified both hardening settings are present.", patch_evidence))

    report = ws / "report.md"
    report.write_text(
        "# Sentinel Swarm Mission Report\n\n"
        f"Mission: `{mission_id}`\n\n"
        f"Task: {task}\n\n"
        "## Verified finding\n"
        f"- `PermitRootLogin yes` observed at line {root_line}.\n"
        f"- `PasswordAuthentication yes` observed at line {pass_line}.\n\n"
        "## Remediation\n"
        "- Changed `PermitRootLogin` to `no`.\n"
        "- Changed `PasswordAuthentication` to `no`.\n\n"
        "## Verification\n"
        f"- Before SHA256: `{digest_before}`\n"
        f"- After SHA256: `{digest_after}`\n"
        "- Patched mission copy re-read successfully.\n"
    )
    events.append(ev(6, "REPORT-WRITER", "report", "Wrote an evidence-backed Markdown report for this mission.", Evidence(path=str(report.relative_to(ROOT)), sha256=sha256(report), excerpt="Sentinel Swarm Mission Report")))

    ledger = ws / "events.jsonl"
    ledger.write_text("\n".join(json.dumps(e.model_dump(), separators=(",", ":")) for e in events)+"\n")
    return MissionResult(mission_id=mission_id, events=events, report_path=str(report.relative_to(ROOT)))
