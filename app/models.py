from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Literal

AgentName = Literal["RECON", "EXPLOIT-ANALYSIS", "THREAT-MODEL", "SECURE-CODING", "REPORT-WRITER"]

class MissionRequest(BaseModel):
    task: str = Field(default="Audit the built-in SSH misconfiguration demo", min_length=1, max_length=500)

class Evidence(BaseModel):
    path: str
    line: int | None = None
    sha256: str
    excerpt: str

class Event(BaseModel):
    seq: int
    agent: AgentName
    kind: Literal["observed", "analysis", "challenge", "remediation", "verified", "report"]
    message: str
    evidence: Evidence | None = None

class MissionResult(BaseModel):
    mission_id: str
    status: Literal["completed"] = "completed"
    events: list[Event]
    report_path: str
