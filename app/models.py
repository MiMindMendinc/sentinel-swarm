from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

AgentName = Literal[
    "RECON",
    "EXPLOIT-ANALYSIS",
    "THREAT-MODEL",
    "SECURE-CODING",
    "REPORT-WRITER",
]
ScenarioName = Literal["ssh-misconfig"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class MissionRequest(StrictModel):
    scenario_id: ScenarioName = "ssh-misconfig"
    task: str = Field(
        default="Audit the built-in SSH misconfiguration demo",
        min_length=1,
        max_length=500,
        description="Operator note for the fixed built-in scenario; not an arbitrary command.",
    )

    @field_validator("task", mode="before")
    @classmethod
    def normalize_task(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("task must be a string")
        normalized = " ".join(value.replace("\r", " ").replace("\n", " ").split())
        if not normalized:
            raise ValueError("task must contain non-whitespace characters")
        return normalized


class Evidence(StrictModel):
    path: str
    line: int | None = None
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    excerpt: str


class Event(StrictModel):
    seq: int = Field(ge=1)
    agent: AgentName
    kind: Literal["observed", "analysis", "challenge", "remediation", "verified", "report"]
    message: str
    evidence: Evidence | None = None


class VerificationResult(StrictModel):
    mission_id: str
    valid: bool
    checked_artifacts: int = Field(ge=0)
    checked_ledger_entries: int = Field(ge=0)
    errors: list[str]
    manifest_sha256: str | None = None
    ledger_head_sha256: str | None = None


class MissionResult(StrictModel):
    mission_id: str
    scenario_id: ScenarioName
    status: Literal["completed"] = "completed"
    events: list[Event]
    report_path: str
    manifest_path: str
    manifest_sha256: str
    ledger_path: str
    ledger_head_sha256: str
    verification: VerificationResult
