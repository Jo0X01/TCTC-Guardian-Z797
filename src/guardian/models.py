from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class Finding:
    title: str
    severity: str
    confidence: str
    category: str
    description: str
    evidence: list[str] = field(default_factory=list)
    path: str = ""
    sha256: str = ""
    remediation: str = "none"
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    stage_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StageResult:
    stage_id: str
    name: str
    status: str = "pending"
    message: str = "Waiting"
    findings: int = 0
    duration_seconds: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    scan_id: str
    started_at: str
    ended_at: str = ""
    mode: str = "targeted"
    hostname: str = ""
    os_name: str = ""
    stages: list[StageResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    cancelled: bool = False
    visibility_notes: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "mode": self.mode,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "stages": [s.to_dict() for s in self.stages],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "cancelled": self.cancelled,
            "visibility_notes": self.visibility_notes,
            "coverage": self.coverage,
            "summary": {
                "critical": sum(f.severity == "Critical" for f in self.findings),
                "high": sum(f.severity == "High" for f in self.findings),
                "medium": sum(f.severity == "Medium" for f in self.findings),
                "low": sum(f.severity == "Low" for f in self.findings),
                "info": sum(f.severity == "Info" for f in self.findings),
                "errors": len(self.errors),
                "completed_stages": sum(s.status == "completed" for s in self.stages),
                "warning_stages": sum(s.status == "warning" for s in self.stages),
                "error_stages": sum(s.status == "error" for s in self.stages),
                "skipped_stages": sum(s.status == "skipped" for s in self.stages),
            },
        }
