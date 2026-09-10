from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def parse_utc(value: str) -> datetime:
    if not value:
        raise ValueError("timestamp is required")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    asset_id: str
    source: str
    severity: str
    owner: Optional[str]
    first_seen: datetime
    last_seen: datetime
    status: str
    cve: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding_id is required")
        if not self.asset_id.strip():
            raise ValueError("asset_id is required")
        if not self.source.strip():
            raise ValueError("source is required")
        severity = self.severity.lower()
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"unsupported severity: {self.severity}")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        object.__setattr__(self, "severity", severity)


@dataclass(frozen=True)
class QualityIssue:
    rule_id: str
    severity: str
    record_id: str
    field: str
    message: str
    remediation: str

    def __post_init__(self) -> None:
        if self.severity not in {"critical", "high", "medium", "low"}:
            raise ValueError("invalid quality issue severity")
