from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import QualityIssue, SecurityFinding, parse_utc

SEVERITY_WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 1}


def load_findings(path: str | Path) -> list[SecurityFinding]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    findings: list[SecurityFinding] = []
    seen_ids: set[str] = set()
    for item in raw:
        required = {"finding_id", "asset_id", "source", "severity", "first_seen", "last_seen", "status"}
        missing = required - item.keys()
        if missing:
            raise ValueError(f"missing required fields: {sorted(missing)}")
        if item["finding_id"] in seen_ids:
            raise ValueError(f"duplicate finding_id: {item['finding_id']}")
        seen_ids.add(item["finding_id"])
        findings.append(SecurityFinding(
            finding_id=item["finding_id"], asset_id=item["asset_id"], source=item["source"],
            severity=item["severity"], owner=item.get("owner"), first_seen=parse_utc(item["first_seen"]),
            last_seen=parse_utc(item["last_seen"]), status=item["status"], cve=item.get("cve")
        ))
    return findings


def assess(findings: list[SecurityFinding], now: datetime | None = None) -> list[QualityIssue]:
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    issues: list[QualityIssue] = []
    valid_statuses = {"open", "remediated", "accepted", "false_positive"}
    known_sources = {"tenable", "qualys", "defender", "crowdstrike", "manual"}

    fingerprints: Counter[tuple[str, str | None, str]] = Counter(
        (f.asset_id.lower(), f.cve.upper() if f.cve else None, f.source.lower()) for f in findings
    )

    for f in findings:
        if not f.owner or not f.owner.strip():
            issues.append(QualityIssue("DQ-OWN-001", "high", f.finding_id, "owner", "Finding has no accountable owner.", "Assign an accountable service or asset owner and revalidate ownership mapping."))
        if f.status not in valid_statuses:
            issues.append(QualityIssue("DQ-STA-001", "high", f.finding_id, "status", f"Unsupported lifecycle status: {f.status}", "Map source-specific state into the canonical lifecycle taxonomy."))
        if f.source.lower() not in known_sources:
            issues.append(QualityIssue("DQ-SRC-001", "medium", f.finding_id, "source", f"Unrecognized source system: {f.source}", "Register the source and document ingestion ownership before production use."))
        if f.last_seen > now + timedelta(minutes=5):
            issues.append(QualityIssue("DQ-TIM-001", "critical", f.finding_id, "last_seen", "Observation timestamp is materially in the future.", "Correct source clock/timezone handling and replay affected records."))
        if now - f.last_seen > timedelta(days=30) and f.status == "open":
            issues.append(QualityIssue("DQ-FRE-001", "medium", f.finding_id, "last_seen", "Open finding is based on stale telemetry older than 30 days.", "Refresh scanner/telemetry evidence before using this record for current risk decisions."))
        if f.cve and (not f.cve.startswith("CVE-") or len(f.cve.split("-")) != 3):
            issues.append(QualityIssue("DQ-CVE-001", "medium", f.finding_id, "cve", f"Malformed CVE identifier: {f.cve}", "Normalize and validate CVE identifiers against canonical CVE syntax."))
        fp = (f.asset_id.lower(), f.cve.upper() if f.cve else None, f.source.lower())
        if fingerprints[fp] > 1:
            issues.append(QualityIssue("DQ-DUP-001", "high", f.finding_id, "finding_id", "Potential duplicate remediation unit detected.", "Reconcile scanner evidence using a documented asset/CVE/service deduplication key."))
    return issues


def metrics(findings: list[SecurityFinding], issues: list[QualityIssue]) -> dict[str, object]:
    affected = {i.record_id for i in issues}
    total = len(findings)
    weighted = sum(SEVERITY_WEIGHT[i.severity] for i in issues)
    return {
        "records": total,
        "records_with_issues": len(affected),
        "clean_record_pct": round(100.0 * (total - len(affected)) / total, 1) if total else 100.0,
        "issue_count": len(issues),
        "quality_risk_score": min(100, weighted),
        "issues_by_severity": dict(Counter(i.severity for i in issues)),
        "issues_by_rule": dict(Counter(i.rule_id for i in issues)),
    }
