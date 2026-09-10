from __future__ import annotations

from .models import QualityIssue, SecurityFinding
from .quality_engine import metrics


def render_markdown(findings: list[SecurityFinding], issues: list[QualityIssue]) -> str:
    m = metrics(findings, issues)
    lines = [
        "# Security Data Quality Assessment",
        "",
        "## Executive summary",
        f"- Records assessed: **{m['records']}**",
        f"- Records with quality issues: **{m['records_with_issues']}**",
        f"- Clean-record rate: **{m['clean_record_pct']}%**",
        f"- Quality-risk score: **{m['quality_risk_score']}/100**",
        "",
        "## Findings",
    ]
    if not issues:
        lines.append("No quality issues detected in the assessed synthetic dataset.")
    for issue in sorted(issues, key=lambda i: (i.severity, i.rule_id, i.record_id)):
        lines.extend([
            f"### {issue.rule_id} — {issue.record_id}",
            f"- Severity: **{issue.severity.title()}**",
            f"- Field: `{issue.field}`",
            f"- Observation: {issue.message}",
            f"- Remediation: {issue.remediation}",
            "",
        ])
    lines.extend([
        "## Validation standard",
        "A data-quality issue is only considered closed after the source mapping, timestamp, ownership, lifecycle state, or deduplication logic has been corrected and the affected record has been reprocessed successfully.",
        "",
        "## Limitations",
        "This repository uses synthetic records and offline deterministic checks. It does not query production scanners, SIEMs, CMDBs, cloud platforms, or employer/client environments.",
    ])
    return "\n".join(lines)
