# Example Security Data Quality Assessment

> Synthetic example output for portfolio demonstration only.

## Executive summary
The sample dataset demonstrates how security reporting can become unreliable when ownership, lifecycle states, telemetry freshness, CVE formatting and duplicate records are not governed consistently.

### Key observations
- One asset has no accountable owner, creating remediation-routing risk.
- Two records represent the same source/asset/CVE remediation unit and require reconciliation.
- One source is not registered in the canonical source catalogue.
- One lifecycle state falls outside the supported governance taxonomy.
- One CVE identifier is malformed.
- Two open records rely on telemetry older than 30 days.

## Business impact
Uncorrected defects can inflate backlog counts, misstate SLA performance, distort risk prioritization and route remediation work to the wrong team.

## Remediation priorities
1. Reconcile duplicate records before executive metric aggregation.
2. Assign accountable ownership to all active findings.
3. Normalize lifecycle states at ingestion.
4. Register source systems and document data lineage.
5. Refresh stale observations before current-risk decisions.
6. Enforce CVE syntax validation at ingestion.

## Validation
Re-run the deterministic checks after correcting source or transformation logic. Quality findings remain open until affected records pass the relevant checks after reprocessing.
