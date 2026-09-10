# Architecture and Methodology

## Purpose
Security decisions are only as reliable as the telemetry, ownership and lifecycle data feeding them. This project models security data quality as an engineering control that can be tested, scored, remediated and revalidated.

## Architecture
1. **Ingestion** — JSON findings are parsed into immutable canonical records.
2. **Validation** — required fields, severities and timezone-aware timestamps fail closed.
3. **Quality controls** — deterministic rules assess ownership, lifecycle taxonomy, freshness, source registration, CVE syntax and potential duplicate remediation units.
4. **Risk aggregation** — issue severity is converted into a bounded quality-risk score while retaining rule-level transparency.
5. **Reporting** — Markdown output presents executive metrics, evidence, remediation and closure criteria.

## Control catalogue
- `DQ-OWN-001` — missing accountable owner.
- `DQ-STA-001` — unsupported lifecycle state.
- `DQ-SRC-001` — unregistered source system.
- `DQ-TIM-001` — future-dated observation suggesting clock/timezone or ingestion defects.
- `DQ-FRE-001` — stale open finding without recent evidence.
- `DQ-CVE-001` — malformed CVE identifier.
- `DQ-DUP-001` — potential duplicate remediation unit within the same source.

## Remediation workflow
1. Confirm whether the issue is caused by source data, transformation logic or governance.
2. Correct the authoritative mapping or normalization rule rather than editing reports manually.
3. Reprocess the affected record.
4. Re-run quality controls.
5. Close only when the record passes and evidence shows the corrected lineage.

## Security relevance
Poor data quality can produce false SLA breaches, incorrect ownership escalation, inflated vulnerability counts, missed exposure, misleading executive metrics and unreliable remediation prioritization. These are governance and engineering risks even when no adversary activity is present.

## MITRE ATT&CK context
This project is primarily a security engineering/data-governance control and does not map quality defects to attacker behavior. Where downstream vulnerability records reference exploitation, ATT&CK mappings such as T1190 or T1210 belong to the underlying security finding, not to the data-quality issue itself. This separation prevents overstating evidence.

## Limitations
All data is synthetic. No production scanner, SIEM, CMDB, EDR, cloud tenant, credential or client environment is accessed.
