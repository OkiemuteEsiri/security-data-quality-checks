# Security Data Quality Checks

Security automation and data-engineering project for validating the integrity, freshness, ownership and lifecycle quality of vulnerability and security telemetry before it reaches operational or executive reporting.

## Problem statement
Vulnerability-management, detection, exposure-management and GRC programs depend on data from scanners, EDR platforms, SIEMs, CMDBs and asset inventories. Weak data quality can create false SLA breaches, duplicate vulnerability counts, stale exposure decisions, incorrect ownership escalation and misleading executive metrics.

This repository demonstrates a defensive engineering pattern for making security-data quality measurable, explainable and testable.

## What this project implements
- Immutable canonical security-finding models.
- Fail-closed JSON ingestion and required-field validation.
- UTC timestamp normalization and temporal-integrity checks.
- Ownership coverage checks.
- Canonical lifecycle-state validation.
- Source-system registration controls.
- Stale-evidence detection for open findings.
- CVE-format validation.
- Potential duplicate remediation-unit detection.
- Severity-weighted quality-risk scoring bounded to 0–100.
- Clean-record rate and issue metrics by severity/rule.
- Markdown executive/technical reporting.
- Offline CLI execution.
- Synthetic security findings dataset.
- Unit-test coverage and least-privilege GitHub Actions CI.

## Repository structure
```text
.github/workflows/ci.yml       Least-privilege CI checks
data/synthetic_findings.json   Synthetic vulnerability/security records
docs/architecture-methodology.md
reports/example-assessment.md
src/models.py                  Validated domain models
src/quality_engine.py          Quality controls and metrics
src/reporting.py               Markdown reporting
src/cli.py                     Offline command-line entry point
tests/test_quality_engine.py   Unit tests
```

## Data-quality controls
| Rule | Control | Risk |
|---|---|---|
| DQ-OWN-001 | Missing accountable owner | Remediation cannot be routed reliably |
| DQ-STA-001 | Unsupported lifecycle state | SLA/backlog metrics become inconsistent |
| DQ-SRC-001 | Unregistered source system | Lineage and normalization are not governed |
| DQ-TIM-001 | Future-dated observation | Clock/timezone or ingestion defect |
| DQ-FRE-001 | Stale open finding | Current risk may be based on obsolete evidence |
| DQ-CVE-001 | Malformed CVE identifier | Correlation and enrichment may fail |
| DQ-DUP-001 | Potential duplicate remediation unit | Backlog/exposure may be overstated |

## Usage
Run against the included synthetic dataset:

```bash
python -m src.cli data/synthetic_findings.json --output quality-report.md
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## Design principles
### Evidence before metrics
Records are checked before they are trusted for aggregate reporting. A dashboard should not hide malformed or stale source data.

### Correct the lineage, not the presentation
The remediation workflow favors fixing authoritative source mappings and transformation logic rather than manually editing downstream reports.

### Explainable risk
Every issue retains a rule ID, severity, record ID, affected field, observation, remediation and closure condition.

### Conservative security interpretation
A security-data defect is not presented as proof of compromise. Likewise, downstream ATT&CK mappings belong to the underlying security event or vulnerability, not to the data-quality defect itself.

## Architecture
```text
Synthetic / exported findings
          |
          v
  Canonical ingestion
          |
          v
 Schema + temporal validation
          |
          v
 Data-quality control engine
          |
          +--> rule-level findings
          +--> quality metrics
          +--> bounded risk score
          |
          v
 Markdown assessment report
          |
          v
 Remediation -> reprocess -> revalidate
```

See `docs/architecture-methodology.md` for the control rationale and validation workflow.

## Example operational questions answered
- What percentage of security records are clean enough for trusted reporting?
- Which security-data defects most directly threaten remediation governance?
- Are open vulnerabilities backed by recent evidence?
- Are findings assigned to accountable owners?
- Are lifecycle states normalized across tools?
- Are scanner records potentially double-counting the same remediation unit?
- Is CVE enrichment likely to fail because identifiers are malformed?
- Which source systems require normalization/governance work?

## Remediation and validation workflow
1. Identify the quality issue and affected source record.
2. Determine whether the defect originates in the source, transformation layer or governance mapping.
3. Correct the authoritative mapping or normalization rule.
4. Reprocess affected records.
5. Re-run the quality controls.
6. Close the issue only when the reprocessed record passes validation.

## Security impact
Reliable security data reduces the risk of:
- incorrect vulnerability prioritization;
- misleading SLA and compliance metrics;
- inflated or understated exposure counts;
- ownership disputes and delayed remediation;
- stale findings driving current-risk decisions;
- broken CVE/threat-intelligence enrichment;
- unreliable executive reporting.

## MITRE ATT&CK context
This project does not map data-quality defects themselves to adversary techniques. If an underlying vulnerability record is associated with exploitation, techniques such as **T1190 — Exploit Public-Facing Application** or **T1210 — Exploitation of Remote Services** may be recorded on that security finding. Keeping those mappings separate prevents unsupported claims about compromise.

## Skills demonstrated
- Security engineering
- Vulnerability-management data governance
- Security automation with Python
- Canonical data modelling
- Validation and fail-closed ingestion
- Exposure and remediation metrics
- Data lineage thinking
- Risk scoring and executive reporting
- Unit testing
- CI/CD security controls

## Limitations
- The dataset is entirely synthetic.
- The engine performs deterministic offline checks; it does not contact scanner, EDR, SIEM, CMDB or cloud APIs.
- Duplicate detection is intentionally conservative and should be extended with service/port/plugin identity for heterogeneous production feeds.
- CVE syntax validation is structural and does not query an authoritative CVE catalogue.
- Thresholds such as the 30-day freshness window should be governed per environment and telemetry source.

## Roadmap
- Add configurable rule policies and thresholds.
- Add cross-source reconciliation with canonical asset identities.
- Add service/port/plugin-aware deduplication.
- Add schema-version tracking and data-contract tests.
- Add trend reporting for ownership, freshness and normalization defects.
- Add optional CSV and JSON assessment outputs.
- Add quality gates suitable for security-data CI pipelines.

## Safety
This repository contains no production credentials, employer/client data, exploit payloads, malware, live-system targeting or offensive automation. All examples are synthetic and intended for defensive security engineering and portfolio demonstration.
