from __future__ import annotations

import argparse
from pathlib import Path

from .quality_engine import assess, load_findings
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic security findings for data-quality defects.")
    parser.add_argument("input", help="Path to JSON findings array")
    parser.add_argument("--output", default="quality-report.md", help="Markdown report path")
    args = parser.parse_args()

    findings = load_findings(args.input)
    issues = assess(findings)
    report = render_markdown(findings, issues)
    Path(args.output).write_text(report, encoding="utf-8")
    print(f"Assessed {len(findings)} records; identified {len(issues)} quality issues.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
