import unittest
from datetime import datetime, timezone

from src.models import SecurityFinding
from src.quality_engine import assess, metrics


NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def finding(**overrides):
    base = dict(
        finding_id="F-1", asset_id="srv-1", source="tenable", severity="high",
        owner="platform", first_seen=datetime(2026, 9, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 9, tzinfo=timezone.utc), status="open",
        cve="CVE-2026-1234",
    )
    base.update(overrides)
    return SecurityFinding(**base)


class QualityEngineTests(unittest.TestCase):
    def test_clean_record_has_no_issues(self):
        self.assertEqual([], assess([finding()], NOW))

    def test_missing_owner_is_high(self):
        issues = assess([finding(owner=None)], NOW)
        self.assertTrue(any(i.rule_id == "DQ-OWN-001" and i.severity == "high" for i in issues))

    def test_invalid_status_is_flagged(self):
        issues = assess([finding(status="investigating")], NOW)
        self.assertTrue(any(i.rule_id == "DQ-STA-001" for i in issues))

    def test_unknown_source_is_flagged(self):
        issues = assess([finding(source="custom-feed")], NOW)
        self.assertTrue(any(i.rule_id == "DQ-SRC-001" for i in issues))

    def test_future_timestamp_is_critical(self):
        future = datetime(2026, 9, 11, tzinfo=timezone.utc)
        issues = assess([finding(last_seen=future)], NOW)
        self.assertTrue(any(i.rule_id == "DQ-TIM-001" and i.severity == "critical" for i in issues))

    def test_stale_open_record_is_flagged(self):
        stale = datetime(2026, 7, 1, tzinfo=timezone.utc)
        issues = assess([finding(last_seen=stale)], NOW)
        self.assertTrue(any(i.rule_id == "DQ-FRE-001" for i in issues))

    def test_malformed_cve_is_flagged(self):
        issues = assess([finding(cve="CVE2026-1234")], NOW)
        self.assertTrue(any(i.rule_id == "DQ-CVE-001" for i in issues))

    def test_duplicate_remediation_unit_is_flagged(self):
        a = finding(finding_id="F-1")
        b = finding(finding_id="F-2")
        issues = assess([a, b], NOW)
        dupes = [i for i in issues if i.rule_id == "DQ-DUP-001"]
        self.assertEqual(2, len(dupes))

    def test_metrics_clean_rate(self):
        records = [finding(finding_id="F-1"), finding(finding_id="F-2", owner=None, asset_id="srv-2")]
        m = metrics(records, assess(records, NOW))
        self.assertEqual(50.0, m["clean_record_pct"])

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            finding(severity="urgent")


if __name__ == "__main__":
    unittest.main()
