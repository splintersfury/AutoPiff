"""
Unit tests for AutoPiff Stage 7: Report schema validation.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"


@pytest.fixture
def report_schema():
    with open(SCHEMA_DIR / "report.schema.json") as f:
        return json.load(f)


def _make_report_finding(**overrides):
    """Build a minimal valid report finding."""
    finding = {
        "rank": 1,
        "function": "HandleIoctl",
        "score": 8.45,
        "confidence": 0.92,
        "rule_ids": ["added_len_check_before_memcpy"],
        "category": "bounds_check",
        "reachability": {"class": "ioctl", "path": ["IRP_MJ_DEVICE_CONTROL"]},
        "sinks": ["memory_copy"],
        "added_checks": ["RtlCopyMemory", "InputBufferLength"],
        "why": "Added length check before memcpy",
    }
    finding.update(overrides)
    return finding


def _make_report(findings=None, **overrides):
    """Build a minimal valid report document."""
    doc = {
        "autopiff_stage": "report",
        "driver": {
            "name": "cldflt.sys",
            "arch": "x64",
            "old": {"sha256": "b" * 64, "version": "10.0.26100.0"},
            "new": {"sha256": "a" * 64, "version": "10.0.26100.1"},
        },
        "pairing": {"decision": "accept", "noise_risk": "low", "confidence": 0.85},
        "summary": {
            "total_findings": len(findings) if findings else 0,
            "reachable_findings": 1 if findings else 0,
            "top_categories": ["bounds_check"] if findings else [],
        },
        "findings": findings if findings is not None else [],
        "metadata": {
            "autopiff_version": "0.6.0",
            "generated_at": "2026-01-15T12:00:00+00:00",
        },
    }
    doc.update(overrides)
    return doc


class TestReportSchema:
    """Tests for report.schema.json validation."""

    def test_valid_full_report(self, report_schema):
        """Full report with findings passes."""
        findings = [_make_report_finding()]
        doc = _make_report(findings=findings)
        validate(instance=doc, schema=report_schema)

    def test_valid_empty_findings(self, report_schema):
        """Report with no findings passes."""
        doc = _make_report(findings=[])
        validate(instance=doc, schema=report_schema)

    def test_invalid_missing_metadata(self, report_schema):
        """Missing required metadata should fail."""
        doc = _make_report()
        del doc["metadata"]
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=report_schema)

    def test_invalid_pairing_decision_enum(self, report_schema):
        """Bad pairing decision enum should fail."""
        doc = _make_report()
        doc["pairing"]["decision"] = "maybe"
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=report_schema)

    def test_invalid_noise_risk_enum(self, report_schema):
        """Bad noise_risk enum should fail."""
        doc = _make_report()
        doc["pairing"]["noise_risk"] = "extreme"
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=report_schema)

    def test_invalid_sha256_format(self, report_schema):
        """Bad SHA256 format should fail."""
        doc = _make_report()
        doc["driver"]["new"]["sha256"] = "not_a_valid_hash"
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=report_schema)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
