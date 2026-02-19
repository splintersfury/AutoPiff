"""
Unit tests for AutoPiff Stage 6: Ranking schema validation.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"


@pytest.fixture
def ranking_schema():
    with open(SCHEMA_DIR / "ranking.schema.json") as f:
        return json.load(f)


def _make_finding(**overrides):
    """Build a minimal valid finding with optional overrides."""
    finding = {
        "rank": 1,
        "function": "HandleIoctl",
        "final_score": 8.45,
        "rule_ids": ["added_len_check_before_memcpy"],
        "category": "bounds_check",
        "semantic_confidence": 0.92,
        "matching_confidence": 0.85,
        "reachability_class": "ioctl",
        "reachability_confidence": 0.95,
        "reachability_path": ["IRP_MJ_DEVICE_CONTROL", "sub_140002000"],
        "sinks": ["memory_copy"],
        "indicators": ["RtlCopyMemory"],
        "why_matters": "Added length check before memcpy",
        "diff_snippet": "+  if (len > MAX) return STATUS_INVALID_PARAMETER;",
        "penalties_applied": [],
        "score_breakdown": {
            "semantic": [
                {
                    "rule_id": "added_len_check_before_memcpy",
                    "base_weight": 6.0,
                    "rule_confidence": 0.92,
                    "contribution": 5.80,
                }
            ],
            "reachability": {
                "class": "ioctl",
                "bonus": 4.0,
                "confidence": 0.95,
                "contribution": 4.0,
            },
            "sinks": [
                {"sink_group": "memory_copy", "bonus": 1.5, "contribution": 1.38}
            ],
            "penalties": [],
            "final": {
                "total_before_clamp": 11.18,
                "total_after_clamp": 11.18,
                "gates_triggered": [],
            },
        },
    }
    finding.update(overrides)
    return finding


def _make_ranking(findings=None, skipped=None, **overrides):
    """Build a minimal valid ranking document."""
    doc = {
        "autopiff_stage": "ranking",
        "driver_new": {"sha256": "a" * 64, "version": "10.0.26100.1"},
        "driver_old": {"sha256": "b" * 64, "version": "10.0.26100.0"},
        "scoring_model_version": 2,
        "findings": findings if findings is not None else [],
        "skipped_findings": skipped if skipped is not None else [],
    }
    doc.update(overrides)
    return doc


class TestRankingSchema:
    """Tests for ranking.schema.json validation."""

    def test_valid_full_ranking(self, ranking_schema):
        """Full ranking with findings and skipped entries passes."""
        findings = [_make_finding(rank=1), _make_finding(rank=2, function="ProcessPnP")]
        skipped = [
            {"function": "DriverEntry", "reason": "semantic_confidence 0.40 below hard_min 0.45"}
        ]
        doc = _make_ranking(findings=findings, skipped=skipped)
        validate(instance=doc, schema=ranking_schema)

    def test_valid_empty_findings(self, ranking_schema):
        """Empty findings list is valid."""
        doc = _make_ranking(findings=[], skipped=[])
        validate(instance=doc, schema=ranking_schema)

    def test_invalid_missing_scoring_model_version(self, ranking_schema):
        """Missing required scoring_model_version should fail."""
        doc = _make_ranking()
        del doc["scoring_model_version"]
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=ranking_schema)

    def test_invalid_finding_score_above_max(self, ranking_schema):
        """Finding score >15.0 should fail."""
        finding = _make_finding(final_score=15.01)
        doc = _make_ranking(findings=[finding])
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=ranking_schema)

    def test_invalid_reachability_class_enum(self, ranking_schema):
        """Bad reachability_class enum value should fail."""
        finding = _make_finding(reachability_class="syscall")
        doc = _make_ranking(findings=[finding])
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=ranking_schema)

    def test_invalid_empty_rule_ids(self, ranking_schema):
        """Empty rule_ids array violates minItems: 1."""
        finding = _make_finding(rule_ids=[])
        doc = _make_ranking(findings=[finding])
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=ranking_schema)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
