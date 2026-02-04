"""
Unit tests for AutoPiff Stages 1-4 schemas.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"


@pytest.fixture
def pairing_schema():
    with open(SCHEMA_DIR / "pairing.schema.json") as f:
        return json.load(f)


@pytest.fixture
def symbols_schema():
    with open(SCHEMA_DIR / "symbols.schema.json") as f:
        return json.load(f)


@pytest.fixture
def matching_schema():
    with open(SCHEMA_DIR / "matching.schema.json") as f:
        return json.load(f)


@pytest.fixture
def semantic_deltas_schema():
    with open(SCHEMA_DIR / "semantic_deltas.schema.json") as f:
        return json.load(f)


class TestPairingSchema:
    """Tests for Stage 1: Pairing schema."""

    def test_valid_accept(self, pairing_schema):
        doc = {
            "autopiff_stage": "pairing",
            "driver_new": {
                "sha256": "a" * 64,
                "product": "Test Driver",
                "version": "1.0.0",
                "arch": "x64"
            },
            "driver_old": {
                "sha256": "b" * 64,
                "product": "Test Driver",
                "version": "0.9.0",
                "arch": "x64"
            },
            "decision": "accept",
            "confidence": 0.85,
            "noise_risk": "low",
            "rationale": ["Same product family", "Adjacent versions"]
        }
        validate(instance=doc, schema=pairing_schema)

    def test_valid_reject_no_prior(self, pairing_schema):
        doc = {
            "autopiff_stage": "pairing",
            "driver_new": {
                "sha256": "a" * 64,
                "product": "New Driver",
                "version": "1.0.0",
                "arch": "x64"
            },
            "driver_old": None,
            "decision": "reject",
            "confidence": 1.0,
            "noise_risk": "high",
            "rationale": ["No prior version found"]
        }
        validate(instance=doc, schema=pairing_schema)

    def test_invalid_decision(self, pairing_schema):
        doc = {
            "autopiff_stage": "pairing",
            "driver_new": {
                "sha256": "a" * 64,
                "product": "Test",
                "version": "1.0",
                "arch": "x64"
            },
            "driver_old": None,
            "decision": "invalid_decision",  # Invalid
            "confidence": 0.5,
            "noise_risk": "low",
            "rationale": []
        }
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=pairing_schema)

    def test_invalid_sha256(self, pairing_schema):
        doc = {
            "autopiff_stage": "pairing",
            "driver_new": {
                "sha256": "not-a-valid-sha256",  # Invalid
                "product": "Test",
                "version": "1.0",
                "arch": "x64"
            },
            "driver_old": None,
            "decision": "reject",
            "confidence": 1.0,
            "noise_risk": "high",
            "rationale": []
        }
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=pairing_schema)


class TestMatchingSchema:
    """Tests for Stage 3: Matching schema."""

    def test_valid_matching(self, matching_schema):
        doc = {
            "autopiff_stage": "matching",
            "driver_new": {"sha256": "a" * 64},
            "driver_old": {"sha256": "b" * 64},
            "matching": {
                "method": "hash_lcs",
                "confidence": 0.87,
                "matched_count": 150,
                "added_count": 10,
                "removed_count": 5,
                "changed_count": 25,
                "total_new": 160,
                "total_old": 155,
                "quality": "high",
                "matched_pairs": [
                    {"function": "DriverEntry", "confidence": 0.95, "changed": True, "delta_score": 42}
                ]
            }
        }
        validate(instance=doc, schema=matching_schema)

    def test_invalid_quality(self, matching_schema):
        doc = {
            "autopiff_stage": "matching",
            "driver_new": {"sha256": "a" * 64},
            "driver_old": {"sha256": "b" * 64},
            "matching": {
                "method": "hash_lcs",
                "confidence": 0.5,
                "matched_count": 50,
                "added_count": 10,
                "removed_count": 5,
                "changed_count": 15,
                "total_new": 60,
                "total_old": 55,
                "quality": "excellent"  # Invalid - must be high/medium/low
            }
        }
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=matching_schema)


class TestSemanticDeltasSchema:
    """Tests for Stage 4: Semantic Deltas schema."""

    def test_valid_deltas(self, semantic_deltas_schema):
        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9.0"},
            "deltas": [
                {
                    "function": "HandleIoctl",
                    "rule_id": "added_len_check_before_memcpy",
                    "category": "bounds_check",
                    "confidence": 0.92,
                    "sinks": ["memory_copy"],
                    "indicators": ["RtlCopyMemory", "InputBufferLength"],
                    "diff_snippet": "+  if (len > sizeof(buf)) return STATUS_INVALID_PARAMETER;",
                    "why_matters": "Added a length/bounds check before a memory copy operation.",
                    "surface_area": ["ioctl"]
                }
            ],
            "summary": {
                "total_deltas": 1,
                "by_category": {"bounds_check": 1},
                "by_rule": {"added_len_check_before_memcpy": 1},
                "top_functions": ["HandleIoctl"]
            }
        }
        validate(instance=doc, schema=semantic_deltas_schema)

    def test_invalid_category(self, semantic_deltas_schema):
        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": [
                {
                    "function": "Test",
                    "rule_id": "test_rule",
                    "category": "invalid_category",  # Invalid
                    "confidence": 0.8,
                    "sinks": [],
                    "indicators": [],
                    "diff_snippet": "",
                    "why_matters": "Test"
                }
            ]
        }
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=semantic_deltas_schema)

    def test_empty_deltas_valid(self, semantic_deltas_schema):
        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": []
        }
        validate(instance=doc, schema=semantic_deltas_schema)


class TestSymbolsSchema:
    """Tests for Stage 2: Symbols schema."""

    def test_valid_symbols(self, symbols_schema):
        doc = {
            "autopiff_stage": "symbols",
            "driver_new": {
                "sha256": "a" * 64,
                "function_count": 150,
                "source_path": "/tmp/new.c",
                "pdb_found": False
            },
            "driver_old": {
                "sha256": "b" * 64,
                "function_count": 145,
                "source_path": "/tmp/old.c",
                "pdb_found": False
            },
            "symbolization": {
                "method": "ghidra_decompile",
                "coverage": 0.75,
                "anchors": [
                    {"name": "DriverEntry", "addr_new": "0x1000", "addr_old": "0x1000", "confidence": 0.95}
                ]
            }
        }
        validate(instance=doc, schema=symbols_schema)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
