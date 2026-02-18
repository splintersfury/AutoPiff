"""
Unit tests for the AutoPiff reachability schema validation.
"""

import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

SCHEMA_PATH = Path(__file__).parent.parent.parent / "schemas" / "reachability.schema.json"


@pytest.fixture
def schema():
    with open(SCHEMA_PATH, 'r') as f:
        return json.load(f)


class TestReachabilitySchema:
    """Tests for reachability.schema.json validation."""

    def test_valid_full_data(self, schema):
        """Valid data with all fields should pass."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "a" * 64,
                "arch": "x86_64"
            },
            "dispatch": {
                "driver_entry": "DriverEntry",
                "major_functions": {
                    "IRP_MJ_CREATE": "sub_140001000",
                    "IRP_MJ_CLOSE": None,
                    "IRP_MJ_DEVICE_CONTROL": "sub_140002000",
                    "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
                }
            },
            "ioctls": [
                {
                    "ioctl": "0x222000",
                    "handler": "sub_140005000",
                    "confidence": 0.9,
                    "evidence": ["switch_on_IoControlCode"]
                }
            ],
            "tags": [
                {
                    "function": "sub_140005000",
                    "reachability_class": "ioctl",
                    "confidence": 0.95,
                    "paths": [["IRP_MJ_DEVICE_CONTROL", "sub_140002000", "sub_140005000"]],
                    "evidence": ["direct_callgraph_edge", "ioctl_case_call"]
                }
            ],
            "notes": ["Test note"]
        }
        validate(instance=data, schema=schema)

    def test_valid_empty_tags(self, schema):
        """Valid data with no tags should pass."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "b" * 64,
                "arch": "x64"
            },
            "dispatch": {
                "driver_entry": None,
                "major_functions": {
                    "IRP_MJ_CREATE": None,
                    "IRP_MJ_CLOSE": None,
                    "IRP_MJ_DEVICE_CONTROL": None,
                    "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
                }
            },
            "ioctls": [],
            "tags": [],
            "notes": ["DriverEntry not found"]
        }
        validate(instance=data, schema=schema)

    def test_valid_unknown_reachability(self, schema):
        """Tag with unknown reachability and empty paths should pass."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "c" * 64,
                "arch": "ARM64"
            },
            "dispatch": {
                "driver_entry": "DriverEntry",
                "major_functions": {
                    "IRP_MJ_CREATE": None,
                    "IRP_MJ_CLOSE": None,
                    "IRP_MJ_DEVICE_CONTROL": None,
                    "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
                }
            },
            "ioctls": [],
            "tags": [
                {
                    "function": "sub_140003000",
                    "reachability_class": "unknown",
                    "confidence": 0.0,
                    "paths": [],
                    "evidence": ["driver_entry_dispatch_setup"]
                }
            ],
            "notes": []
        }
        validate(instance=data, schema=schema)

    def test_invalid_missing_dispatch(self, schema):
        """Missing required 'dispatch' field should fail."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "d" * 64,
                "arch": "x64"
            },
            "ioctls": [],
            "tags": [],
            "notes": []
        }
        with pytest.raises(ValidationError):
            validate(instance=data, schema=schema)

    def test_invalid_reachability_class(self, schema):
        """Invalid reachability_class value should fail."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "e" * 64,
                "arch": "x64"
            },
            "dispatch": {
                "driver_entry": "DriverEntry",
                "major_functions": {
                    "IRP_MJ_CREATE": None,
                    "IRP_MJ_CLOSE": None,
                    "IRP_MJ_DEVICE_CONTROL": None,
                    "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
                }
            },
            "ioctls": [],
            "tags": [
                {
                    "function": "test_func",
                    "reachability_class": "invalid_class",
                    "confidence": 0.5,
                    "paths": [],
                    "evidence": ["driver_entry_dispatch_setup"]
                }
            ],
            "notes": []
        }
        with pytest.raises(ValidationError):
            validate(instance=data, schema=schema)

    def test_invalid_sha256_format(self, schema):
        """Invalid SHA256 format should fail."""
        data = {
            "autopiff_stage": "reachability",
            "driver": {
                "sha256": "not_a_hash",
                "arch": "x64"
            },
            "dispatch": {
                "driver_entry": None,
                "major_functions": {
                    "IRP_MJ_CREATE": None,
                    "IRP_MJ_CLOSE": None,
                    "IRP_MJ_DEVICE_CONTROL": None,
                    "IRP_MJ_INTERNAL_DEVICE_CONTROL": None
                }
            },
            "ioctls": [],
            "tags": [],
            "notes": []
        }
        with pytest.raises(ValidationError):
            validate(instance=data, schema=schema)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
