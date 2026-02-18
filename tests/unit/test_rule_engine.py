"""
Unit tests for the AutoPiff Semantic Rule Engine.
"""

import pytest
from pathlib import Path
import tempfile
import os

# Create minimal test fixtures
RULES_YAML = """
version: 1
categories:
  - id: bounds_check
    description: Added or strengthened bounds/size/index validation.
  - id: lifetime_fix
    description: Added or strengthened pointer lifetime protection.
  - id: user_boundary_check
    description: Added validation of user-mode supplied data.

rules:
  - rule_id: added_len_check_before_memcpy
    category: bounds_check
    confidence: 0.92
    required_signals:
      - sink_group: memory_copy
      - change_type: guard_added
      - guard_kind: length_check
      - proximity: near_sink
    plain_english_summary: Added a length check before memory copy.

  - rule_id: probe_for_read_or_write_added
    category: user_boundary_check
    confidence: 0.93
    required_signals:
      - sink_group: user_probe
      - change_type: validation_added
      - validation_kind: probe
    plain_english_summary: Added ProbeForRead/ProbeForWrite.

global_exclusions:
  - pattern_id: logging_only
    description: Changes limited to logging.
    hints:
      - DbgPrint
      - WPP
"""

SINKS_YAML = """
version: 1
sinks:
  memory_copy:
    description: Memory copy primitives.
    symbols:
      - RtlCopyMemory
      - memcpy
      - memmove

  user_probe:
    description: User/kernel boundary validation.
    symbols:
      - ProbeForRead
      - ProbeForWrite
"""


@pytest.fixture
def rule_engine():
    """Create a rule engine with test fixtures."""
    # Import here to avoid issues if module not installed
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-patch-differ"))

    from rule_engine import SemanticRuleEngine

    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = os.path.join(tmpdir, "rules.yaml")
        sinks_path = os.path.join(tmpdir, "sinks.yaml")

        with open(rules_path, "w") as f:
            f.write(RULES_YAML)
        with open(sinks_path, "w") as f:
            f.write(SINKS_YAML)

        yield SemanticRuleEngine(rules_path, sinks_path)


class TestSinkDetection:
    """Tests for sink symbol detection."""

    def test_find_memcpy_sink(self, rule_engine):
        diff_lines = [
            "--- old",
            "+++ new",
            " void func() {",
            "+    if (len > sizeof(buf)) return;",
            "+    RtlCopyMemory(dst, src, len);",
            " }"
        ]
        sinks = rule_engine._find_sinks(diff_lines)
        assert len(sinks) == 1
        assert sinks[0].group == "memory_copy"
        assert sinks[0].symbol == "RtlCopyMemory"

    def test_find_probe_sink(self, rule_engine):
        diff_lines = [
            "--- old",
            "+++ new",
            "+    ProbeForRead(buffer, length, 1);",
        ]
        sinks = rule_engine._find_sinks(diff_lines)
        assert len(sinks) == 1
        assert sinks[0].group == "user_probe"


class TestGuardDetection:
    """Tests for guard/validation detection."""

    def test_detect_length_check(self, rule_engine):
        added_lines = [
            "if (InputBufferLength < sizeof(REQUEST)) return STATUS_INVALID_PARAMETER;",
            "RtlCopyMemory(dst, src, len);"
        ]
        guards = rule_engine._detect_guard_type(added_lines)
        assert "length_check" in guards

    def test_detect_null_check(self, rule_engine):
        added_lines = [
            "if (ptr == NULL) return;",
            "ExFreePool(ptr);"
        ]
        guards = rule_engine._detect_guard_type(added_lines)
        assert "null_check" in guards

    def test_detect_probe(self, rule_engine):
        added_lines = [
            "ProbeForRead(userBuffer, size, 1);",
            "ProbeForWrite(outBuffer, outSize, 1);"
        ]
        guards = rule_engine._detect_guard_type(added_lines)
        assert "probe" in guards


class TestExclusions:
    """Tests for global exclusion patterns."""

    def test_logging_only_excluded(self, rule_engine):
        diff_lines = [
            "--- old",
            "+++ new",
            "+    DbgPrint(\"Debug message\");",
        ]
        is_excluded, reason = rule_engine._is_excluded(diff_lines)
        assert is_excluded
        assert reason == "logging_only"

    def test_non_logging_not_excluded(self, rule_engine):
        diff_lines = [
            "--- old",
            "+++ new",
            "+    if (len > MAX) return STATUS_INVALID_PARAMETER;",
            "+    RtlCopyMemory(dst, src, len);",
        ]
        is_excluded, _ = rule_engine._is_excluded(diff_lines)
        assert not is_excluded


class TestRuleEvaluation:
    """Tests for full rule evaluation."""

    def test_memcpy_guard_rule_matches(self, rule_engine):
        old_code = """
void HandleRequest(PVOID buf, SIZE_T len) {
    RtlCopyMemory(dest, buf, len);
}
"""
        new_code = """
void HandleRequest(PVOID buf, SIZE_T len) {
    if (len > sizeof(dest)) return;
    RtlCopyMemory(dest, buf, len);
}
"""
        diff_lines = [
            "--- old",
            "+++ new",
            " void HandleRequest(PVOID buf, SIZE_T len) {",
            "+    if (len > sizeof(dest)) return;",
            "     RtlCopyMemory(dest, buf, len);",
            " }"
        ]

        hits = rule_engine.evaluate("HandleRequest", old_code, new_code, diff_lines)

        assert len(hits) >= 1
        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" in rule_ids

    def test_probe_rule_matches(self, rule_engine):
        old_code = "void func(PVOID buf) { memcpy(dst, buf, len); }"
        new_code = "void func(PVOID buf) { ProbeForRead(buf, len, 1); memcpy(dst, buf, len); }"
        diff_lines = [
            "--- old",
            "+++ new",
            " void func(PVOID buf) {",
            "+    ProbeForRead(buf, len, 1);",
            "     memcpy(dst, buf, len);",
            " }"
        ]

        hits = rule_engine.evaluate("func", old_code, new_code, diff_lines)
        rule_ids = [h.rule_id for h in hits]
        assert "probe_for_read_or_write_added" in rule_ids

    def test_no_hits_on_unchanged(self, rule_engine):
        code = "void func() { int x = 1; }"
        diff_lines = []  # No diff

        hits = rule_engine.evaluate("func", code, code, diff_lines)
        assert len(hits) == 0


class TestSurfaceClassification:
    """Tests for attack surface classification."""

    def test_classify_ioctl(self, rule_engine):
        code = "case IRP_MJ_DEVICE_CONTROL: IoControlCode = stack->Parameters.DeviceIoControl.IoControlCode;"
        surfaces = rule_engine.classify_surface_area(code)
        assert "ioctl" in surfaces

    def test_classify_ndis(self, rule_engine):
        code = "NdisMIndicateReceiveNetBufferLists(adapter, nbl, 0, count, 0);"
        surfaces = rule_engine.classify_surface_area(code)
        assert "ndis" in surfaces

    def test_classify_storage(self, rule_engine):
        code = "StorPortNotification(RequestComplete, hwDevice, srb);"
        surfaces = rule_engine.classify_surface_area(code)
        assert "storage" in surfaces

    def test_classify_unknown(self, rule_engine):
        code = "int x = calculate(a, b);"
        surfaces = rule_engine.classify_surface_area(code)
        assert surfaces == ["unknown"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
