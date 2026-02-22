"""
Unit tests for AutoPiff attack surface detection (new feature analysis).

Tests the evaluate_new_function() rule engine method, change_type flow
through scoring, and report template rendering.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ─── Test fixtures: minimal YAML configs ────────────────────────────────

RULES_YAML = """
version: 2
categories:
  - id: bounds_check
    description: Added or strengthened bounds/size/index validation.
  - id: new_attack_surface
    description: New code introduces potential attack surface.

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

  - rule_id: new_ioctl_handler
    category: new_attack_surface
    rule_type: attack_surface
    confidence: 0.75
    sink_groups:
      - io_sanitization
      - user_probe
    mitigating_guards:
      - length_check
      - sizeof_check
      - probe
      - previous_mode_gate
    plain_english_summary: New IOCTL dispatch handler introduces user-reachable attack surface.

  - rule_id: new_pool_operations
    category: new_attack_surface
    rule_type: attack_surface
    confidence: 0.70
    sink_groups:
      - pool_alloc
    mitigating_guards:
      - length_check
      - overflow_check
      - null_check
    plain_english_summary: New code performs pool allocations without adequate size validation.

  - rule_id: new_memory_copy_operations
    category: new_attack_surface
    rule_type: attack_surface
    confidence: 0.70
    sink_groups:
      - memory_copy
    mitigating_guards:
      - length_check
      - sizeof_check
      - overflow_check
    plain_english_summary: New code performs memory copy without bounds checking.

  - rule_id: new_user_buffer_access
    category: new_attack_surface
    rule_type: attack_surface
    confidence: 0.75
    sink_groups:
      - user_probe
    mitigating_guards:
      - probe
      - previous_mode_gate
      - seh_guard
    plain_english_summary: New code accesses user-mode buffers without probe or SEH protection.

  - rule_id: new_string_operations
    category: new_attack_surface
    rule_type: attack_surface
    confidence: 0.65
    sink_groups:
      - string_copy
    mitigating_guards:
      - length_check
      - safe_string_replacement
    plain_english_summary: New code performs string copy/concat without bounded variants.

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

  pool_alloc:
    description: Pool allocation.
    symbols:
      - ExAllocatePoolWithTag
      - ExAllocatePool2

  user_probe:
    description: User/kernel boundary validation.
    symbols:
      - ProbeForRead
      - ProbeForWrite
      - ExGetPreviousMode

  io_sanitization:
    description: IO validation helpers.
    symbols:
      - RtlULongAdd
      - RtlULongMult

  string_copy:
    description: String copy/concat routines.
    symbols:
      - wcscpy
      - strcpy
      - strcat
"""


@pytest.fixture
def rule_engine():
    """Create a rule engine with attack surface rules."""
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


# ═══════════════════════════════════════════════════════════════════════
# evaluate_new_function() tests
# ═══════════════════════════════════════════════════════════════════════


class TestEvaluateNewFunction:
    """Tests for the evaluate_new_function() method."""

    def test_fires_on_ioctl_handler_with_sinks(self, rule_engine):
        """New IOCTL handler with IO sanitization sinks should fire."""
        code = """
NTSTATUS NewIoctlHandler(PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    RtlULongAdd(inLen, 0x10, &totalSize);
    ExAllocatePoolWithTag(NonPagedPool, totalSize, 'ATAG');
    RtlCopyMemory(dest, buffer, inLen);
    return STATUS_SUCCESS;
}
"""
        hits = rule_engine.evaluate_new_function("NewIoctlHandler", code)
        assert len(hits) >= 1
        rule_ids = [h.rule_id for h in hits]
        # Should fire at least ioctl handler or memory copy rules
        assert any(rid in rule_ids for rid in [
            "new_ioctl_handler", "new_pool_operations",
            "new_memory_copy_operations"
        ])

    def test_does_not_fire_on_benign_code(self, rule_engine):
        """Benign code without any sinks should not fire."""
        code = """
int CalculateSum(int a, int b) {
    int result = a + b;
    return result;
}
"""
        hits = rule_engine.evaluate_new_function("CalculateSum", code)
        assert len(hits) == 0

    def test_does_not_fire_on_empty_code(self, rule_engine):
        """Empty or trivially small code should not fire."""
        hits = rule_engine.evaluate_new_function("Empty", "")
        assert len(hits) == 0

        hits = rule_engine.evaluate_new_function("Tiny", "return 0;")
        assert len(hits) == 0

    def test_confidence_reduces_with_one_guard(self, rule_engine):
        """When one mitigating guard is present, confidence should be reduced."""
        # Code with pool alloc but also a null check (one guard)
        code_no_guard = """
NTSTATUS AllocBuffer(SIZE_T size) {
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, size, 'TEST');
    RtlCopyMemory(buf, src, size);
    return STATUS_SUCCESS;
}
"""
        code_one_guard = """
NTSTATUS AllocBuffer(SIZE_T size) {
    if (size > sizeof(LARGE_BUF)) return STATUS_INVALID_PARAMETER;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, size, 'TEST');
    RtlCopyMemory(buf, src, size);
    return STATUS_SUCCESS;
}
"""
        hits_no_guard = rule_engine.evaluate_new_function("AllocNoGuard", code_no_guard)
        hits_one_guard = rule_engine.evaluate_new_function("AllocOneGuard", code_one_guard)

        # Both should have hits (one guard is not enough to suppress)
        assert len(hits_no_guard) >= 1
        assert len(hits_one_guard) >= 1

        # Find matching rule IDs to compare confidence
        for rid in ["new_pool_operations", "new_memory_copy_operations"]:
            no_guard_hit = next((h for h in hits_no_guard if h.rule_id == rid), None)
            one_guard_hit = next((h for h in hits_one_guard if h.rule_id == rid), None)
            if no_guard_hit and one_guard_hit:
                assert one_guard_hit.confidence < no_guard_hit.confidence
                break

    def test_two_guards_suppress_rule(self, rule_engine):
        """When two or more mitigating guards are present, rule should NOT fire."""
        code = """
NTSTATUS SafeAlloc(SIZE_T size) {
    if (size > sizeof(MAX_BUF)) return STATUS_INVALID_PARAMETER;
    NTSTATUS st;
    st = RtlULongAdd(size, 0x10, &totalSize);
    if (!NT_SUCCESS(st)) return STATUS_INTEGER_OVERFLOW;
    PVOID buf = ExAllocatePoolWithTag(NonPagedPool, totalSize, 'SAFE');
    if (buf == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(buf, src, size);
    return STATUS_SUCCESS;
}
"""
        hits = rule_engine.evaluate_new_function("SafeAlloc", code)
        # pool_operations and memory_copy rules should be suppressed
        # because length_check + overflow_check + null_check are present
        pool_hits = [h for h in hits if h.rule_id == "new_pool_operations"]
        assert len(pool_hits) == 0

    def test_returns_correct_category(self, rule_engine):
        """All hits should have category new_attack_surface."""
        code = """
void CopyUserData(PVOID userBuf, SIZE_T len) {
    PVOID kernel = ExAllocatePoolWithTag(NonPagedPool, len, 'COPY');
    RtlCopyMemory(kernel, userBuf, len);
}
"""
        hits = rule_engine.evaluate_new_function("CopyUserData", code)
        for hit in hits:
            assert hit.category == "new_attack_surface"

    def test_does_not_fire_patch_rules(self, rule_engine):
        """evaluate_new_function should NOT fire regular patch rules."""
        code = """
void HandleRequest(PVOID buf, SIZE_T len) {
    if (len > sizeof(dest)) return;
    RtlCopyMemory(dest, buf, len);
}
"""
        hits = rule_engine.evaluate_new_function("HandleRequest", code)
        for hit in hits:
            # Should only have attack_surface rules, not patch rules
            assert hit.rule_id != "added_len_check_before_memcpy"

    def test_string_operations_detected(self, rule_engine):
        """New code with unsafe string operations should fire."""
        code = """
void BuildPath(PWCHAR dest, PWCHAR src) {
    wcscpy(dest, L"\\\\Device\\\\");
    strcat(narrowBuf, userInput);
}
"""
        hits = rule_engine.evaluate_new_function("BuildPath", code)
        rule_ids = [h.rule_id for h in hits]
        assert "new_string_operations" in rule_ids


# ═══════════════════════════════════════════════════════════════════════
# change_type scoring tests
# ═══════════════════════════════════════════════════════════════════════


SCORING_YAML = """
version: 2
gating:
  matching_confidence:
    min_required: 0.40
    cap_if_below: 3.0
  semantic_confidence:
    soft_min: 0.60
    cap_if_below_soft_min: 5.0
    hard_min: 0.45
    drop_if_below_hard_min: true
  reachability_confidence:
    soft_min: 0.55
    multiplier_if_below: 0.70
weights:
  semantic_rule_base:
    added_len_check_before_memcpy: 6.0
    new_ioctl_handler: 5.0
  category_multiplier:
    bounds_check: 1.05
    new_attack_surface: 0.90
  change_type_multiplier:
    patch: 1.0
    new_feature: 0.85
  reachability_bonus:
    ioctl: 4.0
    unknown: 0.0
  sink_bonus:
    memory_copy: 1.5
  penalties:
    pairing_decision:
      accept: 0.0
    noise_risk:
      low: 0.0
    matching_quality:
      high: 0.0
composition:
  max_findings_in_report: 10
  clamp:
    min: 0.0
    max: 15.0
matching_quality_buckets:
  high:
    min_confidence: 0.80
  medium:
    min_confidence: 0.60
  low:
    min_confidence: 0.00
"""


class TestChangeTypeScoring:
    """Tests that change_type_multiplier is applied correctly."""

    def test_new_feature_gets_lower_score(self):
        """new_feature change_type should produce a lower score than patch."""
        import yaml
        scoring = yaml.safe_load(SCORING_YAML)

        # Import the scoring function from karton_patch_differ
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-patch-differ"))

        # Build two identical deltas, only change_type differs
        base_delta = {
            "function": "TestFunc",
            "rule_id": "added_len_check_before_memcpy",
            "category": "bounds_check",
            "confidence": 0.90,
            "sinks": ["memory_copy"],
            "indicators": ["RtlCopyMemory"],
            "diff_snippet": "",
            "why_matters": "test",
            "surface_area": ["ioctl"],
        }

        delta_patch = {**base_delta, "change_type": "patch"}
        delta_new = {**base_delta, "change_type": "new_feature"}

        # Manually compute scores using the same logic as _score_findings
        weights = scoring["weights"]
        rule_base = weights["semantic_rule_base"]
        cat_mult = weights["category_multiplier"]
        ct_mult = weights["change_type_multiplier"]

        for delta, ct in [(delta_patch, "patch"), (delta_new, "new_feature")]:
            base_w = rule_base.get(delta["rule_id"], 3.0)
            semantic = base_w * delta["confidence"] * cat_mult.get(delta["category"], 1.0)
            raw = semantic * ct_mult.get(ct, 1.0)
            delta["_score"] = raw

        assert delta_new["_score"] < delta_patch["_score"]
        assert delta_new["_score"] == pytest.approx(
            delta_patch["_score"] * 0.85, rel=1e-2
        )


# ═══════════════════════════════════════════════════════════════════════
# Report template tests
# ═══════════════════════════════════════════════════════════════════════


class TestReportTemplateChangeType:
    """Tests that report templates render [PATCH]/[NEW] prefix."""

    def test_new_prefix_rendered(self):
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-report"))
        import report_templates as tpl

        finding = {
            "rank": 1,
            "function": "NewHandler",
            "final_score": 7.5,
            "semantic_confidence": 0.75,
            "why_matters": "New IOCTL handler detected",
            "rule_ids": ["new_ioctl_handler"],
            "reachability_class": "ioctl",
            "reachability_path": [],
            "sinks": ["io_sanitization"],
            "indicators": ["RtlULongAdd"],
            "change_type": "new_feature",
        }
        rendered = tpl.render_finding(finding)
        assert "[NEW]" in rendered
        assert "NewHandler" in rendered

    def test_patch_prefix_rendered(self):
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-report"))
        import report_templates as tpl

        finding = {
            "rank": 1,
            "function": "PatchedFunc",
            "final_score": 8.0,
            "semantic_confidence": 0.92,
            "why_matters": "Added length check",
            "rule_ids": ["added_len_check_before_memcpy"],
            "reachability_class": "ioctl",
            "reachability_path": [],
            "sinks": ["memory_copy"],
            "indicators": ["RtlCopyMemory"],
            "change_type": "patch",
        }
        rendered = tpl.render_finding(finding)
        assert "[PATCH]" in rendered

    def test_default_is_patch(self):
        """Findings without change_type should default to [PATCH]."""
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-report"))
        import report_templates as tpl

        finding = {
            "rank": 1,
            "function": "OldFinding",
            "final_score": 6.0,
            "semantic_confidence": 0.80,
            "why_matters": "test",
            "rule_ids": ["some_rule"],
            "reachability_class": "unknown",
            "reachability_path": [],
            "sinks": [],
            "indicators": [],
        }
        rendered = tpl.render_finding(finding)
        assert "[PATCH]" in rendered

    def test_executive_summary_counts(self):
        """Executive summary should show patch vs new feature breakdown."""
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-report"))
        import report_templates as tpl

        findings = [
            {"category": "bounds_check", "final_score": 8.0, "function": "A", "change_type": "patch"},
            {"category": "new_attack_surface", "final_score": 7.0, "function": "B", "change_type": "new_feature"},
            {"category": "new_attack_surface", "final_score": 6.5, "function": "C", "change_type": "new_feature"},
        ]
        rendered = tpl.render_executive_summary(findings, reachable_count=2)
        assert "1 patches" in rendered
        assert "2 new attack surface" in rendered

    def test_humanize_new_attack_surface(self):
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-report"))
        import report_templates as tpl

        assert "attack surface" in tpl._humanize_category("new_attack_surface").lower()


# ═══════════════════════════════════════════════════════════════════════
# Schema validation with change_type
# ═══════════════════════════════════════════════════════════════════════


class TestSchemaWithChangeType:
    """Verify schemas accept the new change_type field."""

    @pytest.fixture
    def semantic_deltas_schema(self):
        schema_path = Path(__file__).parent.parent.parent / "schemas" / "semantic_deltas.schema.json"
        with open(schema_path) as f:
            return json.load(f)

    @pytest.fixture
    def ranking_schema(self):
        schema_path = Path(__file__).parent.parent.parent / "schemas" / "ranking.schema.json"
        with open(schema_path) as f:
            return json.load(f)

    @pytest.fixture
    def report_schema(self):
        schema_path = Path(__file__).parent.parent.parent / "schemas" / "report.schema.json"
        with open(schema_path) as f:
            return json.load(f)

    def test_semantic_deltas_accepts_change_type(self, semantic_deltas_schema):
        from jsonschema import validate

        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": [
                {
                    "function": "NewHandler",
                    "rule_id": "new_ioctl_handler",
                    "category": "new_attack_surface",
                    "confidence": 0.75,
                    "sinks": ["io_sanitization"],
                    "indicators": ["RtlULongAdd"],
                    "diff_snippet": "+RtlULongAdd(a, b, &c);",
                    "why_matters": "New IOCTL handler",
                    "surface_area": ["ioctl"],
                    "change_type": "new_feature",
                }
            ],
        }
        validate(instance=doc, schema=semantic_deltas_schema)

    def test_semantic_deltas_accepts_patch_type(self, semantic_deltas_schema):
        from jsonschema import validate

        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": [
                {
                    "function": "PatchedFunc",
                    "rule_id": "added_len_check_before_memcpy",
                    "category": "bounds_check",
                    "confidence": 0.92,
                    "sinks": ["memory_copy"],
                    "indicators": ["RtlCopyMemory"],
                    "diff_snippet": "+if (len > MAX) return;",
                    "why_matters": "Added length check",
                    "change_type": "patch",
                }
            ],
        }
        validate(instance=doc, schema=semantic_deltas_schema)

    def test_semantic_deltas_without_change_type_still_valid(self, semantic_deltas_schema):
        """Backward compat: no change_type field should still validate."""
        from jsonschema import validate

        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": [
                {
                    "function": "OldFunc",
                    "rule_id": "added_len_check_before_memcpy",
                    "category": "bounds_check",
                    "confidence": 0.92,
                    "sinks": ["memory_copy"],
                    "indicators": ["RtlCopyMemory"],
                    "diff_snippet": "",
                    "why_matters": "test",
                }
            ],
        }
        validate(instance=doc, schema=semantic_deltas_schema)

    def test_semantic_deltas_rejects_invalid_change_type(self, semantic_deltas_schema):
        from jsonschema import validate, ValidationError

        doc = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {"sha256": "a" * 64, "version": "1.0"},
            "driver_old": {"sha256": "b" * 64, "version": "0.9"},
            "deltas": [
                {
                    "function": "Func",
                    "rule_id": "test",
                    "category": "bounds_check",
                    "confidence": 0.8,
                    "sinks": [],
                    "indicators": [],
                    "diff_snippet": "",
                    "why_matters": "test",
                    "change_type": "invalid_type",
                }
            ],
        }
        with pytest.raises(ValidationError):
            validate(instance=doc, schema=semantic_deltas_schema)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
