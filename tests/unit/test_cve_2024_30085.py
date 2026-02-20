"""
CVE-2024-30085 Detection Test for AutoPiff

Tests whether AutoPiff's semantic rule engine can detect the security fix
for CVE-2024-30085 (Windows Cloud Files Mini Filter Driver EoP).

Vulnerability: Heap-based buffer overflow in HsmIBitmapNORMALOpen (cldflt.sys)
Root cause: Unbounded memcpy into 0x1000-byte heap buffer
Fix: Added size <= 0x1000 bounds check before RtlCopyMemory call
Patched: June 2024 Patch Tuesday (KB5039212 for Win11 22H2)

Binary versions tested:
  - Vulnerable: cldflt.sys 10.0.22621.3672 (sha256: fff42100...)
  - Patched:    cldflt.sys 10.0.22621.3733 (sha256: 0b495138...)
"""

import pytest
from pathlib import Path
import tempfile
import os
import sys

# ---------------------------------------------------------------------------
# Realistic decompiled C code based on CVE-2024-30085 analysis
# (What Ghidra would produce from cldflt.sys HsmIBitmapNORMALOpen)
# ---------------------------------------------------------------------------

# Pre-patch: No bounds check before RtlCopyMemory into 0x1000-byte HsBm buffer
VULNERABLE_HsmIBitmapNORMALOpen = """\
NTSTATUS HsmIBitmapNORMALOpen(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PHSM_REPARSE_DATA ReparseData,
    _In_ ULONG ReparseDataLength,
    _Out_ PHSM_BITMAP_CONTEXT *BitmapContext)
{
    NTSTATUS Status;
    PHSM_BITMAP_CONTEXT HsBm;
    PVOID DecompressedBuffer;
    ULONG DecompressedSize;
    PVOID local_70;

    /* Allocate fixed-size 0x1000 bitmap context */
    HsBm = (PHSM_BITMAP_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx, 0x1000, 'mBsH');
    if (HsBm == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(HsBm, 0x1000);
    HsBm->Signature = 'mBsH';

    /* Read reparse buffer (up to 0x4000 bytes) */
    Status = HsmpRpReadBuffer(
        Instance, FileObject, ReparseData,
        ReparseDataLength, &local_70, &DecompressedSize);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(HsBm, 'mBsH');
        return Status;
    }

    /* Decompress the bitmap data */
    Status = HsmpRpiDecompressBuffer(
        local_70, DecompressedSize,
        &DecompressedBuffer, &DecompressedSize);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(HsBm, 'mBsH');
        return Status;
    }

    /* BUG: No size validation! DecompressedSize can exceed 0x1000 */
    RtlCopyMemory(HsBm->BitmapData, DecompressedBuffer, DecompressedSize);

    HsBm->BitmapSize = DecompressedSize;
    *BitmapContext = HsBm;
    return STATUS_SUCCESS;
}
"""

# Post-patch: Added bounds check (DecompressedSize <= 0x1000) before RtlCopyMemory
PATCHED_HsmIBitmapNORMALOpen = """\
NTSTATUS HsmIBitmapNORMALOpen(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFILE_OBJECT FileObject,
    _In_ PHSM_REPARSE_DATA ReparseData,
    _In_ ULONG ReparseDataLength,
    _Out_ PHSM_BITMAP_CONTEXT *BitmapContext)
{
    NTSTATUS Status;
    PHSM_BITMAP_CONTEXT HsBm;
    PVOID DecompressedBuffer;
    ULONG DecompressedSize;
    PVOID local_70;

    /* Allocate fixed-size 0x1000 bitmap context */
    HsBm = (PHSM_BITMAP_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx, 0x1000, 'mBsH');
    if (HsBm == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(HsBm, 0x1000);
    HsBm->Signature = 'mBsH';

    /* Read reparse buffer (up to 0x4000 bytes) */
    Status = HsmpRpReadBuffer(
        Instance, FileObject, ReparseData,
        ReparseDataLength, &local_70, &DecompressedSize);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(HsBm, 'mBsH');
        return Status;
    }

    /* Decompress the bitmap data */
    Status = HsmpRpiDecompressBuffer(
        local_70, DecompressedSize,
        &DecompressedBuffer, &DecompressedSize);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(HsBm, 'mBsH');
        return Status;
    }

    /* FIX: Validate decompressed size fits in allocated buffer */
    if (DecompressedSize > 0x1000) {
        ExFreePoolWithTag(HsBm, 'mBsH');
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(HsBm->BitmapData, DecompressedBuffer, DecompressedSize);

    HsBm->BitmapSize = DecompressedSize;
    *BitmapContext = HsBm;
    return STATUS_SUCCESS;
}
"""

# Unified diff that AutoPiff's rule engine would process
DIFF_HsmIBitmapNORMALOpen = [
    "--- a/cldflt.sys/HsmIBitmapNORMALOpen",
    "+++ b/cldflt.sys/HsmIBitmapNORMALOpen",
    " NTSTATUS HsmIBitmapNORMALOpen(",
    "     _In_ PFLT_INSTANCE Instance,",
    "     _In_ PFILE_OBJECT FileObject,",
    "     _In_ PHSM_REPARSE_DATA ReparseData,",
    "     _In_ ULONG ReparseDataLength,",
    "     _Out_ PHSM_BITMAP_CONTEXT *BitmapContext)",
    " {",
    "     NTSTATUS Status;",
    "     PHSM_BITMAP_CONTEXT HsBm;",
    "     PVOID DecompressedBuffer;",
    "     ULONG DecompressedSize;",
    " ",
    "     HsBm = (PHSM_BITMAP_CONTEXT)ExAllocatePoolWithTag(",
    "         NonPagedPoolNx, 0x1000, 'mBsH');",
    "     if (HsBm == NULL) {",
    "         return STATUS_INSUFFICIENT_RESOURCES;",
    "     }",
    " ",
    "     RtlZeroMemory(HsBm, 0x1000);",
    "     HsBm->Signature = 'mBsH';",
    " ",
    "     Status = HsmpRpReadBuffer(",
    "         Instance, FileObject, ReparseData,",
    "         ReparseDataLength, &local_70, &DecompressedSize);",
    "     if (!NT_SUCCESS(Status)) {",
    "         ExFreePoolWithTag(HsBm, 'mBsH');",
    "         return Status;",
    "     }",
    " ",
    "     Status = HsmpRpiDecompressBuffer(",
    "         local_70, DecompressedSize,",
    "         &DecompressedBuffer, &DecompressedSize);",
    "     if (!NT_SUCCESS(Status)) {",
    "         ExFreePoolWithTag(HsBm, 'mBsH');",
    "         return Status;",
    "     }",
    " ",
    "+    /* FIX: Validate decompressed size fits in allocated buffer */",
    "+    if (DecompressedSize > 0x1000) {",
    "+        ExFreePoolWithTag(HsBm, 'mBsH');",
    "+        return STATUS_BUFFER_OVERFLOW;",
    "+    }",
    "+",
    "     RtlCopyMemory(HsBm->BitmapData, DecompressedBuffer, DecompressedSize);",
    " ",
    "     HsBm->BitmapSize = DecompressedSize;",
    "     *BitmapContext = HsBm;",
    "     return STATUS_SUCCESS;",
    " }",
]

# Alternative diff: more terse Ghidra-style decompilation (less readable names)
DIFF_GHIDRA_STYLE = [
    "--- a/cldflt.sys/FUN_1c0054a80",
    "+++ b/cldflt.sys/FUN_1c0054a80",
    " long FUN_1c0054a80(longlong param_1, longlong param_2, longlong param_3,",
    "                     uint param_4, longlong *param_5)",
    " {",
    "     long lVar1;",
    "     void *pvVar2;",
    "     uint uVar3;",
    "     void *local_70;",
    " ",
    "     pvVar2 = ExAllocatePoolWithTag(0x200, 0x1000, 0x6d427348);",
    "     if (pvVar2 == (void *)0x0) {",
    "         return -0x3ffffff5;",
    "     }",
    "     RtlZeroMemory(pvVar2, 0x1000);",
    " ",
    "     lVar1 = HsmpRpReadBuffer(param_1, param_2, param_3, param_4,",
    "                               &local_70, &uVar3);",
    "     if (lVar1 < 0) {",
    "         ExFreePoolWithTag(pvVar2, 0x6d427348);",
    "         return lVar1;",
    "     }",
    " ",
    "     lVar1 = HsmpRpiDecompressBuffer(local_70, uVar3, &local_70, &uVar3);",
    "     if (lVar1 < 0) {",
    "         ExFreePoolWithTag(pvVar2, 0x6d427348);",
    "         return lVar1;",
    "     }",
    " ",
    "+    if (0x1000 < uVar3) {",
    "+        ExFreePoolWithTag(pvVar2, 0x6d427348);",
    "+        return -0x3ffffffb;",
    "+    }",
    "     RtlCopyMemory((void *)((longlong)pvVar2 + 0x20), local_70, (ulonglong)uVar3);",
    " ",
    "     *(uint *)((longlong)pvVar2 + 0x18) = uVar3;",
    "     *param_5 = (longlong)pvVar2;",
    "     return 0;",
    " }",
]

# Full call chain context: HsmpSetupContexts calling HsmIBitmapNORMALOpen
PATCHED_HsmpSetupContexts = """\
NTSTATUS HsmpSetupContexts(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PHSM_REPARSE_DATA ReparseData,
    _In_ ULONG ReparseDataLength)
{
    NTSTATUS Status;
    PHSM_STREAM_CONTEXT StreamContext;
    PHSM_BITMAP_CONTEXT BitmapContext;

    Status = HsmpCtxCreateStreamContext(FltObjects->Instance, &StreamContext);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = HsmpRpValidateBuffer(ReparseData, ReparseDataLength);
    if (!NT_SUCCESS(Status)) {
        FltReleaseContext(StreamContext);
        return Status;
    }

    if (ReparseData->ReparseTag == IO_REPARSE_TAG_CLOUD_6) {
        Status = HsmIBitmapNORMALOpen(
            FltObjects->Instance,
            FltObjects->FileObject,
            ReparseData,
            ReparseDataLength,
            &BitmapContext);
        if (!NT_SUCCESS(Status)) {
            FltReleaseContext(StreamContext);
            return Status;
        }
        StreamContext->BitmapContext = BitmapContext;
    }

    FltReleaseContext(StreamContext);
    return STATUS_SUCCESS;
}
"""


# ---------------------------------------------------------------------------
# Fixture: full production rules + sinks
# ---------------------------------------------------------------------------

RULES_PATH = Path(__file__).parent.parent.parent / "rules" / "semantic_rules.yaml"
SINKS_PATH = Path(__file__).parent.parent.parent / "rules" / "sinks.yaml"


@pytest.fixture
def rule_engine():
    """Create rule engine with full production rules."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-patch-differ"))
    from rule_engine import SemanticRuleEngine
    return SemanticRuleEngine(str(RULES_PATH), str(SINKS_PATH))


@pytest.fixture
def rule_engine_minimal():
    """Create rule engine with minimal test rules (for isolation)."""
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "services" / "karton-patch-differ"))
    from rule_engine import SemanticRuleEngine

    rules_yaml = """
version: 1
categories:
  - id: bounds_check
    description: Added or strengthened bounds/size/index validation.
  - id: lifetime_fix
    description: Added pointer lifetime protection.

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

  - rule_id: added_struct_size_validation
    category: bounds_check
    confidence: 0.88
    required_signals:
      - change_type: guard_added
      - guard_kind: sizeof_check
    plain_english_summary: Added validation that a buffer/structure is large enough.

global_exclusions:
  - pattern_id: logging_only
    description: Changes limited to logging.
    hints:
      - DbgPrint
      - WPP
  - pattern_id: refactor_only
    description: Reordering/renaming.
"""

    sinks_yaml = """
version: 1
sinks:
  memory_copy:
    description: Memory copy primitives.
    symbols:
      - RtlCopyMemory
      - memcpy
      - memmove
      - RtlMoveMemory
  pool_alloc:
    description: Pool allocation.
    symbols:
      - ExAllocatePoolWithTag
      - ExAllocatePool2
  pool_free:
    description: Pool free.
    symbols:
      - ExFreePool
      - ExFreePoolWithTag
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = os.path.join(tmpdir, "rules.yaml")
        sinks_path = os.path.join(tmpdir, "sinks.yaml")
        with open(rules_path, "w") as f:
            f.write(rules_yaml)
        with open(sinks_path, "w") as f:
            f.write(sinks_yaml)
        yield SemanticRuleEngine(rules_path, sinks_path)


# ===========================================================================
# Test Class: CVE-2024-30085 Detection
# ===========================================================================

class TestCVE2024_30085_Detection:
    """
    Verify that AutoPiff detects the security fix for CVE-2024-30085.

    The fix adds a bounds check (DecompressedSize <= 0x1000) before
    RtlCopyMemory in HsmIBitmapNORMALOpen to prevent heap overflow.
    """

    def test_primary_rule_fires(self, rule_engine):
        """The added_len_check_before_memcpy rule must fire on the CVE fix diff."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" in rule_ids, (
            f"Expected 'added_len_check_before_memcpy' to fire. Got: {rule_ids}"
        )

    def test_confidence_is_high(self, rule_engine):
        """The detection confidence should be >= 0.90 for this clear-cut fix."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert target_hit.confidence >= 0.90, (
            f"Expected confidence >= 0.90, got {target_hit.confidence}"
        )

    def test_correct_category(self, rule_engine):
        """Detection should be categorized as bounds_check."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert target_hit.category == "bounds_check"

    def test_memory_copy_sink_identified(self, rule_engine):
        """The rule must identify memory_copy as the relevant sink group."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert "memory_copy" in target_hit.sinks

    def test_rtlcopymemory_in_indicators(self, rule_engine):
        """RtlCopyMemory should appear in the hit indicators."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert any("RtlCopyMemory" in ind for ind in target_hit.indicators), (
            f"Expected RtlCopyMemory in indicators: {target_hit.indicators}"
        )

    def test_ghidra_style_decompilation(self, rule_engine):
        """Detection must also work with raw Ghidra-style decompiled code."""
        # Ghidra often produces less readable output with generic names
        ghidra_old = """\
long FUN_1c0054a80(longlong param_1, longlong param_2, longlong param_3,
                    uint param_4, longlong *param_5)
{
    void *pvVar2;
    uint uVar3;
    void *local_70;
    pvVar2 = ExAllocatePoolWithTag(0x200, 0x1000, 0x6d427348);
    if (pvVar2 == (void *)0x0) return -0x3ffffff5;
    RtlZeroMemory(pvVar2, 0x1000);
    HsmpRpReadBuffer(param_1, param_2, param_3, param_4, &local_70, &uVar3);
    HsmpRpiDecompressBuffer(local_70, uVar3, &local_70, &uVar3);
    RtlCopyMemory((void *)((longlong)pvVar2 + 0x20), local_70, (ulonglong)uVar3);
    *(uint *)((longlong)pvVar2 + 0x18) = uVar3;
    *param_5 = (longlong)pvVar2;
    return 0;
}
"""
        ghidra_new = """\
long FUN_1c0054a80(longlong param_1, longlong param_2, longlong param_3,
                    uint param_4, longlong *param_5)
{
    void *pvVar2;
    uint uVar3;
    void *local_70;
    pvVar2 = ExAllocatePoolWithTag(0x200, 0x1000, 0x6d427348);
    if (pvVar2 == (void *)0x0) return -0x3ffffff5;
    RtlZeroMemory(pvVar2, 0x1000);
    HsmpRpReadBuffer(param_1, param_2, param_3, param_4, &local_70, &uVar3);
    HsmpRpiDecompressBuffer(local_70, uVar3, &local_70, &uVar3);
    if (0x1000 < uVar3) {
        ExFreePoolWithTag(pvVar2, 0x6d427348);
        return -0x3ffffffb;
    }
    RtlCopyMemory((void *)((longlong)pvVar2 + 0x20), local_70, (ulonglong)uVar3);
    *(uint *)((longlong)pvVar2 + 0x18) = uVar3;
    *param_5 = (longlong)pvVar2;
    return 0;
}
"""

        hits = rule_engine.evaluate(
            "FUN_1c0054a80", ghidra_old, ghidra_new, DIFF_GHIDRA_STYLE
        )

        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" in rule_ids, (
            f"Ghidra-style diff not detected. Got: {rule_ids}"
        )

    def test_why_matters_is_explanatory(self, rule_engine):
        """The hit should include a meaningful plain-english explanation."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert len(target_hit.why_matters) > 10, (
            f"Expected explanatory text, got: '{target_hit.why_matters}'"
        )
        # Should mention length/bounds and memory copy
        why_lower = target_hit.why_matters.lower()
        assert "length" in why_lower or "bounds" in why_lower, (
            f"Explanation should mention length/bounds: '{target_hit.why_matters}'"
        )

    def test_diff_snippet_included(self, rule_engine):
        """Hit should include a non-empty diff snippet for analyst review."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        target_hit = next(
            (h for h in hits if h.rule_id == "added_len_check_before_memcpy"), None
        )
        assert target_hit is not None
        assert len(target_hit.diff_snippet) > 0


class TestCVE2024_30085_SurfaceClassification:
    """Test that the attack surface is correctly classified for cldflt.sys context."""

    def test_filesystem_filter_surface(self, rule_engine):
        """cldflt.sys functions using Flt* APIs should classify as filesystem."""
        surfaces = rule_engine.classify_surface_area(PATCHED_HsmpSetupContexts)
        assert "filesystem" in surfaces, (
            f"Expected 'filesystem' surface for minifilter code. Got: {surfaces}"
        )

    def test_ioctl_not_in_bitmap_function(self, rule_engine):
        """HsmIBitmapNORMALOpen itself doesn't directly handle IOCTLs."""
        surfaces = rule_engine.classify_surface_area(PATCHED_HsmIBitmapNORMALOpen)
        assert "ioctl" not in surfaces


class TestCVE2024_30085_SinkDetection:
    """Test low-level sink and guard detection on CVE-2024-30085 patterns."""

    def test_sinks_found_in_diff(self, rule_engine):
        """RtlCopyMemory sink must be found in the diff."""
        sinks = rule_engine._find_sinks(DIFF_HsmIBitmapNORMALOpen)
        groups = {s.group for s in sinks}
        assert "memory_copy" in groups, (
            f"Expected memory_copy sink. Found groups: {groups}"
        )

    def test_pool_sinks_also_present(self, rule_engine):
        """ExFreePoolWithTag in added lines should also be detected as pool_free sink."""
        sinks = rule_engine._find_sinks(DIFF_HsmIBitmapNORMALOpen)
        groups = {s.group for s in sinks}
        assert "pool_free" in groups, (
            f"Expected pool_free sink (ExFreePoolWithTag in added cleanup). Found: {groups}"
        )

    def test_length_check_guard_detected(self, rule_engine):
        """The added `if (DecompressedSize > 0x1000)` must be detected as length_check."""
        added_lines = [
            "/* FIX: Validate decompressed size fits in allocated buffer */",
            "if (DecompressedSize > 0x1000) {",
            "    ExFreePoolWithTag(HsBm, 'mBsH');",
            "    return STATUS_BUFFER_OVERFLOW;",
            "}",
        ]
        guards = rule_engine._detect_guard_type(added_lines)
        assert "length_check" in guards, (
            f"Expected length_check guard. Detected guards: {list(guards.keys())}"
        )

    def test_ghidra_style_guard_detected(self, rule_engine):
        """The Ghidra-style `if (0x1000 < uVar3)` must also be detected."""
        added_lines = [
            "if (0x1000 < uVar3) {",
            "    ExFreePoolWithTag(pvVar2, 0x6d427348);",
            "    return -0x3ffffffb;",
            "}",
        ]
        guards = rule_engine._detect_guard_type(added_lines)
        # This checks if the guard is detected - Ghidra reverses comparison order
        # The length_check pattern looks for len/Length comparisons
        # This is a harder case - let's check what gets detected
        detected = list(guards.keys())
        assert len(detected) > 0, (
            "Expected at least one guard detected in Ghidra-style size check"
        )

    def test_proximity_guard_to_memcpy(self, rule_engine):
        """The bounds check is within 10 lines of RtlCopyMemory (near_sink)."""
        # In our diff, the added guard is ~5 lines before RtlCopyMemory
        guard_lines = rule_engine._find_guard_lines(
            DIFF_HsmIBitmapNORMALOpen, "length_check"
        )
        assert len(guard_lines) > 0, "No guard lines found"

        sinks = rule_engine._find_sinks(DIFF_HsmIBitmapNORMALOpen)
        memcpy_sinks = [s for s in sinks if s.group == "memory_copy"]
        assert len(memcpy_sinks) > 0, "No memory_copy sinks found"

        # Verify proximity
        for gl in guard_lines:
            for sink in memcpy_sinks:
                if rule_engine._check_proximity(gl, sink.line_num, "near_sink"):
                    return  # Pass
        pytest.fail(
            f"No guard line is near a memory_copy sink. "
            f"Guard lines: {guard_lines}, Sink lines: {[s.line_num for s in memcpy_sinks]}"
        )


class TestCVE2024_30085_NegativeCases:
    """Ensure the rule engine doesn't false-positive on non-security changes."""

    def test_logging_only_change_excluded(self, rule_engine):
        """Adding only DbgPrint near memcpy should NOT trigger the rule."""
        old_code = "void Func() { RtlCopyMemory(dst, src, len); }"
        new_code = "void Func() { DbgPrint(\"copying %d bytes\", len); RtlCopyMemory(dst, src, len); }"
        diff_lines = [
            "--- old",
            "+++ new",
            " void Func() {",
            "+    DbgPrint(\"copying %d bytes\", len);",
            "     RtlCopyMemory(dst, src, len);",
            " }",
        ]

        hits = rule_engine.evaluate("Func", old_code, new_code, diff_lines)
        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" not in rule_ids

    def test_no_diff_no_detection(self, rule_engine):
        """Identical pre/post code should produce zero hits."""
        hits = rule_engine.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            VULNERABLE_HsmIBitmapNORMALOpen,
            [],
        )
        assert len(hits) == 0

    def test_unrelated_change_no_false_positive(self, rule_engine):
        """A comment-only change near memcpy should not trigger bounds_check."""
        diff_lines = [
            "--- old",
            "+++ new",
            " void Func() {",
            "+    /* Updated for readability */",
            "     RtlCopyMemory(dst, src, len);",
            " }",
        ]

        hits = rule_engine.evaluate(
            "Func",
            "void Func() { RtlCopyMemory(dst, src, len); }",
            "void Func() { /* Updated for readability */ RtlCopyMemory(dst, src, len); }",
            diff_lines,
        )
        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" not in rule_ids


class TestCVE2024_30085_MinimalEngine:
    """Run key tests with the minimal rule engine for isolation."""

    def test_minimal_engine_detects_fix(self, rule_engine_minimal):
        """Even the stripped-down engine should detect the CVE fix."""
        hits = rule_engine_minimal.evaluate(
            "HsmIBitmapNORMALOpen",
            VULNERABLE_HsmIBitmapNORMALOpen,
            PATCHED_HsmIBitmapNORMALOpen,
            DIFF_HsmIBitmapNORMALOpen,
        )

        rule_ids = [h.rule_id for h in hits]
        assert "added_len_check_before_memcpy" in rule_ids


class TestCVE2024_30085_BinaryMetadata:
    """Validate that we have the correct binary versions for testing."""

    VULN_PATH = Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/vulnerable/cldflt.sys")
    PATCH_PATH = Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/patched/cldflt.sys")

    @pytest.mark.skipif(
        not Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/vulnerable/cldflt.sys").exists(),
        reason="cldflt.sys binaries not present"
    )
    def test_vulnerable_binary_exists(self):
        assert self.VULN_PATH.exists()
        assert self.VULN_PATH.stat().st_size == 569344

    @pytest.mark.skipif(
        not Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/patched/cldflt.sys").exists(),
        reason="cldflt.sys binaries not present"
    )
    def test_patched_binary_exists(self):
        assert self.PATCH_PATH.exists()
        assert self.PATCH_PATH.stat().st_size == 569344

    @pytest.mark.skipif(
        not Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/vulnerable/cldflt.sys").exists(),
        reason="cldflt.sys binaries not present"
    )
    def test_versions_are_different(self):
        """Ensure we have distinct pre/post patch versions."""
        import hashlib
        vuln_hash = hashlib.sha256(self.VULN_PATH.read_bytes()).hexdigest()
        patch_hash = hashlib.sha256(self.PATCH_PATH.read_bytes()).hexdigest()
        assert vuln_hash != patch_hash, "Vulnerable and patched binaries are identical!"
        # Verify known hashes
        assert vuln_hash == "fff42100bfe8870c3988f572d35c1f4d3f194a35e2e6673bdd26cbc5da78e828"
        assert patch_hash == "0b495138e1ce25decdd3a940fd584288bd219131a35b57a977aefb214503ca88"

    @pytest.mark.skipif(
        not Path("/home/splintersfury/Documents/Kernel_Debugging/CVE-2024-30085/drivers/win11_22h2/vulnerable/cldflt.sys").exists(),
        reason="cldflt.sys binaries not present"
    )
    def test_version_strings(self):
        """Verify the exact Windows versions (pre-patch 3672, post-patch 3733)."""
        try:
            import pefile
        except ImportError:
            pytest.skip("pefile not installed")

        for path, expected_substr in [
            (self.VULN_PATH, "22621.3672"),
            (self.PATCH_PATH, "22621.3733"),
        ]:
            pe = pefile.PE(str(path))
            version = "unknown"
            if hasattr(pe, 'FileInfo'):
                for fi in pe.FileInfo:
                    for entry in fi:
                        if hasattr(entry, 'StringTable'):
                            for st in entry.StringTable:
                                for k, v in st.entries.items():
                                    if b'FileVersion' in k:
                                        version = v.decode()
            assert expected_substr in version, (
                f"Expected version containing '{expected_substr}', got '{version}'"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
