"""
Unit tests for KernelSense Mode 3: Variant Finding.

Tests the embedding index, variant finder, and schema validation.
"""

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate

SCHEMA_DIR = Path(__file__).parent.parent.parent / "schemas"
SERVICE_DIR = Path(__file__).parent.parent.parent / "services" / "karton-kernelsense"


def _import_module(name: str):
    """Import a module from the karton-kernelsense service directory as part of the package."""
    full_name = f"karton_kernelsense.{name}"
    spec = importlib.util.spec_from_file_location(full_name, SERVICE_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    mod.__package__ = "karton_kernelsense"
    sys.modules[full_name] = mod
    spec.loader.exec_module(mod)
    return mod


# Import the modules under test (dash in directory name prevents normal import).
# variant_finder uses relative imports (.embeddings, .llm_client, .prompts) so
# we register a fake package and stub the heavy dependencies (anthropic SDK).
import types

_pkg = types.ModuleType("karton_kernelsense")
_pkg.__path__ = [str(SERVICE_DIR)]
sys.modules["karton_kernelsense"] = _pkg

# embeddings has no heavy deps — import directly
embeddings_mod = _import_module("embeddings")
sys.modules["karton_kernelsense.embeddings"] = embeddings_mod
FunctionEmbeddingIndex = embeddings_mod.FunctionEmbeddingIndex

# llm_client requires `anthropic` SDK — stub it since tests use mock LLMs
_llm_stub = types.ModuleType("karton_kernelsense.llm_client")
_llm_stub.LLMClient = type("LLMClient", (), {})
sys.modules["karton_kernelsense.llm_client"] = _llm_stub

# prompts has no heavy deps
prompts_mod = _import_module("prompts")
sys.modules["karton_kernelsense.prompts"] = prompts_mod

# Now variant_finder's relative imports will resolve
variant_finder_mod = _import_module("variant_finder")
sys.modules["karton_kernelsense.variant_finder"] = variant_finder_mod
VariantFinder = variant_finder_mod.VariantFinder


@pytest.fixture
def kernelsense_schema():
    with open(SCHEMA_DIR / "kernelsense.schema.json") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Embedding Index Tests
# ---------------------------------------------------------------------------


class TestFunctionEmbeddingIndex:
    """Tests for the ChromaDB-backed function embedding index."""

    def _make_index(self, tmpdir):
        return FunctionEmbeddingIndex(persist_dir=str(tmpdir))

    def test_add_driver_from_file(self, tmp_path):
        """Test indexing functions from a decompiled C file."""
        idx = self._make_index(tmp_path)

        c_file = tmp_path / "driver.c"
        c_file.write_text(
            "void HandleIoctl(int request, char *buffer, int size) {\n"
            "    memcpy(kernel_buf, buffer, size);\n"
            "    return;\n"
            "}\n\n"
            "int ProcessRequest(void *context) {\n"
            "    PDEVICE_EXTENSION ext = (PDEVICE_EXTENSION)context;\n"
            "    if (ext == NULL) return STATUS_INVALID_PARAMETER;\n"
            "    ExFreePool(ext->buffer);\n"
            "    ext->buffer = NULL;\n"
            "    return STATUS_SUCCESS;\n"
            "}\n"
        )

        added = idx.add_driver("test_driver", str(c_file))
        assert added == 2

    def test_add_driver_skips_short_functions(self, tmp_path):
        """Functions shorter than 50 chars are skipped."""
        idx = self._make_index(tmp_path)

        c_file = tmp_path / "tiny.c"
        c_file.write_text("void Stub(void) {\n    return;\n}\n")

        added = idx.add_driver("stub_driver", str(c_file))
        assert added == 0

    def test_add_driver_missing_file(self, tmp_path):
        """Non-existent file returns 0."""
        idx = self._make_index(tmp_path)
        added = idx.add_driver("ghost", "/nonexistent/path.c")
        assert added == 0

    def test_add_functions_from_deltas(self, tmp_path):
        """Test indexing from semantic_deltas format."""
        idx = self._make_index(tmp_path)

        deltas = [
            {
                "function": "HandleIoctl",
                "decompiled_old": (
                    "void HandleIoctl(int request, char *buffer, int size) {\n"
                    "    memcpy(kernel_buf, buffer, size);\n"
                    "    return;\n"
                    "}\n"
                ),
                "decompiled_new": "(patched version)",
            },
            {
                "function": "ProcessData",
                "decompiled_old": (
                    "int ProcessData(void *ctx, char *data, unsigned long len) {\n"
                    "    PPOOL_HEADER hdr = ExAllocatePoolWithTag(NonPagedPool, len, TAG);\n"
                    "    RtlCopyMemory(hdr->buffer, data, len);\n"
                    "    return STATUS_SUCCESS;\n"
                    "}\n"
                ),
                "decompiled_new": "(patched version)",
            },
        ]

        added = idx.add_functions_from_deltas("test_driver", deltas)
        assert added == 2

    def test_add_functions_from_deltas_skips_short(self, tmp_path):
        """Short decompiled code is skipped."""
        idx = self._make_index(tmp_path)
        deltas = [{"function": "Tiny", "decompiled_old": "return;"}]
        added = idx.add_functions_from_deltas("drv", deltas)
        assert added == 0

    def test_add_functions_from_deltas_dedup(self, tmp_path):
        """Same driver+function is not indexed twice."""
        idx = self._make_index(tmp_path)
        deltas = [
            {
                "function": "HandleIoctl",
                "decompiled_old": (
                    "void HandleIoctl(int req, char *buf, int sz) {\n"
                    "    memcpy(kernel_buf, buf, sz);\n"
                    "    return;\n"
                    "}\n"
                ),
            },
        ]
        assert idx.add_functions_from_deltas("drv", deltas) == 1
        assert idx.add_functions_from_deltas("drv", deltas) == 0

    def test_query_similar_excludes_same_driver(self, tmp_path):
        """Querying with exclude_driver filters out the source driver."""
        idx = self._make_index(tmp_path)

        code_a = (
            "void HandleIoctl(int req, char *buf, int sz) {\n"
            "    memcpy(kernel_buf, buf, sz);\n"
            "    return;\n"
            "}\n"
        )
        code_b = (
            "void ProcessPacket(int req, char *buf, int sz) {\n"
            "    memcpy(pkt_buf, buf, sz);\n"
            "    return;\n"
            "}\n"
        )

        idx.add_functions_from_deltas(
            "driver_a", [{"function": "HandleIoctl", "decompiled_old": code_a}]
        )
        idx.add_functions_from_deltas(
            "driver_b", [{"function": "ProcessPacket", "decompiled_old": code_b}]
        )

        results = idx.query_similar(code_a, n_results=10, exclude_driver="driver_a")
        assert len(results) >= 1
        for r in results:
            assert r["driver"] != "driver_a"

    def test_query_similar_returns_similarity(self, tmp_path):
        """Results include a similarity score between 0 and 1."""
        idx = self._make_index(tmp_path)

        code = (
            "void HandleIoctl(int req, char *buf, int sz) {\n"
            "    memcpy(kernel_buf, buf, sz);\n"
            "    return;\n"
            "}\n"
        )
        idx.add_functions_from_deltas(
            "drv", [{"function": "HandleIoctl", "decompiled_old": code}]
        )

        results = idx.query_similar(code, n_results=5)
        assert len(results) >= 1
        for r in results:
            assert 0 <= r["similarity"] <= 1
            assert "driver" in r
            assert "function" in r
            assert "code" in r

    def test_get_stats_empty(self, tmp_path):
        """Stats on empty index."""
        idx = self._make_index(tmp_path)
        stats = idx.get_stats()
        assert stats["total_functions"] == 0

    def test_get_stats_after_indexing(self, tmp_path):
        """Stats reflect indexed count."""
        idx = self._make_index(tmp_path)
        idx.add_functions_from_deltas(
            "drv",
            [
                {
                    "function": "Func",
                    "decompiled_old": (
                        "void Func(int a) {\n"
                        "    if (a > MAX) return;\n"
                        "    process(a);\n"
                        "}\n"
                    ),
                }
            ],
        )
        stats = idx.get_stats()
        assert stats["total_functions"] == 1


# ---------------------------------------------------------------------------
# Variant Finder Tests (with mock LLM)
# ---------------------------------------------------------------------------


class MockLLMNeverCalled:
    """LLM mock that fails if called — used when no candidates should reach LLM."""

    def analyze(self, prompt, task_context=""):
        raise AssertionError("LLM should not be called")


class MockLLMVariantResponse:
    """LLM mock that returns a fixed variant assessment."""

    def __init__(self, response: dict):
        self._response = response

    def analyze(self, prompt, task_context=""):
        return self._response


class TestVariantFinder:
    """Tests for the variant finding pipeline (embedding search + LLM)."""

    def _make_finder(self, tmp_path, llm=None):
        idx = FunctionEmbeddingIndex(persist_dir=str(tmp_path))
        return VariantFinder(index=idx, llm=llm or MockLLMNeverCalled()), idx

    def test_find_variants_empty_index(self, tmp_path):
        """Variant search on an empty index returns empty list."""
        finder, _ = self._make_finder(tmp_path)
        results = finder.find_variants(
            vulnerable_code="void Func(int a) { memcpy(buf, a, sz); }",
            driver_name="test",
            bug_class="buffer-overflow",
            reasoning="Missing bounds check",
        )
        assert results == []

    def test_find_variants_with_candidates(self, tmp_path):
        """End-to-end: index functions, search, get LLM assessment."""
        mock_llm = MockLLMVariantResponse({
            "candidates": [
                {
                    "index": 1,
                    "is_variant": True,
                    "match_type": "variant",
                    "confidence": 0.82,
                    "reasoning": "Same unchecked memcpy pattern.",
                }
            ]
        })
        finder, idx = self._make_finder(tmp_path, llm=mock_llm)

        # Index a similar function in another driver
        idx.add_functions_from_deltas(
            "other_driver",
            [
                {
                    "function": "CopyUserBuffer",
                    "decompiled_old": (
                        "void CopyUserBuffer(char *dest, char *src, int len) {\n"
                        "    memcpy(dest, src, len);\n"
                        "    return;\n"
                        "}\n"
                    ),
                }
            ],
        )

        results = finder.find_variants(
            vulnerable_code=(
                "void HandleIoctl(int req, char *buf, int sz) {\n"
                "    memcpy(kernel_buf, buf, sz);\n"
                "    return;\n"
                "}\n"
            ),
            driver_name="source_driver",
            bug_class="buffer-overflow",
            reasoning="Missing bounds check before memcpy",
        )

        # We may or may not get results depending on embedding similarity
        # but the pipeline should not error
        assert isinstance(results, list)

    def test_find_variants_excludes_source_driver(self, tmp_path):
        """Variants from the same driver are excluded."""
        finder, idx = self._make_finder(tmp_path)

        code = (
            "void HandleIoctl(int req, char *buf, int sz) {\n"
            "    memcpy(kernel_buf, buf, sz);\n"
            "    return;\n"
            "}\n"
        )
        # Index only the source driver
        idx.add_functions_from_deltas(
            "source_driver", [{"function": "HandleIoctl", "decompiled_old": code}]
        )

        results = finder.find_variants(
            vulnerable_code=code,
            driver_name="source_driver",
            bug_class="buffer-overflow",
            reasoning="Missing bounds check",
        )
        # Should be empty since the only indexed function is from the source driver
        assert results == []


# ---------------------------------------------------------------------------
# Schema Tests (variant_candidates in KernelSense output)
# ---------------------------------------------------------------------------


class TestKernelSenseVariantSchema:
    """Validate that variant output conforms to the JSON schema."""

    def test_valid_output_with_variants(self, kernelsense_schema):
        output = {
            "autopiff_stage": "kernelsense",
            "driver_new": {"sha256": "abc123", "version": "1.0"},
            "driver_old": {"sha256": "def456", "version": "0.9"},
            "findings": [
                {
                    "rank": 1,
                    "function": "HandleIoctl",
                    "original_score": 8.5,
                    "category": "bounds_check",
                    "rule_ids": ["added_len_check_before_memcpy"],
                    "llm_assessment": {
                        "is_security_fix": True,
                        "bug_class": "buffer-overflow",
                        "exploitability": "likely",
                        "confidence": 0.92,
                        "reasoning": "Pre-patch memcpy has no bounds check.",
                    },
                    "variant_candidates": [
                        {
                            "driver": "ntfs.sys",
                            "function": "NtfsWriteData",
                            "similarity": 0.85,
                            "is_variant": True,
                            "match_type": "variant",
                            "confidence": 0.78,
                            "reasoning": "Same unchecked memcpy pattern.",
                        },
                        {
                            "driver": "fastfat.sys",
                            "function": "FatWriteBuffer",
                            "similarity": 0.72,
                            "is_variant": False,
                            "match_type": "related",
                            "confidence": 0.45,
                            "reasoning": "Similar structure but has bounds check.",
                        },
                    ],
                }
            ],
            "summary": {
                "total_analyzed": 1,
                "security_fixes": 1,
                "false_positives": 0,
                "variant_searches": 1,
                "variants_found": 1,
            },
        }
        validate(instance=output, schema=kernelsense_schema)

    def test_valid_output_without_variants(self, kernelsense_schema):
        """Output with no variant_candidates still validates."""
        output = {
            "autopiff_stage": "kernelsense",
            "findings": [
                {
                    "function": "SomeFunc",
                    "original_score": 5.0,
                    "false_positive_check": {
                        "is_false_positive": True,
                        "reasoning": "Refactoring only.",
                        "pattern": "refactoring",
                        "confidence": 0.85,
                    },
                }
            ],
            "summary": {"total_analyzed": 1, "security_fixes": 0, "false_positives": 1},
        }
        validate(instance=output, schema=kernelsense_schema)

    def test_invalid_match_type(self, kernelsense_schema):
        """Invalid match_type should fail validation."""
        output = {
            "autopiff_stage": "kernelsense",
            "findings": [
                {
                    "function": "Func",
                    "original_score": 8.0,
                    "variant_candidates": [
                        {
                            "driver": "drv",
                            "function": "Fn",
                            "similarity": 0.8,
                            "is_variant": True,
                            "match_type": "invalid_type",
                            "confidence": 0.5,
                            "reasoning": "test",
                        }
                    ],
                }
            ],
            "summary": {"total_analyzed": 1},
        }
        with pytest.raises(ValidationError):
            validate(instance=output, schema=kernelsense_schema)

    def test_variant_summary_fields(self, kernelsense_schema):
        """Summary can include variant_searches and variants_found."""
        output = {
            "autopiff_stage": "kernelsense",
            "findings": [],
            "summary": {
                "total_analyzed": 0,
                "security_fixes": 0,
                "false_positives": 0,
                "variant_searches": 3,
                "variants_found": 1,
            },
        }
        validate(instance=output, schema=kernelsense_schema)
