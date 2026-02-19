"""
Unit tests for AutoPiff Stage 6 scoring logic and Stage 7 report templates.

Tests the scoring engine and report templates directly without Karton dependency.
"""

import sys
import json
import pytest
from pathlib import Path
from jsonschema import validate

# ── paths ──────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent.parent
RANKING_DIR = ROOT / "services" / "karton-ranking"
REPORT_DIR = ROOT / "services" / "karton-report"
SCHEMA_DIR = ROOT / "schemas"
SCORING_YAML = ROOT / "rules" / "scoring.yaml"

# Insert service dirs so we can import modules without Karton running
sys.path.insert(0, str(REPORT_DIR))

import yaml
import report_templates as tpl


# ── load scoring config ────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def scoring():
    with open(SCORING_YAML) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def report_schema():
    with open(SCHEMA_DIR / "report.schema.json") as f:
        return json.load(f)


# ── helpers to run scoring logic extracted from karton_ranking.py ──────────
def _score_deltas(deltas, scoring, matching_confidence=0.85, pairing_info=None):
    """
    Replicates RankingKarton._score_and_rank logic standalone.

    Takes a list of merged deltas (each with reachability_class already set),
    the scoring config, and optional pairing/matching overrides.
    Returns (findings, skipped).
    """
    from collections import defaultdict

    if pairing_info is None:
        pairing_info = {"decision": "accept", "noise_risk": "low"}

    weights = scoring.get("weights", {})
    gating = scoring.get("gating", {})
    composition = scoring.get("composition", {})
    quality_buckets = scoring.get("matching_quality_buckets", {})

    rule_base = weights.get("semantic_rule_base", {})
    cat_mult = weights.get("category_multiplier", {})
    reach_bonus_map = weights.get("reachability_bonus", {})
    sink_bonus_map = weights.get("sink_bonus", {})
    penalty_cfg = weights.get("penalties", {})

    clamp_min = composition.get("clamp", {}).get("min", 0.0)
    clamp_max = composition.get("clamp", {}).get("max", 15.0)
    max_findings = composition.get("max_findings_in_report", 10)

    high_min = quality_buckets.get("high", {}).get("min_confidence", 0.80)
    med_min = quality_buckets.get("medium", {}).get("min_confidence", 0.60)
    if matching_confidence >= high_min:
        quality = "high"
    elif matching_confidence >= med_min:
        quality = "medium"
    else:
        quality = "low"

    by_function = defaultdict(list)
    for delta in deltas:
        by_function[delta.get("function", "unknown")].append(delta)

    scored = []
    skipped = []

    for func_name, func_deltas in by_function.items():
        primary = func_deltas[0]
        semantic_confidence = primary.get("confidence", 0.5)

        hard_min = gating.get("semantic_confidence", {}).get("hard_min", 0.45)
        if semantic_confidence < hard_min:
            if gating.get("semantic_confidence", {}).get("drop_if_below_hard_min", True):
                for d in func_deltas:
                    skipped.append({
                        "function": func_name,
                        "rule_id": d.get("rule_id", ""),
                        "reason": f"semantic_confidence {semantic_confidence:.2f} below hard_min {hard_min}",
                    })
                continue

        gates = []
        semantic_breakdown = []
        semantic_total = 0.0
        all_rule_ids = []
        all_sinks = []
        all_indicators = []
        best_category = primary.get("category", "")

        for d in func_deltas:
            rid = d.get("rule_id", "")
            all_rule_ids.append(rid)
            all_sinks.extend(d.get("sinks", []))
            all_indicators.extend(d.get("indicators", []))
            base_w = rule_base.get(rid, 3.0)
            cat_m = cat_mult.get(d.get("category", ""), 1.0)
            contribution = base_w * semantic_confidence * cat_m
            semantic_total += contribution
            semantic_breakdown.append({
                "rule_id": rid,
                "base_weight": base_w,
                "rule_confidence": round(semantic_confidence, 2),
                "contribution": round(contribution, 2),
            })

        all_sinks = list(dict.fromkeys(all_sinks))
        all_indicators = list(dict.fromkeys(all_indicators))

        reach_class = primary.get("reachability_class", "unknown")
        reach_conf = primary.get("reachability_confidence", 0.0)
        reach_bonus = reach_bonus_map.get(reach_class, 0.0)
        reach_total = reach_bonus

        reach_soft_min = gating.get("reachability_confidence", {}).get("soft_min", 0.55)
        if reach_conf < reach_soft_min and reach_class != "unknown":
            mult = gating.get("reachability_confidence", {}).get("multiplier_if_below", 0.70)
            reach_total *= mult
            gates.append(f"reachability_confidence_below_{reach_soft_min}")

        sink_breakdown = []
        sink_total = 0.0
        for sink in all_sinks:
            bonus = sink_bonus_map.get(sink, 0.0)
            contribution = bonus * min(1.0, semantic_confidence)
            sink_total += contribution
            if bonus > 0:
                sink_breakdown.append({
                    "sink_group": sink,
                    "bonus": bonus,
                    "contribution": round(contribution, 2),
                })

        penalty_breakdown = []
        penalty_total = 0.0
        pair_decision = pairing_info.get("decision", "accept")
        pair_pen = penalty_cfg.get("pairing_decision", {}).get(pair_decision, 0.0)
        if pair_pen > 0:
            penalty_total += pair_pen
            penalty_breakdown.append({"type": "pairing_decision", "value": pair_pen})

        noise_risk = pairing_info.get("noise_risk", "low")
        noise_pen = penalty_cfg.get("noise_risk", {}).get(noise_risk, 0.0)
        if noise_pen > 0:
            penalty_total += noise_pen
            penalty_breakdown.append({"type": "noise_risk", "value": noise_pen})

        quality_pen = penalty_cfg.get("matching_quality", {}).get(quality, 0.0)
        if quality_pen > 0:
            penalty_total += quality_pen
            penalty_breakdown.append({"type": "matching_quality", "value": quality_pen})

        raw = semantic_total + reach_total + sink_total - penalty_total
        clamped = max(clamp_min, min(clamp_max, raw))

        match_min_req = gating.get("matching_confidence", {}).get("min_required", 0.40)
        match_cap = gating.get("matching_confidence", {}).get("cap_if_below", 3.0)
        if matching_confidence < match_min_req and clamped > match_cap:
            clamped = match_cap
            gates.append(f"matching_confidence_cap_{match_cap}")

        soft_min = gating.get("semantic_confidence", {}).get("soft_min", 0.60)
        soft_cap = gating.get("semantic_confidence", {}).get("cap_if_below_soft_min", 5.0)
        if semantic_confidence < soft_min and clamped > soft_cap:
            clamped = soft_cap
            gates.append(f"semantic_confidence_cap_{soft_cap}")

        finding = {
            "rank": 0,
            "function": func_name,
            "final_score": round(clamped, 2),
            "rule_ids": all_rule_ids,
            "category": best_category,
            "semantic_confidence": round(semantic_confidence, 2),
            "matching_confidence": round(matching_confidence, 2),
            "reachability_class": reach_class,
            "reachability_confidence": round(reach_conf, 2),
            "reachability_path": primary.get("reachability_path", []),
            "sinks": all_sinks,
            "indicators": all_indicators,
            "why_matters": primary.get("why_matters", ""),
            "diff_snippet": primary.get("diff_snippet", ""),
            "penalties_applied": penalty_breakdown,
            "score_breakdown": {
                "semantic": semantic_breakdown,
                "reachability": {
                    "class": reach_class,
                    "bonus": reach_bonus,
                    "confidence": round(reach_conf, 2),
                    "contribution": round(reach_total, 2),
                },
                "sinks": sink_breakdown,
                "penalties": penalty_breakdown,
                "final": {
                    "total_before_clamp": round(raw, 2),
                    "total_after_clamp": round(clamped, 2),
                    "gates_triggered": gates,
                },
            },
        }
        scored.append(finding)

    scored.sort(key=lambda x: x["final_score"], reverse=True)
    top = scored[:max_findings]
    for i, finding in enumerate(top, 1):
        finding["rank"] = i

    for extra in scored[max_findings:]:
        skipped.append({
            "function": extra["function"],
            "rule_id": extra["rule_ids"][0] if extra["rule_ids"] else "",
            "reason": f"ranked #{scored.index(extra)+1}, outside top {max_findings}",
        })

    return top, skipped


def _make_delta(function, rule_id, category="bounds_check", confidence=0.90,
                reachability_class="unknown", reachability_confidence=0.0,
                sinks=None, indicators=None):
    """Build a minimal delta entry."""
    return {
        "function": function,
        "rule_id": rule_id,
        "category": category,
        "confidence": confidence,
        "reachability_class": reachability_class,
        "reachability_confidence": reachability_confidence,
        "reachability_path": [],
        "sinks": sinks or [],
        "indicators": indicators or [],
        "why_matters": "",
        "diff_snippet": "",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Scoring logic tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRuleStacking:
    """Two rules on the same function should score higher than one rule."""

    def test_two_rules_beat_one(self, scoring):
        one_rule = [_make_delta("FuncA", "added_len_check_before_memcpy")]
        two_rules = [
            _make_delta("FuncA", "added_len_check_before_memcpy"),
            _make_delta("FuncA", "added_struct_size_validation"),
        ]
        (f1,), _ = _score_deltas(one_rule, scoring)
        (f2,), _ = _score_deltas(two_rules, scoring)
        assert f2["final_score"] > f1["final_score"]


class TestReachabilityBonus:
    """Reachability class ordering: ioctl > irp > internal > unknown."""

    def test_ordering(self, scoring):
        scores = {}
        for cls in ("ioctl", "irp", "internal", "unknown"):
            deltas = [_make_delta(
                f"Func_{cls}", "added_len_check_before_memcpy",
                reachability_class=cls, reachability_confidence=0.90,
            )]
            (f,), _ = _score_deltas(deltas, scoring)
            scores[cls] = f["final_score"]
        assert scores["ioctl"] > scores["irp"]
        assert scores["irp"] > scores["internal"]
        assert scores["internal"] > scores["unknown"]


class TestSemanticConfidenceGates:
    """Semantic confidence gating behaviour."""

    def test_hard_min_drops_finding(self, scoring):
        """Confidence below hard_min (0.45) → finding dropped entirely."""
        deltas = [_make_delta("FuncLow", "added_len_check_before_memcpy", confidence=0.40)]
        findings, skipped = _score_deltas(deltas, scoring)
        assert len(findings) == 0
        assert len(skipped) == 1
        assert "hard_min" in skipped[0]["reason"]

    def test_soft_min_caps_score(self, scoring):
        """Confidence below soft_min (0.60) → score capped at 5.0."""
        deltas = [_make_delta(
            "FuncMed", "added_len_check_before_memcpy",
            confidence=0.55, reachability_class="ioctl", reachability_confidence=0.90,
            sinks=["memory_copy"],
        )]
        (f,), _ = _score_deltas(deltas, scoring)
        assert f["final_score"] <= 5.0
        assert "semantic_confidence_cap_5.0" in f["score_breakdown"]["final"]["gates_triggered"]


class TestMatchingConfidenceGate:
    """Matching confidence gating behaviour."""

    def test_low_matching_caps_score(self, scoring):
        """Matching confidence below min (0.40) → score capped at 3.0."""
        deltas = [_make_delta(
            "FuncMatch", "added_len_check_before_memcpy",
            confidence=0.90, reachability_class="ioctl", reachability_confidence=0.90,
        )]
        (f,), _ = _score_deltas(deltas, scoring, matching_confidence=0.35)
        assert f["final_score"] <= 3.0
        assert "matching_confidence_cap_3.0" in f["score_breakdown"]["final"]["gates_triggered"]


class TestScoreClamping:
    """Raw score above 15 should be clamped to 15.0."""

    def test_clamp_to_max(self, scoring):
        # Stack many high-weight rules on an ioctl-reachable function
        deltas = [
            _make_delta("FuncHuge", "added_len_check_before_memcpy",
                        confidence=1.0, reachability_class="ioctl",
                        reachability_confidence=1.0, sinks=["memory_copy"]),
            _make_delta("FuncHuge", "probe_for_read_or_write_added",
                        category="user_boundary_check", confidence=1.0,
                        reachability_class="ioctl", reachability_confidence=1.0,
                        sinks=["user_probe"]),
            _make_delta("FuncHuge", "access_mode_enforcement_added",
                        category="authorization", confidence=1.0,
                        reachability_class="ioctl", reachability_confidence=1.0,
                        sinks=["authorization"]),
        ]
        (f,), _ = _score_deltas(deltas, scoring)
        assert f["final_score"] == 15.0
        assert f["score_breakdown"]["final"]["total_before_clamp"] > 15.0


class TestPenalties:
    """Quarantine pairing decision applies a 2.0 penalty."""

    def test_quarantine_penalty(self, scoring):
        deltas_accept = [_make_delta("FuncP", "added_len_check_before_memcpy")]
        deltas_quarantine = [_make_delta("FuncP", "added_len_check_before_memcpy")]

        (fa,), _ = _score_deltas(deltas_accept, scoring,
                                 pairing_info={"decision": "accept", "noise_risk": "low"})
        (fq,), _ = _score_deltas(deltas_quarantine, scoring,
                                 pairing_info={"decision": "quarantine", "noise_risk": "low"})
        assert fa["final_score"] - fq["final_score"] == pytest.approx(2.0, abs=0.01)
        assert any(p["type"] == "pairing_decision" and p["value"] == 2.0
                    for p in fq["penalties_applied"])


class TestTopNLimit:
    """12 functions should yield 10 findings + 2 skipped."""

    def test_top_10_and_skipped(self, scoring):
        deltas = [
            _make_delta(f"Func{i:02d}", "added_len_check_before_memcpy", confidence=0.90)
            for i in range(12)
        ]
        findings, skipped = _score_deltas(deltas, scoring)
        assert len(findings) == 10
        # The 2 extra go to skipped
        overflow_skipped = [s for s in skipped if "outside top" in s.get("reason", "")]
        assert len(overflow_skipped) == 2


class TestReachabilityMerge:
    """_merge_reachability replaces surface_area with real reachability tags."""

    def test_merge_replaces_heuristics(self):
        # Simulate what _merge_reachability does
        sys.path.insert(0, str(RANKING_DIR))
        # Import function indirectly by reading the module without Karton
        # We can test the merge logic inline
        semantic_deltas = {
            "deltas": [
                {"function": "HandleIoctl", "surface_area": ["ioctl"]},
                {"function": "InternalHelper", "surface_area": ["internal"]},
            ]
        }
        reach_lookup = {
            "HandleIoctl": {
                "reachability_class": "ioctl",
                "confidence": 0.95,
                "paths": [["IRP_MJ_DEVICE_CONTROL", "HandleIoctl"]],
            },
        }
        # Replicate merge logic
        merged = []
        for delta in semantic_deltas["deltas"]:
            d = dict(delta)
            func = d.get("function", "")
            reach_info = reach_lookup.get(func)
            if reach_info:
                d["reachability_class"] = reach_info["reachability_class"]
                d["reachability_confidence"] = reach_info["confidence"]
                d["reachability_path"] = (
                    reach_info["paths"][0] if reach_info["paths"] else []
                )
            else:
                d["reachability_class"] = "unknown"
                d["reachability_confidence"] = 0.0
                d["reachability_path"] = []
            merged.append(d)

        assert merged[0]["reachability_class"] == "ioctl"
        assert merged[0]["reachability_confidence"] == 0.95
        assert merged[0]["reachability_path"] == ["IRP_MJ_DEVICE_CONTROL", "HandleIoctl"]
        assert merged[1]["reachability_class"] == "unknown"
        assert merged[1]["reachability_confidence"] == 0.0


# ═══════════════════════════════════════════════════════════════════════════
# Report template tests
# ═══════════════════════════════════════════════════════════════════════════


class TestRenderHeader:
    """render_header outputs driver name, versions, and pairing info."""

    def test_contains_driver_info(self):
        header = tpl.render_header(
            "cldflt.sys", "x64",
            {"sha256": "b" * 64, "version": "10.0.0"},
            {"sha256": "a" * 64, "version": "10.0.1"},
            {"decision": "accept", "noise_risk": "low", "confidence": 0.85},
        )
        assert "cldflt.sys" in header
        assert "x64" in header
        assert "10.0.0" in header
        assert "10.0.1" in header
        assert "accept" in header
        assert "0.85" in header


class TestRenderExecutiveSummary:
    """Executive summary varies based on findings count."""

    def test_zero_findings(self):
        summary = tpl.render_executive_summary([], 0)
        assert "No findings" in summary
        assert "0 security-relevant" in summary

    def test_with_findings(self):
        findings = [
            {"function": "HandleIoctl", "final_score": 8.5, "category": "bounds_check"},
            {"function": "ProcessPnP", "final_score": 5.0, "category": "bounds_check"},
        ]
        summary = tpl.render_executive_summary(findings, 1)
        assert "Bounds check" in summary
        assert "HandleIoctl" in summary
        assert "Recommended starting point" in summary


class TestRenderFinding:
    """render_finding contains all required sections."""

    def test_contains_all_sections(self):
        finding = {
            "rank": 1,
            "function": "HandleIoctl",
            "final_score": 8.45,
            "semantic_confidence": 0.92,
            "rule_ids": ["added_len_check_before_memcpy"],
            "reachability_class": "ioctl",
            "reachability_path": ["IRP_MJ_DEVICE_CONTROL", "HandleIoctl"],
            "sinks": ["memory_copy"],
            "indicators": ["RtlCopyMemory"],
            "why_matters": "Added length check before memcpy",
            "diff_snippet": "+  if (len > MAX) return;",
        }
        rendered = tpl.render_finding(finding)
        assert "Why this matters" in rendered
        assert "What changed" in rendered
        assert "Reachability" in rendered
        assert "Key Indicators" in rendered
        assert "HandleIoctl" in rendered
        assert "memory_copy" in rendered
        assert "RtlCopyMemory" in rendered


class TestRenderSkipped:
    """render_skipped lists function and reason."""

    def test_skipped_entries(self):
        skipped = [
            {"function": "DriverEntry", "reason": "below hard_min"},
            {"function": "InternalHelper", "reason": "outside top 10"},
        ]
        rendered = tpl.render_skipped(skipped)
        assert "DriverEntry" in rendered
        assert "below hard_min" in rendered
        assert "InternalHelper" in rendered

    def test_empty_skipped(self):
        rendered = tpl.render_skipped([])
        assert "No changes were skipped" in rendered


class TestHumanizeCategory:
    """_humanize_category covers all 22 categories."""

    EXPECTED = {
        "bounds_check": "Bounds check added before memory operation",
        "lifetime_fix": "Object lifetime / use-after-free fix",
        "user_boundary_check": "User/kernel boundary validation added",
        "int_overflow": "Integer overflow protection added",
        "state_hardening": "State management hardening",
        "race_condition": "Race condition mitigation",
        "type_confusion": "Type confusion prevention",
        "authorization": "Authorization check added",
        "info_disclosure": "Information disclosure prevention",
        "ioctl_hardening": "IOCTL handler hardening",
        "mdl_handling": "MDL handling safety improvement",
        "object_management": "Object reference management fix",
        "string_handling": "Safe string handling",
        "pool_hardening": "Memory pool safety improvement",
        "crypto_hardening": "Cryptographic operation hardening",
        "error_path_hardening": "Error path cleanup improvement",
        "dos_hardening": "Denial of service prevention",
        "ndis_hardening": "NDIS driver hardening",
        "filesystem_filter": "Filesystem filter safety improvement",
        "pnp_power": "PnP/Power management fix",
        "dma_mmio": "DMA/MMIO bounds validation",
        "wdf_hardening": "WDF framework safety improvement",
    }

    @pytest.mark.parametrize("category,expected", EXPECTED.items())
    def test_category(self, category, expected):
        assert tpl._humanize_category(category) == expected

    def test_unknown_category_fallback(self):
        result = tpl._humanize_category("some_new_category")
        assert result == "Some new category"


# ═══════════════════════════════════════════════════════════════════════════
# JSON report generation test
# ═══════════════════════════════════════════════════════════════════════════


class TestGenerateJsonReport:
    """_generate_json_report output validates against report schema."""

    def test_findings_transform(self, report_schema):
        """final_score → score, indicators → added_checks in report output."""
        # Build a ranking-style finding (what Stage 6 produces)
        ranking_finding = {
            "rank": 1,
            "function": "HandleIoctl",
            "final_score": 8.45,
            "rule_ids": ["added_len_check_before_memcpy"],
            "category": "bounds_check",
            "semantic_confidence": 0.92,
            "matching_confidence": 0.85,
            "reachability_class": "ioctl",
            "reachability_confidence": 0.95,
            "reachability_path": ["IRP_MJ_DEVICE_CONTROL"],
            "sinks": ["memory_copy"],
            "indicators": ["RtlCopyMemory", "InputBufferLength"],
            "why_matters": "Added length check",
            "diff_snippet": "+  if (len > MAX) return;",
            "penalties_applied": [],
            "score_breakdown": {
                "semantic": [], "reachability": {"class": "ioctl", "bonus": 4.0,
                "confidence": 0.95, "contribution": 4.0},
                "sinks": [], "penalties": [],
                "final": {"total_before_clamp": 8.45, "total_after_clamp": 8.45,
                          "gates_triggered": []},
            },
        }

        # Replicate _generate_json_report transform
        findings = [ranking_finding]
        driver_old = {"sha256": "b" * 64, "version": "10.0.0"}
        driver_new = {"sha256": "a" * 64, "version": "10.0.1"}
        pairing_info = {"decision": "accept", "noise_risk": "low", "confidence": 0.85}

        categories = [f.get("category", "") for f in findings]
        unique_cats = list(dict.fromkeys(categories))
        reachable_count = sum(
            1 for f in findings if f.get("reachability_class", "unknown") != "unknown"
        )

        report_findings = []
        for f in findings:
            report_findings.append({
                "rank": f.get("rank", 0),
                "function": f.get("function", ""),
                "score": f.get("final_score", 0.0),
                "confidence": f.get("semantic_confidence", 0.0),
                "rule_ids": f.get("rule_ids", []),
                "category": f.get("category", ""),
                "reachability": {
                    "class": f.get("reachability_class", "unknown"),
                    "path": f.get("reachability_path", []),
                },
                "sinks": f.get("sinks", []),
                "added_checks": f.get("indicators", []),
                "why": f.get("why_matters", ""),
            })

        report = {
            "autopiff_stage": "report",
            "driver": {
                "name": "cldflt.sys",
                "arch": "x64",
                "old": driver_old,
                "new": driver_new,
            },
            "pairing": pairing_info,
            "summary": {
                "total_findings": len(findings),
                "reachable_findings": reachable_count,
                "top_categories": unique_cats[:5],
            },
            "findings": report_findings,
            "skipped": [],
            "metadata": {
                "autopiff_version": "0.6.0",
                "generated_at": "2026-01-15T12:00:00+00:00",
            },
        }

        # Must validate against the report schema
        validate(instance=report, schema=report_schema)

        # Verify transform: final_score → score, indicators → added_checks
        rf = report["findings"][0]
        assert rf["score"] == 8.45
        assert rf["added_checks"] == ["RtlCopyMemory", "InputBufferLength"]
        assert rf["reachability"]["class"] == "ioctl"
        assert "final_score" not in rf
        assert "indicators" not in rf


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
