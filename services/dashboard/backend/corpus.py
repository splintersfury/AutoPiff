"""Corpus status reader for the AutoPiff dashboard.

Reads the CVE validation corpus manifest, scans the corpus directory to
determine per-CVE status (pending / downloaded / decompiled / evaluated),
and optionally loads cached evaluation results.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .models import (
    CategoryMetrics,
    ConfidenceStats,
    CorpusOverview,
    CorpusStatus,
    CVECorpusEntry,
    DetectionDetail,
    DetectionRates,
    UnexpectedHit,
)

logger = logging.getLogger(__name__)


def _determine_status(cve_dir: Path, cve_id: str) -> CorpusStatus:
    """Determine the pipeline status for a single CVE based on filesystem state."""
    eval_cache = cve_dir / "cache" / "eval_result.json"
    if eval_cache.exists():
        return CorpusStatus.evaluated

    vuln_c = cve_dir / "cache" / "vuln.c"
    fix_c = cve_dir / "cache" / "fix.c"
    if vuln_c.exists() and fix_c.exists():
        return CorpusStatus.decompiled

    # Check if any binary exists in vuln/ or fix/
    vuln_dir = cve_dir / "vuln"
    fix_dir = cve_dir / "fix"
    has_vuln = vuln_dir.is_dir() and any(vuln_dir.iterdir())
    has_fix = fix_dir.is_dir() and any(fix_dir.iterdir())
    if has_vuln and has_fix:
        return CorpusStatus.downloaded

    return CorpusStatus.pending


def _load_eval_cache(cve_dir: Path) -> Optional[dict]:
    """Load cached evaluation result if it exists."""
    eval_cache = cve_dir / "cache" / "eval_result.json"
    if not eval_cache.exists():
        return None
    try:
        return json.loads(eval_cache.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to read eval cache %s: %s", eval_cache, exc)
        return None


def _build_detection_details(
    cve_entry: dict, cached: Optional[dict]
) -> list[DetectionDetail]:
    """Build DetectionDetail list from manifest expectations + eval cache."""
    expected = cve_entry.get("expected_detections", [])
    detection_results = cached.get("detection_results", []) if cached else []
    details: list[DetectionDetail] = []

    for i, exp in enumerate(expected):
        detail = DetectionDetail(
            function_pattern=exp.get("function_pattern", ""),
            expected_category=exp.get("expected_categories", [""])[0] if exp.get("expected_categories") else "",
            expected_rules=exp.get("expected_rules", []),
            min_confidence=exp.get("min_confidence", 0.0),
        )

        # Match against eval results by index (corpus evaluator preserves order)
        if i < len(detection_results):
            result = detection_results[i]
            detail.matched_function = result.get("matched_function")
            # metrics.py writes matched_category/matched_rule/matched_confidence
            detail.actual_category = result.get("matched_category")
            detail.actual_rule = result.get("matched_rule")
            detail.actual_confidence = result.get("matched_confidence")
            detail.is_tp = result.get("is_tp", False)

        details.append(detail)

    return details


def _build_unexpected_hits(cached: Optional[dict]) -> list[UnexpectedHit]:
    """Extract unexpected hits (false positives) from eval cache."""
    if not cached:
        return []
    return [
        UnexpectedHit(
            function=h.get("function", ""),
            rule_id=h.get("rule_id", ""),
            category=h.get("category", ""),
            confidence=h.get("confidence", 0.0),
        )
        for h in cached.get("unexpected_hits", [])
    ]


def get_corpus_entry(cve_entry: dict, corpus_dir: Path) -> CVECorpusEntry:
    """Build a CVECorpusEntry from a manifest entry + filesystem state."""
    cve_id = cve_entry["cve_id"]
    cve_dir = corpus_dir / cve_id
    status = _determine_status(cve_dir, cve_id)

    cached = _load_eval_cache(cve_dir)
    detection_details = _build_detection_details(cve_entry, cached)
    unexpected_hits = _build_unexpected_hits(cached)

    entry = CVECorpusEntry(
        cve_id=cve_id,
        driver=cve_entry.get("driver", ""),
        description=cve_entry.get("description", ""),
        expected_category_primary=cve_entry.get("expected_category_primary", ""),
        vuln_build=cve_entry.get("vuln_version", {}).get("build", ""),
        fix_build=cve_entry.get("fix_version", {}).get("build", ""),
        vuln_kb=cve_entry.get("vuln_version", {}).get("kb", ""),
        fix_kb=cve_entry.get("fix_version", {}).get("kb", ""),
        expected_detections_count=len(cve_entry.get("expected_detections", [])),
        detection_details=detection_details,
        unexpected_hits=unexpected_hits,
        status=status,
    )

    # Enrich with cached evaluation results if available
    if cached:
        entry.tp = cached.get("tp", 0)
        entry.fn = cached.get("fn", 0)
        entry.fp = cached.get("fp", 0)
        entry.total_changed = cached.get("total_functions_changed", 0)
        entry.total_hits = cached.get("total_hits", 0)
        entry.error = cached.get("error")

    return entry


def get_per_category_metrics(entries: list[CVECorpusEntry]) -> list[CategoryMetrics]:
    """Aggregate TP/FP/FN per expected_category_primary from evaluated entries."""
    cats: dict[str, dict] = {}

    for e in entries:
        cat = e.expected_category_primary
        if not cat:
            continue
        if cat not in cats:
            cats[cat] = {"cve_count": 0, "tp": 0, "fn": 0, "fp": 0}
        cats[cat]["cve_count"] += 1
        if e.status == CorpusStatus.evaluated:
            cats[cat]["tp"] += e.tp
            cats[cat]["fn"] += e.fn
            cats[cat]["fp"] += e.fp

    result: list[CategoryMetrics] = []
    for cat, data in sorted(cats.items()):
        tp, fp, fn = data["tp"], data["fp"], data["fn"]
        precision = recall = f1 = None
        if tp + fp > 0:
            precision = round(tp / (tp + fp), 4)
        if tp + fn > 0:
            recall = round(tp / (tp + fn), 4)
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = round(2 * precision * recall / (precision + recall), 4)

        result.append(CategoryMetrics(
            category=cat,
            cve_count=data["cve_count"],
            tp=tp,
            fn=fn,
            fp=fp,
            precision=precision,
            recall=recall,
            f1=f1,
        ))

    return result


def _compute_detection_rates(entries: list[CVECorpusEntry]) -> DetectionRates:
    """Compute high-level detection rates from evaluated entries."""
    evaluated = [e for e in entries if e.status == CorpusStatus.evaluated]
    total = len(evaluated)
    if total == 0:
        return DetectionRates()

    func_flagged = sum(1 for e in evaluated if e.tp > 0)
    cat_correct = 0
    rule_exact = 0

    for e in evaluated:
        if e.error:
            continue
        for d in e.detection_details:
            if d.is_tp and d.actual_category == e.expected_category_primary:
                cat_correct += 1
                break
        for d in e.detection_details:
            if d.is_tp and d.actual_rule and d.actual_rule in d.expected_rules:
                rule_exact += 1
                break

    return DetectionRates(
        vuln_function_flagged=round(func_flagged / total, 4),
        correct_category=round(cat_correct / total, 4),
        exact_rule=round(rule_exact / total, 4),
    )


def _compute_confidence_stats(entries: list[CVECorpusEntry]) -> ConfidenceStats:
    """Compute confidence statistics from true positive detections."""
    confidences: list[float] = []
    for e in entries:
        if e.status != CorpusStatus.evaluated:
            continue
        for d in e.detection_details:
            if d.is_tp and d.actual_confidence is not None:
                confidences.append(d.actual_confidence)

    if not confidences:
        return ConfidenceStats()

    return ConfidenceStats(
        mean=round(sum(confidences) / len(confidences), 4),
        min=round(min(confidences), 4),
        max=round(max(confidences), 4),
        count=len(confidences),
    )


def get_corpus_overview(
    manifest_path: Path,
    corpus_dir: Path,
) -> CorpusOverview:
    """Build a full CorpusOverview from the manifest and corpus directory."""
    manifest = json.loads(manifest_path.read_text())
    cves_raw = manifest.get("cves", [])

    entries: list[CVECorpusEntry] = []
    for cve_entry in cves_raw:
        entries.append(get_corpus_entry(cve_entry, corpus_dir))

    # Aggregate counts
    downloaded = sum(1 for e in entries if e.status != CorpusStatus.pending)
    decompiled = sum(
        1 for e in entries
        if e.status in (CorpusStatus.decompiled, CorpusStatus.evaluated)
    )
    evaluated = sum(1 for e in entries if e.status == CorpusStatus.evaluated)

    # Compute overall precision / recall / F1 from evaluated entries
    total_tp = sum(e.tp for e in entries if e.status == CorpusStatus.evaluated)
    total_fp = sum(e.fp for e in entries if e.status == CorpusStatus.evaluated)
    total_fn = sum(e.fn for e in entries if e.status == CorpusStatus.evaluated)

    precision = recall = f1 = None
    if evaluated > 0:
        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        if precision + recall > 0:
            f1 = 2 * precision * recall / (precision + recall)
        else:
            f1 = 0.0
        precision = round(precision, 4)
        recall = round(recall, 4)
        f1 = round(f1, 4)

    per_category = get_per_category_metrics(entries)
    detection_rates = _compute_detection_rates(entries)
    confidence_stats = _compute_confidence_stats(entries)

    return CorpusOverview(
        total_cves=len(entries),
        downloaded=downloaded,
        decompiled=decompiled,
        evaluated=evaluated,
        overall_precision=precision,
        overall_recall=recall,
        overall_f1=f1,
        per_category=per_category,
        detection_rates=detection_rates,
        confidence_stats=confidence_stats,
        cves=entries,
    )
