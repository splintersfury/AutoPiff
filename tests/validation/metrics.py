"""
Precision / Recall / F1 computation and reporting for the CVE validation
corpus.
"""

import json
from collections import defaultdict
from dataclasses import asdict
from typing import Dict, List, Optional

try:
    from .evaluate import CVEResult
except ImportError:
    from evaluate import CVEResult


def _safe_div(num: float, den: float) -> float:
    return num / den if den > 0 else 0.0


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    """Compute precision, recall, F1 from raw counts."""
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def compute_overall(results: List[CVEResult]) -> Dict[str, float]:
    """Compute overall P/R/F1 across all CVEs."""
    tp = sum(r.tp for r in results)
    fp = sum(r.fp for r in results)
    fn = sum(r.fn for r in results)
    return _prf(tp, fp, fn)


def compute_per_category(results: List[CVEResult]) -> Dict[str, Dict[str, float]]:
    """Compute P/R/F1 per expected_category_primary."""
    by_cat: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for r in results:
        cat = r.expected_category_primary
        if not cat:
            continue
        by_cat[cat]["tp"] += r.tp
        by_cat[cat]["fn"] += r.fn
        # FPs are harder to attribute per-category; assign to primary
        by_cat[cat]["fp"] += r.fp

    return {cat: _prf(**counts) for cat, counts in sorted(by_cat.items())}


def compute_detection_rates(results: List[CVEResult]) -> Dict[str, float]:
    """Compute high-level detection rates.

    - vuln_function_flagged: % of CVEs where at least one expected function
      received any hit
    - correct_category: % of CVEs where the primary category was detected
    - exact_rule: % of CVEs where the exact expected rule fired
    """
    total = len(results)
    if total == 0:
        return {"vuln_function_flagged": 0.0, "correct_category": 0.0, "exact_rule": 0.0}

    func_flagged = 0
    cat_correct = 0
    rule_exact = 0

    for r in results:
        if r.error:
            continue
        if r.tp > 0:
            func_flagged += 1
        # Check if primary category was detected
        for det in r.detection_results:
            if det.is_tp and det.matched_category == r.expected_category_primary:
                cat_correct += 1
                break
        # Check exact rule match
        for det in r.detection_results:
            if det.is_tp and det.matched_rule in det.expected_rules:
                rule_exact += 1
                break

    return {
        "vuln_function_flagged": round(func_flagged / total, 4),
        "correct_category": round(cat_correct / total, 4),
        "exact_rule": round(rule_exact / total, 4),
    }


def compute_confidence_stats(results: List[CVEResult]) -> Dict[str, Optional[float]]:
    """Compute confidence statistics for true positives."""
    confidences = []
    for r in results:
        for det in r.detection_results:
            if det.is_tp and det.matched_confidence is not None:
                confidences.append(det.matched_confidence)

    if not confidences:
        return {"mean": None, "min": None, "max": None, "count": 0}

    return {
        "mean": round(sum(confidences) / len(confidences), 4),
        "min": round(min(confidences), 4),
        "max": round(max(confidences), 4),
        "count": len(confidences),
    }


def format_text_report(results: List[CVEResult]) -> str:
    """Format a human-readable text report."""
    lines = []
    lines.append("=" * 72)
    lines.append("AutoPiff CVE Validation Report")
    lines.append("=" * 72)
    lines.append("")

    # Per-CVE summary
    lines.append("Per-CVE Results:")
    lines.append("-" * 72)
    lines.append(f"{'CVE':<20} {'Driver':<16} {'TP':>4} {'FN':>4} {'FP':>4} {'Status':<10}")
    lines.append("-" * 72)

    for r in results:
        if r.error:
            status = "ERROR"
        elif r.tp > 0 and r.fn == 0:
            status = "PASS"
        elif r.tp > 0:
            status = "PARTIAL"
        else:
            status = "FAIL"
        lines.append(f"{r.cve_id:<20} {r.driver:<16} {r.tp:>4} {r.fn:>4} {r.fp:>4} {status:<10}")

    lines.append("")

    # Overall metrics
    overall = compute_overall(results)
    lines.append("Overall Metrics:")
    lines.append(f"  Precision: {overall['precision']:.2%}")
    lines.append(f"  Recall:    {overall['recall']:.2%}")
    lines.append(f"  F1:        {overall['f1']:.2%}")
    lines.append(f"  (TP={overall['tp']}, FP={overall['fp']}, FN={overall['fn']})")
    lines.append("")

    # Per-category
    per_cat = compute_per_category(results)
    if per_cat:
        lines.append("Per-Category Metrics:")
        lines.append("-" * 72)
        lines.append(f"{'Category':<25} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>4} {'FP':>4} {'FN':>4}")
        lines.append("-" * 72)
        for cat, m in per_cat.items():
            lines.append(
                f"{cat:<25} {m['precision']:>7.2%} {m['recall']:>7.2%} "
                f"{m['f1']:>7.2%} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}"
            )
        lines.append("")

    # Detection rates
    rates = compute_detection_rates(results)
    lines.append("Detection Rates:")
    lines.append(f"  Vulnerable function flagged: {rates['vuln_function_flagged']:.0%}")
    lines.append(f"  Correct category detected:   {rates['correct_category']:.0%}")
    lines.append(f"  Exact rule matched:          {rates['exact_rule']:.0%}")
    lines.append("")

    # Confidence stats
    conf = compute_confidence_stats(results)
    if conf["count"] > 0:
        lines.append("True Positive Confidence:")
        lines.append(f"  Mean: {conf['mean']:.2f}  Min: {conf['min']:.2f}  Max: {conf['max']:.2f}  N={conf['count']}")
        lines.append("")

    # Errors and details
    errors = [r for r in results if r.error]
    if errors:
        lines.append("Errors:")
        for r in errors:
            lines.append(f"  {r.cve_id}: {r.error}")
        lines.append("")

    # False negatives detail
    fn_details = [(r, d) for r in results for d in r.detection_results if not d.is_tp]
    if fn_details:
        lines.append("False Negatives (missed detections):")
        for r, d in fn_details:
            lines.append(
                f"  {r.cve_id}: pattern={d.function_pattern} "
                f"expected_cats={d.expected_categories}"
            )
        lines.append("")

    # Top false positives
    fp_all = [(r.cve_id, h) for r in results for h in r.unexpected_hits[:5]]
    if fp_all:
        lines.append("Top False Positives (sample):")
        for cve_id, h in fp_all[:20]:
            lines.append(
                f"  {cve_id}: {h['function']} -> {h['rule_id']} "
                f"({h['category']}, conf={h['confidence']:.2f})"
            )
        lines.append("")

    lines.append("=" * 72)
    return "\n".join(lines)


def format_json_report(results: List[CVEResult]) -> str:
    """Format a machine-readable JSON report."""
    report = {
        "overall": compute_overall(results),
        "per_category": compute_per_category(results),
        "detection_rates": compute_detection_rates(results),
        "confidence_stats": compute_confidence_stats(results),
        "cves": [],
    }

    for r in results:
        cve_data = {
            "cve_id": r.cve_id,
            "driver": r.driver,
            "expected_category_primary": r.expected_category_primary,
            "tp": r.tp,
            "fn": r.fn,
            "fp": r.fp,
            "total_functions_changed": r.total_functions_changed,
            "total_hits": r.total_hits,
            "error": r.error,
            "detection_results": [],
            "unexpected_hits": r.unexpected_hits[:10],
        }
        for d in r.detection_results:
            cve_data["detection_results"].append({
                "function_pattern": d.function_pattern,
                "matched_function": d.matched_function,
                "expected_categories": d.expected_categories,
                "expected_rules": d.expected_rules,
                "matched_category": d.matched_category,
                "matched_rule": d.matched_rule,
                "matched_confidence": d.matched_confidence,
                "is_tp": d.is_tp,
            })
        report["cves"].append(cve_data)

    return json.dumps(report, indent=2)
