"""
Evaluation harness — runs the AutoPiff rule engine on decompiled corpus
pairs and compares results against ground truth from the manifest.
"""

import difflib
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from .decompile import funcs_to_dict, parse_ghidra_output
except ImportError:
    from decompile import funcs_to_dict, parse_ghidra_output

logger = logging.getLogger(__name__)

# Import SemanticRuleEngine without pulling in Karton runtime deps.
# The rule_engine module only needs pyyaml at import time.
_PATCH_DIFFER_DIR = str(
    Path(__file__).resolve().parent.parent.parent
    / "services" / "karton-patch-differ"
)
if _PATCH_DIFFER_DIR not in sys.path:
    sys.path.insert(0, _PATCH_DIFFER_DIR)

from rule_engine import SemanticRuleEngine, RuleHit  # noqa: E402

RULES_PATH = (
    Path(__file__).resolve().parent.parent.parent / "rules" / "semantic_rules.yaml"
)
SINKS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "rules" / "sinks.yaml"
)
CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus"


@dataclass
class DetectionResult:
    """Result of matching a single expected_detection against rule hits."""
    function_pattern: str
    matched_function: Optional[str] = None
    expected_categories: List[str] = field(default_factory=list)
    expected_rules: List[str] = field(default_factory=list)
    min_confidence: float = 0.0
    # What we actually found
    matched_category: Optional[str] = None
    matched_rule: Optional[str] = None
    matched_confidence: Optional[float] = None
    is_tp: bool = False  # true positive


@dataclass
class CVEResult:
    """Aggregate result for one CVE entry."""
    cve_id: str
    driver: str
    expected_category_primary: str
    # Counts
    tp: int = 0  # true positives (expected detections matched)
    fn: int = 0  # false negatives (expected detections not matched)
    fp: int = 0  # false positives (rule hits with no expected detection)
    # Details
    detection_results: List[DetectionResult] = field(default_factory=list)
    unexpected_hits: List[Dict] = field(default_factory=list)
    total_functions_changed: int = 0
    total_hits: int = 0
    error: Optional[str] = None


def _generate_diff(old_code: str, new_code: str, func_name: str) -> List[str]:
    """Generate unified diff lines between old and new function code."""
    old_lines = old_code.splitlines(keepends=True)
    new_lines = new_code.splitlines(keepends=True)
    diff = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile=f"a/{func_name}", tofile=f"b/{func_name}",
        lineterm="",
    ))
    return diff


def _match_functions(old_funcs: Dict[str, str],
                     new_funcs: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """Match functions between old and new by name.

    Returns list of (func_name, old_code, new_code) for functions present in
    both and actually changed.
    """
    common = set(old_funcs.keys()) & set(new_funcs.keys())
    changed = []
    for name in sorted(common):
        if old_funcs[name] != new_funcs[name]:
            changed.append((name, old_funcs[name], new_funcs[name]))
    return changed


def _check_detection(expected: dict, func_name: str,
                     hits: List[RuleHit]) -> DetectionResult:
    """Check if any RuleHit matches an expected detection entry."""
    result = DetectionResult(
        function_pattern=expected["function_pattern"],
        expected_categories=expected.get("expected_categories", []),
        expected_rules=expected.get("expected_rules", []),
        min_confidence=expected.get("min_confidence", 0.0),
    )

    pattern = re.compile(expected["function_pattern"], re.IGNORECASE)
    if not pattern.search(func_name):
        return result

    result.matched_function = func_name

    for hit in hits:
        # Check category match
        cat_match = hit.category in result.expected_categories
        # Check rule match
        rule_match = hit.rule_id in result.expected_rules
        # Check confidence
        conf_ok = hit.confidence >= result.min_confidence

        if cat_match and rule_match and conf_ok:
            result.is_tp = True
            result.matched_category = hit.category
            result.matched_rule = hit.rule_id
            result.matched_confidence = hit.confidence
            return result

        # Partial match: right category but wrong rule (still a TP for
        # category-level recall)
        if cat_match and conf_ok and not result.matched_category:
            result.matched_category = hit.category
            result.matched_rule = hit.rule_id
            result.matched_confidence = hit.confidence

    # If we matched category but not the exact rule, count as TP at
    # category level
    if result.matched_category and not result.is_tp:
        result.is_tp = True

    return result


def evaluate_cve(cve_entry: dict, engine: SemanticRuleEngine,
                 corpus_dir: Path = CORPUS_DIR) -> CVEResult:
    """Evaluate rule engine on a single CVE pair.

    Loads cached decompiled .c files, diffs all changed functions, runs the
    rule engine, and compares against expected detections.
    """
    cve_id = cve_entry["cve_id"]
    driver = cve_entry["driver"]
    cve_dir = corpus_dir / cve_id

    result = CVEResult(
        cve_id=cve_id,
        driver=driver,
        expected_category_primary=cve_entry.get("expected_category_primary", ""),
    )

    vuln_c = cve_dir / "cache" / "vuln.c"
    fix_c = cve_dir / "cache" / "fix.c"

    if not vuln_c.exists() or not fix_c.exists():
        result.error = f"Missing decompiled sources: vuln.c={vuln_c.exists()}, fix.c={fix_c.exists()}"
        # All expected detections are FN
        result.fn = len(cve_entry.get("expected_detections", []))
        return result

    # Parse decompiled output
    old_funcs = funcs_to_dict(parse_ghidra_output(str(vuln_c)))
    new_funcs = funcs_to_dict(parse_ghidra_output(str(fix_c)))

    if not old_funcs or not new_funcs:
        result.error = f"Empty decompilation: vuln={len(old_funcs)} funcs, fix={len(new_funcs)} funcs"
        result.fn = len(cve_entry.get("expected_detections", []))
        return result

    # Match and diff functions
    changed = _match_functions(old_funcs, new_funcs)
    result.total_functions_changed = len(changed)

    # Run rule engine on every changed function
    all_hits: Dict[str, List[RuleHit]] = {}
    for func_name, old_code, new_code in changed:
        diff_lines = _generate_diff(old_code, new_code, func_name)
        if not diff_lines:
            continue
        hits = engine.evaluate(func_name, old_code, new_code, diff_lines)
        if hits:
            all_hits[func_name] = hits
            result.total_hits += len(hits)

    # Check each expected detection
    expected_detections = cve_entry.get("expected_detections", [])
    matched_hit_keys = set()  # Track which hits were expected

    for expected in expected_detections:
        pattern = re.compile(expected["function_pattern"], re.IGNORECASE)
        best_result = None

        # Try each changed function against this expected detection
        for func_name, hits in all_hits.items():
            if pattern.search(func_name):
                det = _check_detection(expected, func_name, hits)
                if det.is_tp:
                    best_result = det
                    # Mark these hits as expected
                    for h in hits:
                        if h.category in expected.get("expected_categories", []):
                            matched_hit_keys.add((func_name, h.rule_id))
                    break
                elif det.matched_function and not best_result:
                    best_result = det

        if best_result is None:
            # No function matched the pattern at all
            best_result = DetectionResult(
                function_pattern=expected["function_pattern"],
                expected_categories=expected.get("expected_categories", []),
                expected_rules=expected.get("expected_rules", []),
                min_confidence=expected.get("min_confidence", 0.0),
            )

        result.detection_results.append(best_result)
        if best_result.is_tp:
            result.tp += 1
        else:
            result.fn += 1

    # Count FPs: hits on functions with no corresponding expected detection
    for func_name, hits in all_hits.items():
        for hit in hits:
            if (func_name, hit.rule_id) not in matched_hit_keys:
                result.fp += 1
                result.unexpected_hits.append({
                    "function": func_name,
                    "rule_id": hit.rule_id,
                    "category": hit.category,
                    "confidence": hit.confidence,
                })

    return result


def evaluate_all(manifest: dict, corpus_dir: Path = CORPUS_DIR,
                 cve_filter: Optional[str] = None,
                 rules_path: Optional[Path] = None,
                 sinks_path: Optional[Path] = None) -> List[CVEResult]:
    """Evaluate all CVEs in the manifest.

    Returns list of CVEResult, one per CVE.
    """
    rp = str(rules_path or RULES_PATH)
    sp = str(sinks_path or SINKS_PATH)

    if not Path(rp).exists():
        raise FileNotFoundError(f"Rules file not found: {rp}")
    if not Path(sp).exists():
        raise FileNotFoundError(f"Sinks file not found: {sp}")

    engine = SemanticRuleEngine(rp, sp)
    logger.info(
        f"Rule engine loaded: {len(engine.rules)} rules, "
        f"{len(engine.sink_lookup)} sinks"
    )

    results = []
    for entry in manifest["cves"]:
        cve_id = entry["cve_id"]
        if cve_filter and cve_id != cve_filter:
            continue

        logger.info(f"--- Evaluating {cve_id} ({entry['driver']}) ---")
        res = evaluate_cve(entry, engine, corpus_dir)
        results.append(res)

        status = "PASS" if res.tp > 0 and res.fn == 0 else "PARTIAL" if res.tp > 0 else "FAIL"
        logger.info(
            f"  {status}: TP={res.tp} FN={res.fn} FP={res.fp} "
            f"({res.total_functions_changed} changed funcs, {res.total_hits} hits)"
        )
        if res.error:
            logger.warning(f"  Error: {res.error}")

    return results
