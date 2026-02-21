#!/usr/bin/env python3
"""Generate seed analysis artifacts from the CVE validation corpus.

Creates realistic combined.json files in the analyses directory so the
dashboard has real data to display.  Uses manifest metadata + evaluation
results + decompiled sources where available.

Usage:
    python3 scripts/seed_analyses.py [--analyses-dir DIR]
"""

import difflib
import hashlib
import json
import random
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "tests" / "validation" / "corpus_manifest.json"
CORPUS_DIR = REPO_ROOT / "corpus"
DEFAULT_ANALYSES_DIR = REPO_ROOT / ".tmp-analyses"

# Address-token normalization (same as evaluate.py)
_ADDR_TOKEN_RE = re.compile(r'\b(FUN|DAT|PTR_LOOP|LAB|switchD)_[0-9a-fA-F]{4,}\b')


def _normalize(code: str) -> str:
    return _ADDR_TOKEN_RE.sub(lambda m: m.group(1) + '_ADDR', code)


def _parse_ghidra_funcs(path: Path) -> dict[str, str]:
    """Parse Ghidra decompiled output into {func_name: code}."""
    if not path.exists():
        return {}
    text = path.read_text(errors="replace")
    funcs: dict[str, str] = {}
    current_name = None
    current_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("// FUNCTION_START:"):
            if current_name:
                funcs[current_name] = "\n".join(current_lines)
            parts = line.split(":", 1)[1].strip()
            current_name = parts.split("@")[0].strip()
            current_lines = []
        elif line.startswith("// FUNCTION_END"):
            if current_name:
                funcs[current_name] = "\n".join(current_lines)
            current_name = None
            current_lines = []
        elif current_name is not None:
            current_lines.append(line)
    if current_name:
        funcs[current_name] = "\n".join(current_lines)
    return funcs


def _generate_diff(old_code: str, new_code: str, name: str) -> str:
    old_lines = _normalize(old_code).splitlines(keepends=True)
    new_lines = _normalize(new_code).splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines,
                                 fromfile=f"a/{name}", tofile=f"b/{name}")
    return "".join(diff)


# Rule engine categories with realistic rules and scores
CATEGORY_RULES = {
    "bounds_check": [
        ("added_len_check_before_memcpy", "Added length validation before memory copy to prevent buffer overflow"),
        ("added_bounds_check_on_offset", "Added offset bounds check to prevent out-of-bounds access"),
        ("added_index_range_check", "Added array index range validation"),
    ],
    "user_boundary_check": [
        ("added_probe_for_write", "Added ProbeForWrite to validate user-mode buffer before kernel write"),
        ("added_probe_call", "Added probe call to validate user-supplied pointer"),
    ],
    "int_overflow": [
        ("added_overflow_check_on_arithmetic", "Added integer overflow check on arithmetic operation"),
        ("added_underflow_guard", "Added underflow guard on size subtraction"),
        ("safe_size_math_helper_added", "Replaced raw size arithmetic with safe math helpers"),
        ("alloc_size_overflow_check_added", "Added overflow/size check before allocating memory"),
    ],
    "lifetime_fix": [
        ("added_refcount_guard", "Added reference count guard to prevent use-after-free"),
        ("added_null_check_before_deref", "Added null check before pointer dereference"),
        ("null_after_free_added", "Pointer set to NULL immediately after freeing memory"),
        ("guard_before_free_added", "Added NULL check before freeing to prevent double-free"),
    ],
    "authorization": [
        ("added_access_check", "Added access check before privileged operation"),
        ("added_previous_mode_gate", "Added PreviousMode gate to prevent kernel-mode bypass"),
    ],
    "race_condition": [
        ("added_lock_around_toctou", "Added lock to prevent TOCTOU race condition"),
        ("added_spinlock_guard", "Added spinlock guard around shared state access"),
        ("spinlock_acquisition_added", "Added spinlock acquisition to protect shared data"),
        ("mutex_or_resource_lock_added", "Added mutex or executive resource lock"),
    ],
    "state_hardening": [
        ("added_state_validation", "Added state machine validation before transition"),
        ("added_flag_check", "Added flag check to prevent invalid state"),
        ("interlocked_refcount_added", "Added Interlocked-based refcounting to protect state"),
    ],
    "info_disclosure": [
        ("stack_variable_initialization_added", "Added stack variable initialization to prevent information leak"),
        ("buffer_zeroing_before_copy_added", "Added RtlZeroMemory before populating output buffer"),
        ("kernel_pointer_scrubbing_added", "Scrubbed kernel pointer from user-accessible output buffer"),
    ],
    "type_confusion": [
        ("object_type_validation_added", "Added object type tag validation before struct access"),
        ("handle_object_type_check_added", "Added ObjectType parameter to ObReferenceObjectByHandle"),
    ],
    "ioctl_hardening": [
        ("ioctl_input_size_validation_added", "Added InputBufferLength/OutputBufferLength size validation"),
        ("ioctl_code_default_case_added", "Added default case with error return to IOCTL dispatch"),
        ("method_neither_probe_added", "Added ProbeForRead/ProbeForWrite with SEH for METHOD_NEITHER"),
    ],
    "mdl_handling": [
        ("mdl_probe_access_mode_fix", "Fixed MmProbeAndLockPages AccessMode from KernelMode to UserMode"),
        ("mdl_safe_mapping_replacement", "Replaced unsafe MmGetSystemAddressForMdl with safe variant"),
        ("mdl_null_check_added", "Added NULL check on Irp->MdlAddress before MDL mapping"),
    ],
    "object_management": [
        ("ob_reference_balance_fix", "Added ObDereferenceObject on error path to fix reference leak"),
        ("handle_force_access_check_added", "Added OBJ_FORCE_ACCESS_CHECK flag on handle operations"),
    ],
    "pool_hardening": [
        ("pool_allocation_null_check_added", "Added NULL check after pool allocation"),
        ("deprecated_pool_api_replacement", "Replaced deprecated ExAllocatePoolWithTag with ExAllocatePool2"),
        ("pool_type_nx_migration", "Migrated pool allocation to NonPagedPoolNx"),
    ],
    "string_handling": [
        ("safe_string_function_replacement", "Replaced unsafe string function with bounded RtlStringCb variant"),
        ("unicode_string_length_validation_added", "Added UNICODE_STRING Length vs MaximumLength validation"),
    ],
    "filesystem_filter": [
        ("flt_context_reference_leak_fix", "Fixed filter context reference leak"),
    ],
}

REACHABILITY_CLASSES = ["ioctl", "irp", "pnp", "internal", "unknown"]
SINK_FUNCS = ["memcpy", "memmove", "RtlCopyMemory", "ExAllocatePoolWithTag",
              "ProbeForWrite", "ProbeForRead", "MmMapLockedPagesSpecifyCache"]


def _make_finding(func_name: str, category: str, rule_idx: int = 0,
                  diff_snippet: str = "", reach_cls: str = "unknown") -> dict:
    rules = CATEGORY_RULES.get(category, CATEGORY_RULES["state_hardening"])
    rule_id, why = rules[rule_idx % len(rules)]
    confidence = round(random.uniform(0.70, 0.98), 2)

    # Score: higher for reachable, lower for internal/unknown
    base_score = random.uniform(3.0, 8.5)
    reach_bonus = {"ioctl": 3.0, "irp": 2.0, "pnp": 1.0, "internal": 0.0, "unknown": 0.0}
    sem_score = round(base_score, 2)
    reach_score = round(reach_bonus.get(reach_cls, 0.0) * random.uniform(0.8, 1.2), 2)
    sink_score = round(random.uniform(0.5, 2.5), 2)
    penalty = round(random.uniform(0.0, 1.5), 2)
    final = round(max(0, sem_score + reach_score + sink_score - penalty), 2)

    sinks = random.sample(SINK_FUNCS, min(random.randint(0, 2), len(SINK_FUNCS)))

    return {
        "function": func_name,
        "rule_id": rule_id,
        "category": category,
        "confidence": confidence,
        "sinks": sinks,
        "indicators": [why.split()[1] + " " + why.split()[2] if len(why.split()) > 2 else "pattern match"],
        "diff_snippet": diff_snippet[:2000] if diff_snippet else "",
        "why_matters": why,
        "surface_area": [reach_cls] if reach_cls != "unknown" else [],
        "final_score": final,
        "score_breakdown": {
            "semantic": sem_score,
            "reachability": reach_score,
            "sinks": sink_score,
            "penalties": penalty,
            "gates": [],
        },
        "reachability_class": reach_cls,
    }


def generate_analysis(cve_entry: dict, corpus_dir: Path) -> dict:
    """Generate a combined.json artifact from a CVE manifest entry."""
    cve_id = cve_entry["cve_id"]
    driver = cve_entry["driver"]
    cve_dir = corpus_dir / cve_id
    category = cve_entry.get("expected_category_primary", "bounds_check")

    vuln_ver = cve_entry.get("vuln_version", {})
    fix_ver = cve_entry.get("fix_version", {})

    driver_new = {
        "sha256": fix_ver.get("sha256", hashlib.sha256(f"{cve_id}-fix".encode()).hexdigest()),
        "product": driver,
        "version": fix_ver.get("build", ""),
        "arch": "x64",
    }
    driver_old = {
        "sha256": vuln_ver.get("sha256", hashlib.sha256(f"{cve_id}-vuln".encode()).hexdigest()),
        "product": driver,
        "version": vuln_ver.get("build", ""),
        "arch": "x64",
    }

    # Try to load real decompiled functions
    vuln_funcs = _parse_ghidra_funcs(cve_dir / "cache" / "vuln.c")
    fix_funcs = _parse_ghidra_funcs(cve_dir / "cache" / "fix.c")

    # Find changed functions
    changed_funcs: list[tuple[str, str]] = []  # (name, diff)
    if vuln_funcs and fix_funcs:
        common = set(vuln_funcs) & set(fix_funcs)
        for name in sorted(common):
            if _normalize(vuln_funcs[name]) != _normalize(fix_funcs[name]):
                diff = _generate_diff(vuln_funcs[name], fix_funcs[name], name)
                if diff:
                    changed_funcs.append((name, diff))

    # Load eval cache if available
    eval_cache = cve_dir / "cache" / "eval_result.json"
    eval_data = None
    if eval_cache.exists():
        try:
            eval_data = json.loads(eval_cache.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    # Generate findings
    deltas = []
    total_funcs = max(len(vuln_funcs), len(fix_funcs), random.randint(200, 800))
    matched_count = int(total_funcs * random.uniform(0.85, 0.95))
    changed_count = len(changed_funcs) if changed_funcs else random.randint(5, 40)

    if eval_data and eval_data.get("unexpected_hits"):
        # Use real unexpected hits as findings
        for hit in eval_data["unexpected_hits"]:
            func_name = hit.get("function", "unknown")
            diff_snippet = ""
            for name, diff in changed_funcs:
                if name == func_name:
                    diff_snippet = diff
                    break
            reach_cls = random.choice(["internal", "unknown", "pnp"])
            deltas.append(_make_finding(
                func_name, hit.get("category", category),
                diff_snippet=diff_snippet, reach_cls=reach_cls,
            ))

    # Add expected-category findings from changed functions
    if changed_funcs:
        # Pick some changed functions for primary-category findings
        candidates = changed_funcs[:min(5, len(changed_funcs))]
        for i, (name, diff) in enumerate(candidates):
            reach_cls = random.choice(REACHABILITY_CLASSES[:3])  # bias toward reachable
            deltas.append(_make_finding(name, category, rule_idx=i,
                                         diff_snippet=diff, reach_cls=reach_cls))
    else:
        # No real data, generate synthetic findings
        for i in range(random.randint(2, 6)):
            func_name = f"FUN_{random.randint(0x1c000000, 0x1c00ffff):08x}"
            reach_cls = random.choice(REACHABILITY_CLASSES)
            deltas.append(_make_finding(func_name, category, rule_idx=i,
                                         reach_cls=reach_cls))

    # Sort by score
    deltas.sort(key=lambda d: d["final_score"], reverse=True)

    # Build category counts
    by_category: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for d in deltas:
        by_category[d["category"]] = by_category.get(d["category"], 0) + 1
        by_rule[d["rule_id"]] = by_rule.get(d["rule_id"], 0) + 1

    # Pairing
    pairing = {
        "decision": "accept",
        "confidence": round(random.uniform(0.85, 0.99), 2),
        "noise_risk": random.choice(["low", "low", "medium"]),
        "rationale": [
            f"Same driver name: {driver}",
            f"Sequential builds: {vuln_ver.get('build', '')} -> {fix_ver.get('build', '')}",
            "Architecture match: x64",
        ],
        "arch_mismatch": False,
        "driver_new": driver_new,
        "driver_old": driver_old,
        "notes": [f"CVE: {cve_id}", cve_entry.get("description", "")],
    }

    # Symbols
    coverage = 0.0
    if vuln_funcs:
        named = sum(1 for n in vuln_funcs if not n.startswith("FUN_"))
        coverage = round(named / max(len(vuln_funcs), 1), 2)
    else:
        coverage = round(random.uniform(0.10, 0.45), 2)

    symbols = {
        "method": "ghidra_decompile",
        "coverage": coverage,
    }

    # Matching
    matching = {
        "method": "hash_lcs",
        "confidence": round(random.uniform(0.80, 0.95), 2),
        "matched_count": matched_count,
        "added_count": random.randint(0, 20),
        "removed_count": random.randint(0, 15),
        "changed_count": changed_count,
        "total_new": total_funcs,
        "total_old": total_funcs - random.randint(-10, 10),
        "quality": "high" if coverage > 0.3 else "medium",
    }

    # Reachability
    reachability = {
        "dispatch": {
            "driver_entry": f"0x{random.randint(0x1c000000, 0x1c00ffff):08x}",
            "major_functions": {
                "IRP_MJ_CREATE": f"0x{random.randint(0x1c000000, 0x1c00ffff):08x}",
                "IRP_MJ_CLOSE": f"0x{random.randint(0x1c000000, 0x1c00ffff):08x}",
                "IRP_MJ_DEVICE_CONTROL": f"0x{random.randint(0x1c000000, 0x1c00ffff):08x}",
            },
        },
        "ioctls": [
            {
                "ioctl": f"0x{random.randint(0x220000, 0x22ffff):06x}",
                "handler": f"0x{random.randint(0x1c000000, 0x1c00ffff):08x}",
                "confidence": round(random.uniform(0.7, 0.99), 2),
                "evidence": ["dispatch table analysis"],
            }
            for _ in range(random.randint(1, 4))
        ],
        "tags": [
            {
                "function": d["function"],
                "reachability_class": d["reachability_class"],
                "confidence": round(random.uniform(0.6, 0.95), 2),
                "paths": [[d["function"], "DispatchDeviceControl", "DriverEntry"]],
                "evidence": ["static call graph"],
            }
            for d in deltas if d["reachability_class"] in ("ioctl", "irp")
        ],
    }

    # Timestamps spread across recent weeks
    days_ago = random.randint(0, 30)
    created = datetime.utcnow() - timedelta(days=days_ago, hours=random.randint(0, 23))

    return {
        "pairing": pairing,
        "symbols": symbols,
        "matching": matching,
        "semantic_deltas": {
            "driver_new": driver_new,
            "driver_old": driver_old,
            "deltas": deltas,
            "summary": {
                "total_deltas": len(deltas),
                "by_category": by_category,
                "by_rule": by_rule,
                "top_functions": [d["function"] for d in deltas[:3]],
                "top_score": deltas[0]["final_score"] if deltas else 0.0,
                "match_rate": round(matched_count / max(total_funcs, 1), 4),
            },
            "notes": [],
        },
        "reachability": reachability,
        "_created_at": created.isoformat(),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate seed analysis data from corpus")
    parser.add_argument("--analyses-dir", type=str, default=str(DEFAULT_ANALYSES_DIR))
    args = parser.parse_args()

    analyses_dir = Path(args.analyses_dir)
    analyses_dir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(MANIFEST_PATH.read_text())
    random.seed(42)  # Reproducible

    for cve_entry in manifest["cves"]:
        cve_id = cve_entry["cve_id"]
        analysis = generate_analysis(cve_entry, CORPUS_DIR)

        # Use a short deterministic ID
        aid = hashlib.sha256(cve_id.encode()).hexdigest()[:8]
        out_dir = analyses_dir / aid
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "combined.json"
        out_path.write_text(json.dumps(analysis, indent=2))

        n_findings = len(analysis["semantic_deltas"]["deltas"])
        top_score = analysis["semantic_deltas"]["summary"]["top_score"]
        print(f"  {aid}  {cve_id:<18} {cve_entry['driver']:<16} {n_findings} findings  top={top_score:.1f}")

    print(f"\nGenerated {len(manifest['cves'])} analyses in {analyses_dir}")


if __name__ == "__main__":
    main()
