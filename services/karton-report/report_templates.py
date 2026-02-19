"""
Report templates for AutoPiff Stage 7.

Generates human-readable markdown and machine-readable JSON reports
per Docs/reporting.md specification.
"""


def render_header(driver_name, arch, old_info, new_info, pairing):
    """Render the report header block."""
    old_ver = old_info.get("version") or old_info.get("sha256", "unknown")[:16]
    new_ver = new_info.get("version") or new_info.get("sha256", "unknown")[:16]
    return (
        f"# AutoPiff Patch Intelligence Report\n"
        f"\n"
        f"Driver: {driver_name}\n"
        f"Architecture: {arch}\n"
        f"Old Version: {old_ver}\n"
        f"New Version: {new_ver}\n"
        f"\n"
        f"Pairing Decision: {pairing.get('decision', 'unknown')}\n"
        f"Noise Risk: {pairing.get('noise_risk', 'unknown')}\n"
        f"Pair Confidence: {pairing.get('confidence', 0.0):.2f}\n"
    )


def render_executive_summary(findings, reachable_count):
    """Render the executive summary section."""
    total = len(findings)
    if total == 0:
        return (
            "## Executive Summary\n"
            "\n"
            "AutoPiff identified 0 security-relevant logic changes.\n"
            "No findings to report.\n"
        )

    # Find top category
    categories = [f.get("category", "") for f in findings]
    top_cat = max(set(categories), key=categories.count) if categories else "unknown"

    # Best finding
    best = findings[0]
    best_name = best.get("function", "unknown")
    best_score = best.get("final_score", best.get("score", 0.0))

    lines = [
        "## Executive Summary",
        "",
        f"AutoPiff identified {total} security-relevant logic changes.",
        f"Of these, {reachable_count} are externally reachable.",
        "",
        "Top risk category:",
        f"- {_humanize_category(top_cat)}",
        "",
        "Recommended starting point:",
        f"- {best_name} (Score: {best_score:.2f})",
    ]
    return "\n".join(lines) + "\n"


def render_finding(finding, rank=None):
    """Render a single finding block."""
    r = rank or finding.get("rank", "?")
    func = finding.get("function", "unknown")
    score = finding.get("final_score", finding.get("score", 0.0))
    conf = finding.get("semantic_confidence", finding.get("confidence", 0.0))

    why = finding.get("why_matters", finding.get("why", ""))
    rule_ids = finding.get("rule_ids", [])
    reach_class = finding.get("reachability_class", "unknown")
    reach_path = finding.get("reachability_path", [])
    if not reach_path and "reachability" in finding:
        reach_path = finding["reachability"].get("path", [])

    sinks = finding.get("sinks", [])
    indicators = finding.get("indicators", finding.get("added_checks", []))
    diff_hint = finding.get("diff_snippet", "")

    lines = [
        f"### [Rank #{r}] {func}",
        f"Score: {score:.2f} | Confidence: {conf:.2f}",
        "",
        "**Why this matters**",
        f"- {why}" if why else "- Security-relevant change detected",
        "",
        "**What changed**",
    ]

    for rid in rule_ids:
        lines.append(f"- {_humanize_rule(rid)}")

    lines.extend([
        "",
        "**Reachability**",
    ])
    if reach_path:
        lines.append(f"- Path: {' -> '.join(reach_path)}")
    lines.append(f"- Reachability Class: {reach_class}")

    lines.extend([
        "",
        "**Key Indicators**",
    ])
    if sinks:
        lines.append(f"- Sink(s): {', '.join(sinks)}")
    if indicators:
        lines.append(f"- Added Check(s): {', '.join(indicators)}")

    if diff_hint:
        lines.extend([
            "",
            "**Diff Hint**",
            f"- {diff_hint[:200]}",
        ])

    return "\n".join(lines) + "\n"


def render_top_findings(findings):
    """Render the top findings section."""
    if not findings:
        return "## Top Findings\n\nNo findings to report.\n"

    sections = ["## Top Findings\n"]
    for finding in findings:
        sections.append(render_finding(finding))
    return "\n".join(sections)


def render_skipped(skipped):
    """Render the skipped/deprioritized section."""
    lines = ["## Skipped or Deprioritized Changes\n"]
    if not skipped:
        lines.append("No changes were skipped.\n")
        return "\n".join(lines)

    for entry in skipped:
        func = entry.get("function", "unknown")
        reason = entry.get("reason", "unspecified")
        lines.append(f"- **{func}**: {reason}")

    return "\n".join(lines) + "\n"


def render_limitations(missing_stages):
    """Render a limitations notice when stages are missing."""
    if not missing_stages:
        return ""
    lines = [
        "## Limitations\n",
        "The following pipeline stages were unavailable:",
    ]
    for stage in missing_stages:
        lines.append(f"- {stage}")
    lines.append("")
    lines.append(
        "Findings may be less accurate due to missing data. "
        "Scores should be interpreted with caution."
    )
    return "\n".join(lines) + "\n"


def _humanize_rule(rule_id):
    """Convert rule_id to human-readable description."""
    return rule_id.replace("_", " ").replace("added", "added").capitalize()


def _humanize_category(category):
    """Convert category to human-readable description."""
    mapping = {
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
    return mapping.get(category, category.replace("_", " ").capitalize())
