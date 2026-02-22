"""
AutoPiff Stage 6: Scoring & Ranking

Consumes reachability-tagged tasks from Stage 5, merges reachability data
into semantic deltas, re-scores using the full scoring.yaml formula with
real reachability classes, and produces a ranked list of top findings.
"""

import os
import json
import logging
from collections import defaultdict

import yaml
from karton.core import Karton, Task
from jsonschema import validate, ValidationError

logger = logging.getLogger("autopiff.ranking")


class RankingKarton(Karton):
    """
    AutoPiff Stage 6: Scoring & Ranking.

    Consumes reachability-tagged deltas from Stage 5, merges reachability
    into semantic deltas, scores each finding using scoring.yaml, and
    produces a ranked top-10 list of security-relevant findings.

    Consumes: type=autopiff, kind=reachability
    Produces: type=autopiff, kind=ranking
    """

    identity = "AutoPiff.Stage6"
    filters = [
        {"type": "autopiff", "kind": "reachability"}
    ]

    def __init__(self, config=None, backend=None):
        super().__init__(config=config, backend=backend)

        # Load ranking output schema
        schema_path = os.environ.get(
            "AUTOPIFF_RANKING_SCHEMA",
            os.path.join(os.path.dirname(__file__), "ranking.schema.json")
        )
        with open(schema_path, "r") as f:
            self.schema = json.load(f)

        # Load scoring model
        scoring_path = os.environ.get(
            "AUTOPIFF_SCORING_YAML",
            os.path.join(os.path.dirname(__file__), "..", "..", "rules", "scoring.yaml")
        )
        with open(scoring_path, "r") as f:
            self.scoring = yaml.safe_load(f)

    def process(self, task: Task) -> None:
        reachability = task.headers.get("reachability")
        if isinstance(reachability, str):
            reachability = json.loads(reachability)

        semantic_deltas = task.get_payload("semantic_deltas")
        if not semantic_deltas:
            self.log.error("No semantic_deltas payload in task")
            return

        if not reachability:
            self.log.error("No reachability data in task headers")
            return

        # Extract reachability tags into a lookup by function name
        reach_lookup = self._build_reachability_lookup(reachability)

        # Fetch pairing/matching metadata from MWDB or task payloads
        pairing_info = self._get_pairing_info(task)
        matching_confidence = pairing_info.get("matching_confidence", 0.80)

        # Merge reachability into deltas
        merged_deltas = self._merge_reachability(semantic_deltas, reach_lookup)

        # Group by function for rule stacking, then score
        findings, skipped = self._score_and_rank(
            merged_deltas, matching_confidence, pairing_info
        )

        # Build ranking output
        driver_new = semantic_deltas.get("driver_new", {})
        driver_old = semantic_deltas.get("driver_old", {})

        # Count reachable
        reachable_count = sum(
            1 for f in findings if f["reachability_class"] != "unknown"
        )
        categories = [f["category"] for f in findings]
        top_cat = max(set(categories), key=categories.count) if categories else ""

        ranking = {
            "autopiff_stage": "ranking",
            "driver_new": driver_new,
            "driver_old": driver_old,
            "scoring_model_version": self.scoring.get("version", 1),
            "findings": findings,
            "skipped_findings": skipped,
            "summary": {
                "total_deltas": len(semantic_deltas.get("deltas", [])),
                "scored_count": len(findings),
                "skipped_count": len(skipped),
                "top_category": top_cat,
                "reachable_count": reachable_count,
            },
        }

        # Validate output
        try:
            validate(instance=ranking, schema=self.schema)
        except ValidationError as e:
            self.log.error(f"Ranking schema validation failed: {e.message}")
            self.log.error(f"Failed at path: {'.'.join(str(p) for p in e.absolute_path)}")
            raise RuntimeError(f"Ranking schema validation failed: {e.message}")

        self.log.info(
            f"Ranked {len(findings)} findings "
            f"({reachable_count} reachable, {len(skipped)} skipped)"
        )

        # Send to Stage 7
        out_task = task.derive_task({
            "type": "autopiff",
            "kind": "ranking",
            "ranking": json.dumps(ranking),
        })
        self.send_task(out_task)

    def _build_reachability_lookup(self, reachability: dict) -> dict:
        """Build function -> reachability info mapping from Stage 5 output."""
        lookup = {}
        for tag in reachability.get("tags", []):
            func = tag.get("function", "")
            if not func:
                continue
            # Keep the best (highest confidence) tag per function
            existing = lookup.get(func)
            if not existing or tag.get("confidence", 0) > existing.get("confidence", 0):
                lookup[func] = {
                    "reachability_class": tag.get("reachability_class", "unknown"),
                    "confidence": tag.get("confidence", 0.0),
                    "paths": tag.get("paths", []),
                }
        return lookup

    def _get_pairing_info(self, task: Task) -> dict:
        """Extract pairing/matching metadata from task payload or defaults."""
        semantic_deltas = task.get_payload("semantic_deltas") or {}

        # Try to get pairing info from the combined artifact
        pairing = {
            "decision": "accept",
            "noise_risk": "low",
            "matching_confidence": 0.80,
        }

        # Check if pairing data was forwarded in payload
        pairing_data = task.get_payload("pairing")
        if pairing_data:
            pairing["decision"] = pairing_data.get("decision", "accept")
            pairing["noise_risk"] = pairing_data.get("noise_risk", "low")
            pairing["matching_confidence"] = pairing_data.get("confidence", 0.80)

        return pairing

    def _merge_reachability(self, semantic_deltas: dict, reach_lookup: dict) -> list:
        """Merge reachability tags into delta entries, replacing surface_area heuristics."""
        merged = []
        for delta in semantic_deltas.get("deltas", []):
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
                # No reachability data for this function
                d["reachability_class"] = "unknown"
                d["reachability_confidence"] = 0.0
                d["reachability_path"] = []
            merged.append(d)
        return merged

    def _score_and_rank(
        self, deltas: list, matching_confidence: float, pairing_info: dict
    ) -> tuple:
        """Score all deltas using scoring.yaml, group by function for stacking.

        Returns (findings, skipped) where findings are top-10 ranked results.
        """
        weights = self.scoring.get("weights", {})
        gating = self.scoring.get("gating", {})
        composition = self.scoring.get("composition", {})
        quality_buckets = self.scoring.get("matching_quality_buckets", {})

        rule_base = weights.get("semantic_rule_base", {})
        cat_mult = weights.get("category_multiplier", {})
        reach_bonus_map = weights.get("reachability_bonus", {})
        sink_bonus_map = weights.get("sink_bonus", {})
        penalty_cfg = weights.get("penalties", {})

        clamp_min = composition.get("clamp", {}).get("min", 0.0)
        clamp_max = composition.get("clamp", {}).get("max", 15.0)
        max_findings = composition.get("max_findings_in_report", 10)

        # Quality bucket
        high_min = quality_buckets.get("high", {}).get("min_confidence", 0.80)
        med_min = quality_buckets.get("medium", {}).get("min_confidence", 0.60)
        if matching_confidence >= high_min:
            quality = "high"
        elif matching_confidence >= med_min:
            quality = "medium"
        else:
            quality = "low"

        # Group deltas by function for rule stacking
        by_function = defaultdict(list)
        for delta in deltas:
            by_function[delta.get("function", "unknown")].append(delta)

        scored = []
        skipped = []

        for func_name, func_deltas in by_function.items():
            # Use the first delta for shared fields
            primary = func_deltas[0]
            semantic_confidence = primary.get("confidence", 0.5)

            # Gate: hard minimum semantic confidence
            hard_min = gating.get("semantic_confidence", {}).get("hard_min", 0.45)
            if semantic_confidence < hard_min:
                if gating.get("semantic_confidence", {}).get(
                    "drop_if_below_hard_min", True
                ):
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

            # Semantic score: stack rules within the same function
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

            # Deduplicate sinks/indicators
            all_sinks = list(dict.fromkeys(all_sinks))
            all_indicators = list(dict.fromkeys(all_indicators))

            # Reachability score: use real class from Stage 5
            reach_class = primary.get("reachability_class", "unknown")
            reach_conf = primary.get("reachability_confidence", 0.0)
            reach_bonus = reach_bonus_map.get(reach_class, 0.0)
            reach_total = reach_bonus

            reach_soft_min = gating.get("reachability_confidence", {}).get(
                "soft_min", 0.55
            )
            if reach_conf < reach_soft_min and reach_class != "unknown":
                mult = gating.get("reachability_confidence", {}).get(
                    "multiplier_if_below", 0.70
                )
                reach_total *= mult
                gates.append(f"reachability_confidence_below_{reach_soft_min}")

            # Sink score
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

            # Penalties
            penalty_breakdown = []
            penalty_total = 0.0

            # Pairing decision penalty
            pair_decision = pairing_info.get("decision", "accept")
            pair_pen = penalty_cfg.get("pairing_decision", {}).get(pair_decision, 0.0)
            if pair_pen > 0:
                penalty_total += pair_pen
                penalty_breakdown.append({"type": "pairing_decision", "value": pair_pen})

            # Noise risk penalty
            noise_risk = pairing_info.get("noise_risk", "low")
            noise_pen = penalty_cfg.get("noise_risk", {}).get(noise_risk, 0.0)
            if noise_pen > 0:
                penalty_total += noise_pen
                penalty_breakdown.append({"type": "noise_risk", "value": noise_pen})

            # Matching quality penalty
            quality_pen = penalty_cfg.get("matching_quality", {}).get(quality, 0.0)
            if quality_pen > 0:
                penalty_total += quality_pen
                penalty_breakdown.append({"type": "matching_quality", "value": quality_pen})

            # Compose final score
            raw = semantic_total + reach_total + sink_total - penalty_total
            clamped = max(clamp_min, min(clamp_max, raw))

            # Gating caps
            match_min_req = gating.get("matching_confidence", {}).get(
                "min_required", 0.40
            )
            match_cap = gating.get("matching_confidence", {}).get("cap_if_below", 3.0)
            if matching_confidence < match_min_req and clamped > match_cap:
                clamped = match_cap
                gates.append(f"matching_confidence_cap_{match_cap}")

            soft_min = gating.get("semantic_confidence", {}).get("soft_min", 0.60)
            soft_cap = gating.get("semantic_confidence", {}).get(
                "cap_if_below_soft_min", 5.0
            )
            if semantic_confidence < soft_min and clamped > soft_cap:
                clamped = soft_cap
                gates.append(f"semantic_confidence_cap_{soft_cap}")

            # Build the finding
            finding = {
                "rank": 0,  # assigned after sort
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

        # Sort by score descending, assign ranks
        scored.sort(key=lambda x: x["final_score"], reverse=True)
        top = scored[:max_findings]
        for i, finding in enumerate(top, 1):
            finding["rank"] = i

        # Remaining scored findings go to skipped
        for extra in scored[max_findings:]:
            skipped.append({
                "function": extra["function"],
                "rule_id": extra["rule_ids"][0] if extra["rule_ids"] else "",
                "reason": f"ranked #{scored.index(extra)+1}, outside top {max_findings}",
            })

        return top, skipped


if __name__ == "__main__":
    RankingKarton().loop()
