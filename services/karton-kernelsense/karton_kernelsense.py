"""
AutoPiff KernelSense: LLM-Augmented Vulnerability Reasoning

Parallel consumer of Stage 6 ranking output. Enriches high-scoring
findings with deep LLM-based vulnerability analysis.

Consumes: type=autopiff, kind=ranking
Produces: type=autopiff, kind=kernelsense
"""

import json
import logging
import os

from jsonschema import ValidationError, validate
from karton.core import Karton, Task

from .llm_client import LLMClient
from .prompts import (
    false_positive_filtering_prompt,
    vulnerability_reasoning_prompt,
)

logger = logging.getLogger("autopiff.kernelsense")


class KernelSenseKarton(Karton):
    """
    KernelSense: LLM-augmented vulnerability reasoning.

    Runs as a parallel consumer alongside Stage 7 (Report). When Stage 6
    emits a ranking, both Report and KernelSense receive it. KernelSense
    enriches findings above the score threshold with LLM analysis.

    Consumes: type=autopiff, kind=ranking
    Produces: type=autopiff, kind=kernelsense
    """

    identity = "AutoPiff.KernelSense"
    filters = [{"type": "autopiff", "kind": "ranking"}]

    def __init__(self, config=None, backend=None):
        super().__init__(config=config, backend=backend)

        self.score_threshold = float(
            os.environ.get("KERNELSENSE_SCORE_THRESHOLD", "6.0")
        )
        self.fp_threshold = float(
            os.environ.get("KERNELSENSE_FP_THRESHOLD", "4.0")
        )

        # Load output schema
        schema_path = os.environ.get(
            "KERNELSENSE_SCHEMA",
            os.path.join(
                os.path.dirname(__file__), "..", "..", "schemas", "kernelsense.schema.json"
            ),
        )
        try:
            with open(schema_path, "r") as f:
                self.schema = json.load(f)
        except FileNotFoundError:
            self.log.warning(f"Schema not found at {schema_path}, validation disabled")
            self.schema = None

        self.llm = LLMClient()

    def process(self, task: Task) -> None:
        ranking_raw = task.headers.get("ranking")
        if isinstance(ranking_raw, str):
            ranking = json.loads(ranking_raw)
        else:
            ranking = ranking_raw

        if not ranking:
            self.log.error("No ranking data in task")
            return

        findings = ranking.get("findings", [])
        driver_new = ranking.get("driver_new", {})
        driver_old = ranking.get("driver_old", {})

        # Get semantic deltas for decompiled code access
        semantic_deltas = task.get_payload("semantic_deltas")

        enriched = []

        for finding in findings:
            score = finding.get("final_score", 0)
            func_name = finding.get("function", "")

            if score >= self.score_threshold:
                # Mode 1: Full vulnerability reasoning
                self.log.info(
                    f"Reasoning about {func_name} (score={score})"
                )
                assessment = self._reason_about_finding(
                    finding, semantic_deltas
                )
                enriched.append(self._build_enriched_finding(finding, assessment))

            elif score >= self.fp_threshold:
                # Mode 2: False positive filtering for medium-score findings
                self.log.info(
                    f"FP filtering {func_name} (score={score})"
                )
                fp_result = self._filter_false_positive(
                    finding, semantic_deltas
                )
                enriched.append(
                    self._build_enriched_finding(finding, fp_assessment=fp_result)
                )

        if not enriched:
            self.log.info("No findings above threshold — skipping KernelSense output")
            return

        # Build output
        output = {
            "autopiff_stage": "kernelsense",
            "driver_new": driver_new,
            "driver_old": driver_old,
            "findings": enriched,
            "summary": {
                "total_analyzed": len(enriched),
                "security_fixes": sum(
                    1
                    for f in enriched
                    if f.get("llm_assessment", {}).get("is_security_fix")
                ),
                "false_positives": sum(
                    1
                    for f in enriched
                    if f.get("false_positive_check", {}).get("is_false_positive")
                ),
            },
        }

        # Validate output
        if self.schema:
            try:
                validate(instance=output, schema=self.schema)
            except ValidationError as e:
                self.log.error(f"Schema validation failed: {e.message}")

        self.log.info(
            f"KernelSense: {len(enriched)} findings analyzed, "
            f"{output['summary']['security_fixes']} security fixes identified"
        )

        # Emit enriched task
        out_task = task.derive_task(
            {
                "type": "autopiff",
                "kind": "kernelsense",
                "kernelsense": json.dumps(output),
            }
        )
        self.send_task(out_task)

    def _reason_about_finding(self, finding: dict, semantic_deltas: dict | None) -> dict:
        """Mode 1: Deep vulnerability reasoning for high-score findings."""
        func_name = finding.get("function", "")
        diff_snippet = finding.get("diff_snippet", "")
        category = finding.get("category", "")
        rule_ids = finding.get("rule_ids", [])
        indicators = finding.get("indicators", [])

        # Try to get decompiled code from semantic deltas
        pre_code, post_code = self._get_decompiled_code(
            func_name, semantic_deltas
        )

        prompt = vulnerability_reasoning_prompt(
            function_name=func_name,
            diff_snippet=diff_snippet,
            decompiled_pre=pre_code,
            decompiled_post=post_code,
            category=category,
            rule_ids=rule_ids,
            indicators=indicators,
        )

        result = self.llm.analyze(
            prompt, task_context=f"vuln_reasoning:{func_name}"
        )

        return {
            "is_security_fix": result.get("is_security_fix", False),
            "bug_class": result.get("bug_class", "unknown"),
            "exploitability": result.get("exploitability", "unknown"),
            "confidence": result.get("confidence", 0.0),
            "reasoning": result.get("reasoning", ""),
        }

    def _filter_false_positive(
        self, finding: dict, semantic_deltas: dict | None
    ) -> dict:
        """Mode 2: False positive filtering for medium-score findings."""
        func_name = finding.get("function", "")
        diff_snippet = finding.get("diff_snippet", "")
        category = finding.get("category", "")
        rule_ids = finding.get("rule_ids", [])
        score = finding.get("final_score", 0)

        # Get post-patch code
        _, post_code = self._get_decompiled_code(func_name, semantic_deltas)

        prompt = false_positive_filtering_prompt(
            function_name=func_name,
            diff_snippet=diff_snippet,
            decompiled_code=post_code,
            category=category,
            rule_id=rule_ids[0] if rule_ids else "",
            original_score=score,
        )

        result = self.llm.analyze(
            prompt, task_context=f"fp_filter:{func_name}"
        )

        return {
            "is_false_positive": result.get("is_false_positive", False),
            "reasoning": result.get("reasoning", ""),
            "pattern": result.get("pattern"),
            "confidence": result.get("confidence", 0.0),
        }

    def _get_decompiled_code(
        self, func_name: str, semantic_deltas: dict | None
    ) -> tuple[str, str]:
        """Extract pre/post decompiled code for a function from semantic deltas."""
        if not semantic_deltas:
            return ("(not available)", "(not available)")

        for delta in semantic_deltas.get("deltas", []):
            if delta.get("function") == func_name:
                pre = delta.get("decompiled_old", "(not available)")
                post = delta.get("decompiled_new", "(not available)")
                return (pre, post)

        return ("(not available)", "(not available)")

    def _build_enriched_finding(
        self,
        finding: dict,
        llm_assessment: dict | None = None,
        fp_assessment: dict | None = None,
    ) -> dict:
        """Build an enriched finding dict combining AutoPiff + LLM results."""
        enriched = {
            "rank": finding.get("rank", 0),
            "function": finding.get("function", ""),
            "original_score": finding.get("final_score", 0),
            "category": finding.get("category", ""),
            "rule_ids": finding.get("rule_ids", []),
        }

        if llm_assessment:
            enriched["llm_assessment"] = llm_assessment

        if fp_assessment:
            enriched["false_positive_check"] = fp_assessment

        return enriched


if __name__ == "__main__":
    KernelSenseKarton().loop()
