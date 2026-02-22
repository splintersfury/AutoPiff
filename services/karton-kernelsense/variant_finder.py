"""
Mode 3: Cross-driver variant search.

Given a known vulnerable function (from Mode 1 reasoning), searches the
embedding index for structurally similar functions in other drivers,
then asks the LLM to evaluate if they share the same bug pattern.
"""

import logging

from .embeddings import FunctionEmbeddingIndex
from .llm_client import LLMClient
from .prompts import variant_finding_prompt

logger = logging.getLogger("kernelsense.variants")

# Max candidates to send to LLM per batch (token budget)
MAX_LLM_CANDIDATES = 10
# Minimum similarity to consider a candidate
MIN_SIMILARITY = 0.65


class VariantFinder:
    """Finds variant vulnerabilities across the driver corpus using embeddings + LLM."""

    def __init__(
        self,
        index: FunctionEmbeddingIndex | None = None,
        llm: LLMClient | None = None,
    ):
        self.index = index or FunctionEmbeddingIndex()
        self.llm = llm or LLMClient()

    def find_variants(
        self,
        vulnerable_code: str,
        driver_name: str,
        bug_class: str,
        reasoning: str,
        n_candidates: int = 20,
    ) -> list[dict]:
        """Search for variant vulnerabilities across the corpus.

        Args:
            vulnerable_code: The pre-patch vulnerable function code
            driver_name: Name of the driver containing the known vulnerability
            bug_class: Identified bug class (from Mode 1)
            reasoning: LLM reasoning about the vulnerability (from Mode 1)
            n_candidates: Number of embedding candidates to retrieve

        Returns:
            List of variant candidate dicts with LLM assessment
        """
        # Step 1: Embedding search — find similar functions
        logger.info(
            f"Searching for variants of {bug_class} pattern "
            f"(excluding {driver_name})"
        )
        candidates = self.index.query_similar(
            function_code=vulnerable_code,
            n_results=n_candidates,
            exclude_driver=driver_name,
        )

        if not candidates:
            logger.info("No similar functions found in index")
            return []

        # Filter by minimum similarity
        candidates = [c for c in candidates if c["similarity"] >= MIN_SIMILARITY]
        logger.info(
            f"Found {len(candidates)} candidates above "
            f"similarity threshold ({MIN_SIMILARITY})"
        )

        if not candidates:
            return []

        # Step 2: LLM analysis — evaluate candidates for same bug pattern
        # Process in batches to stay within token limits
        all_results = []
        for batch_start in range(0, len(candidates), MAX_LLM_CANDIDATES):
            batch = candidates[batch_start : batch_start + MAX_LLM_CANDIDATES]
            batch_results = self._evaluate_batch(
                vulnerable_code, bug_class, reasoning, batch
            )
            all_results.extend(batch_results)

        # Sort by confidence descending
        all_results.sort(key=lambda x: x.get("confidence", 0), reverse=True)

        variants_found = sum(1 for r in all_results if r.get("is_variant"))
        logger.info(
            f"Variant search complete: {variants_found}/{len(all_results)} "
            f"candidates are potential variants"
        )

        return all_results

    def _evaluate_batch(
        self,
        vulnerable_code: str,
        bug_class: str,
        reasoning: str,
        candidates: list[dict],
    ) -> list[dict]:
        """Send a batch of candidates to the LLM for variant assessment."""
        prompt = variant_finding_prompt(
            original_function=vulnerable_code,
            original_bug_class=bug_class,
            original_reasoning=reasoning,
            candidate_functions=candidates,
        )

        result = self.llm.analyze(
            prompt, task_context=f"variant_search:{bug_class}"
        )

        # Merge LLM results with candidate metadata
        merged = []
        llm_candidates = result.get("candidates", [])

        for i, candidate in enumerate(candidates):
            # Find the matching LLM result
            llm_match = None
            for lc in llm_candidates:
                if lc.get("index") == i + 1:
                    llm_match = lc
                    break

            entry = {
                "driver": candidate["driver"],
                "function": candidate["function"],
                "similarity": candidate["similarity"],
                "is_variant": llm_match.get("is_variant", False) if llm_match else False,
                "match_type": llm_match.get("match_type", "unknown") if llm_match else "unknown",
                "confidence": llm_match.get("confidence", 0.0) if llm_match else 0.0,
                "reasoning": llm_match.get("reasoning", "") if llm_match else "",
            }
            merged.append(entry)

        return merged
