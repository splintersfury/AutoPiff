"""
Structured prompts for KernelSense's three analysis modes.

Mode 1: Vulnerability Reasoning — assess if a patch fixes a security bug
Mode 2: False Positive Filtering — validate low-confidence pattern matches
Mode 3: Variant Finding — (deferred to Phase 3, uses embeddings)
"""


def vulnerability_reasoning_prompt(
    function_name: str,
    diff_snippet: str,
    decompiled_pre: str,
    decompiled_post: str,
    category: str,
    rule_ids: list[str],
    indicators: list[str],
) -> str:
    """Build the prompt for Mode 1: vulnerability reasoning.

    Given a function's pre-patch and post-patch decompiled code plus the
    semantic diff, assess whether the change fixes a security vulnerability.
    """
    rules_str = ", ".join(rule_ids) if rule_ids else "none"
    indicators_str = ", ".join(indicators) if indicators else "none"

    return f"""Analyze this kernel driver patch to determine if it fixes a security vulnerability.

## Function: {function_name}
## AutoPiff Category: {category}
## Matched Rules: {rules_str}
## Indicators: {indicators_str}

## Diff Summary
{diff_snippet}

## Pre-Patch Decompiled Code
```c
{decompiled_pre}
```

## Post-Patch Decompiled Code
```c
{decompiled_post}
```

## Your Task

Answer these questions precisely:

1. **Is this a security fix?** (yes/no/uncertain)
   - If yes, what specific vulnerability does it fix?
   - If uncertain, what additional information would resolve the ambiguity?

2. **Bug class:** Classify the vulnerability type.
   Common kernel driver bug classes: use-after-free, double-free, buffer-overflow,
   integer-overflow, race-condition, null-pointer-deref, uninitialized-memory,
   privilege-escalation, type-confusion, TOCTOU, missing-bounds-check, info-leak.
   Use "not-a-bug" if this is a non-security change.

3. **Exploitability:** Rate as one of:
   - "likely" — clear path to exploitation (controllable input reaches the bug)
   - "possible" — bug exists but exploitation path unclear
   - "unlikely" — bug is real but exploitation would be extremely difficult
   - "not-applicable" — not a security bug

4. **Reasoning:** Explain your analysis in 2-4 sentences. Focus on:
   - What the pre-patch code does wrong
   - How the post-patch code fixes it
   - Whether an attacker could control the relevant inputs

Respond in this exact JSON format:
```json
{{
    "is_security_fix": true,
    "bug_class": "buffer-overflow",
    "exploitability": "likely",
    "confidence": 0.85,
    "reasoning": "The pre-patch code calls memcpy without checking..."
}}
```
"""


def false_positive_filtering_prompt(
    function_name: str,
    diff_snippet: str,
    decompiled_code: str,
    category: str,
    rule_id: str,
    original_score: float,
) -> str:
    """Build the prompt for Mode 2: false positive filtering.

    Validate whether a low-confidence AutoPiff match is a real
    security finding or a false positive.
    """
    return f"""AutoPiff flagged this function change as potentially security-relevant,
but with low confidence. Determine if this is a genuine security fix or a false positive.

## Function: {function_name}
## AutoPiff Category: {category}
## Matched Rule: {rule_id}
## Original Score: {original_score}

## Diff Summary
{diff_snippet}

## Decompiled Code (post-patch)
```c
{decompiled_code}
```

## Common False Positive Patterns in Kernel Drivers

- Normal reference counting changes (not UAF)
- Defensive hardening that doesn't fix an actual bug
- Code restructuring/refactoring with no behavioral change
- Error path improvements that don't fix exploitable conditions
- Logging additions or telemetry changes
- Build system or metadata changes reflected in binary

## Your Task

1. **Is this a false positive?** (yes/no/uncertain)
2. **Reasoning:** Explain in 2-3 sentences why this is or isn't a real security finding.
3. **What pattern is this?** If false positive, classify it (refactoring, hardening,
   logging, reference-counting, metadata, other).

Respond in this exact JSON format:
```json
{{
    "is_false_positive": false,
    "reasoning": "This appears to be a genuine bounds check addition...",
    "pattern": null,
    "confidence": 0.80
}}
```
"""


def variant_finding_prompt(
    original_function: str,
    original_bug_class: str,
    original_reasoning: str,
    candidate_functions: list[dict],
) -> str:
    """Build the prompt for Mode 3: variant finding.

    Given a known vulnerable function and a list of similar functions
    from other drivers, identify which candidates share the same bug pattern.
    """
    candidates_text = ""
    for i, c in enumerate(candidate_functions, 1):
        candidates_text += f"""
### Candidate {i}: {c['driver']} / {c['function']}
Similarity: {c['similarity']:.2f}
```c
{c['code']}
```
"""

    return f"""You are analyzing potential variant vulnerabilities across Windows kernel drivers.

## Known Vulnerable Pattern

A vulnerability was found and patched in this function:

**Bug class:** {original_bug_class}
**Analysis:** {original_reasoning}

**Original vulnerable code:**
```c
{original_function}
```

## Candidate Functions

The following functions from OTHER drivers were identified as structurally similar
by embedding-based search. Analyze each one to determine if it shares the same
vulnerability pattern.

{candidates_text}

## Your Task

For each candidate, determine:
1. Does it share the same bug pattern? (yes/no/uncertain)
2. If yes, how similar is the vulnerability? (exact-match, variant, related)
3. Brief reasoning (1-2 sentences)

Respond in this exact JSON format:
```json
{{
    "candidates": [
        {{
            "index": 1,
            "is_variant": true,
            "match_type": "variant",
            "confidence": 0.75,
            "reasoning": "This function uses the same unchecked memcpy pattern..."
        }}
    ]
}}
```
"""
