Perfect 👍 — **conservative is exactly right** for AutoPiff v1.

Below is a **clean, authoritative, agent-executable** draft of
`docs/semantic_rules.md`, explicitly tuned for **high precision / low noise**.

This document *strictly controls* what can appear in the report you just locked down.

---

# AutoPiff – Semantic Rule Specification (v1, Conservative)

## Purpose

Semantic rules define **which code changes are considered security-relevant**
and therefore eligible to appear in AutoPiff reports.

These rules are intentionally **conservative**:

* Fewer findings
* Higher confidence
* Strong bias toward *obvious vulnerability fixes*

AutoPiff v1 prioritizes **trustworthiness over coverage**.

---

## Rule Philosophy

A semantic rule should answer:

> “Does this change plausibly fix a memory-safety or trust-boundary issue
> that could be exploited if reachable?”

Rules must:

* Rely on **explicit code changes**, not inference
* Be explainable in **plain English**
* Trigger on **specific, localized logic changes**
* Avoid refactor-sensitive patterns

Rules must NOT:

* Speculate about exploitability
* Rely on naming alone
* Trigger on stylistic or cosmetic changes

---

## Canonical Rule Categories (v1)

Only the categories below are allowed in v1.

Each rule belongs to **exactly one** category.

---

### 1) Bounds & Size Validation

**Category ID:** `bounds_check`

#### Intent

Detect fixes where insufficient validation of sizes, indices, or lengths
could previously result in out-of-bounds access.

#### High-Signal Indicators

* New conditional checks on:

  * buffer length
  * index bounds
  * structure size
* Added comparisons before copy loops or memory access
* Introduction of explicit size validation helpers

#### Typical Sinks

* `RtlCopyMemory`, `memcpy`, `memmove`
* Manual copy loops
* Array indexing using untrusted values

#### Example Rule Triggers

* `if (len < sizeof(...)) return STATUS_INVALID_PARAMETER;`
* `if (idx >= count) return STATUS_INVALID_PARAMETER;`
* Replacement of unchecked arithmetic with validated size calculation

---

### 2) Pointer Lifetime & Ownership Hardening

**Category ID:** `lifetime_fix`

#### Intent

Detect fixes addressing double free, use-after-free,
or invalid pointer reuse.

#### High-Signal Indicators

* Pointer set to `NULL` immediately after `ExFreePool*`
* Added checks preventing repeated free
* Introduction of reference counting or ownership checks

#### Typical Sinks

* `ExFreePool`, `ExFreePoolWithTag`
* Manual object destruction routines

#### Example Rule Triggers

* `ptr = NULL` added after free
* `if (ptr != NULL)` guard added before free
* Added `InterlockedIncrement/Decrement` guarding object lifetime

---

### 3) User ↔ Kernel Boundary Validation

**Category ID:** `user_boundary_check`

#### Intent

Detect fixes where untrusted user-mode data was previously accessed
without sufficient validation.

#### High-Signal Indicators

* Added calls to:

  * `ProbeForRead`
  * `ProbeForWrite`
  * `ExGetPreviousMode`
* New checks gating behavior based on caller mode
* Added structured exception handling around user pointer access

#### Typical Sinks

* Direct dereference of user-supplied pointers
* Copying from user buffers into kernel memory

#### Example Rule Triggers

* `if (ExGetPreviousMode() != KernelMode) ProbeForRead(...);`
* Introduction of `__try/__except` around pointer access

---

### 4) Integer Overflow / Size Arithmetic Hardening

**Category ID:** `int_overflow`

#### Intent

Detect fixes where integer overflow could previously lead to
incorrect allocation sizes or bounds bypass.

#### High-Signal Indicators

* Replacement of raw arithmetic with:

  * `RtlULongAdd`
  * `RtlULongLongMult`
  * `RtlSizeTMult`
* Explicit overflow checks before allocation

#### Typical Sinks

* `ExAllocatePool*`
* Size-based memory operations

#### Example Rule Triggers

* `if (!NT_SUCCESS(RtlSizeTMult(a, b, &out))) return STATUS_INVALID_PARAMETER;`
* Change from 32-bit to 64-bit arithmetic in size calculations

---

### 5) State & Reference Count Hardening

**Category ID:** `state_hardening`

#### Intent

Detect fixes where inconsistent state or missing synchronization
could lead to unsafe behavior.

#### High-Signal Indicators

* Added reference counting around shared objects
* Added locking around state transitions
* New validation of object state before use

#### Typical Sinks

* Shared global or device context structures
* State machines accessed from multiple IRP paths

#### Example Rule Triggers

* `Interlocked*` operations added
* State validation added before dereference or use

---

## Explicit Non-Rules (v1)

The following MUST NOT trigger semantic findings:

* Logging or tracing changes (ETW, WPP, `DbgPrint`)
* Error code changes without logic changes
* Refactors with no added guards
* Performance-only changes
* Reordering of checks without new validation
* Compiler-inserted artifacts (stack cookies, CFG)

If in doubt, **do not trigger**.

---

## Rule Metadata Contract

Every semantic rule must define:

* `rule_id` (stable, snake_case)
* `category` (one of the canonical categories)
* `confidence` (0.0–1.0)
* `required_signals`
* `excluded_patterns`
* `plain_english_summary`

Rules must be representable in `rules/semantic_rules.yaml`.

---

## Rule → Report Mapping

Each triggered rule contributes:

* Category label (used in report grouping)
* Plain-English explanation (no jargon)
* One or more **key indicators**:

  * sinks involved
  * checks added
* A **diff hint** pointing to what changed

Rules that cannot produce all of the above
**must not surface in reports**.

---

## Rule Confidence (Guidance)

Default confidence guidance:

* Direct guard added before sink: **0.85–0.95**
* Lifetime hardening after free: **0.80–0.90**
* User boundary checks added: **0.85–0.95**
* Integer overflow helpers added: **0.80–0.90**
* State hardening without explicit sink: **≤ 0.75**

---

## Failure Handling

If:

* rule signals conflict
* function matching confidence is low
* reachability is unknown

Then:

* reduce confidence
* allow surfacing **only if score remains high**

---

## Success Criteria

Semantic rules are successful if:

* ≥80% of surfaced findings are “worth a look” to an expert
* False positives are explainable in one sentence
* Rules generalize across vendors and drivers

---

## Versioning

This document defines **AutoPiff Semantic Rules v1**.

All changes:

* must be backward compatible where possible
* must be recorded in `docs/DECISIONS.md`

