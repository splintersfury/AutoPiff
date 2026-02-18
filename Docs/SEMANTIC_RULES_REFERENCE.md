# AutoPiff Semantic Rules Reference

Complete technical reference for the AutoPiff semantic rule system: how rules are defined, how the engine evaluates them, and how scoring ranks findings.

---

## Architecture Overview

```
rules/semantic_rules.yaml    rules/sinks.yaml    rules/scoring.yaml
         |                         |                     |
         v                         v                     v
   +-------------------------------------------------+
   |           SemanticRuleEngine (rule_engine.py)    |
   |  1. Global exclusion check                      |
   |  2. Sink detection in diff                      |
   |  3. Guard/validation detection in added lines   |
   |  4. Per-rule signal matching + proximity check  |
   |  5. RuleHit generation with evidence            |
   +-------------------------------------------------+
                        |
                        v
   +-------------------------------------------------+
   |         Scoring (_score_findings)               |
   |  semantic_score + reachability_bonus +           |
   |  sink_bonus - penalties => final_score          |
   +-------------------------------------------------+
```

The engine takes a unified diff of a changed function and determines whether the change looks like a security fix. Every detection must be explainable.

---

## Configuration Files

### `rules/semantic_rules.yaml`

Defines the 11 semantic rules, 5 categories, and 2 global exclusions. This is the primary configuration file that controls what AutoPiff considers a security-relevant change.

### `rules/sinks.yaml`

Defines 8 groups of "dangerous" API symbols (50+ total). A sink is an API whose misuse commonly leads to vulnerabilities. Rules become high-signal when patches add guards near sinks.

### `rules/scoring.yaml`

Defines the scoring model that ranks findings by exploit relevance: base weights per rule, category multipliers, reachability bonuses, sink bonuses, penalties, and gating thresholds.

---

## Categories

Each rule belongs to exactly one category. Categories group related vulnerability fix patterns.

| Category ID | Description | Rule Count |
|---|---|---|
| `bounds_check` | Added or strengthened bounds/size/index validation | 3 |
| `lifetime_fix` | Added or strengthened pointer lifetime/ownership protection | 2 |
| `user_boundary_check` | Added or strengthened validation of user-mode supplied data/pointers | 3 |
| `int_overflow` | Added or strengthened safe integer/size arithmetic checks | 2 |
| `state_hardening` | Added or strengthened state/refcount/synchronization validation | 1 |

---

## Rules Reference

### Bounds Check Rules

#### `added_len_check_before_memcpy`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.92 |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: memory_copy`, `change_type: guard_added`, `guard_kind: length_check`, `proximity: near_sink` |

**What it detects:** A length or buffer size comparison was added within 10 lines of a memory copy operation (`RtlCopyMemory`, `memcpy`, `memmove`, etc.).

**Example patch:**
```c
// ADDED:
+ if (InputBufferLength < sizeof(REQUEST_STRUCT))
+     return STATUS_INVALID_PARAMETER;
  RtlCopyMemory(dest, src, InputBufferLength);
```

**Why it matters:** Missing length validation before memory copies is one of the most common sources of kernel buffer overflows.

---

#### `added_struct_size_validation`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.88 |
| Base Score Weight | 4.5 |
| Required Signals | `change_type: guard_added`, `guard_kind: sizeof_check` |

**What it detects:** A `sizeof()` check or `RtlSizeT*` validation was added, typically to validate that an input buffer is large enough for the expected structure.

**Example patch:**
```c
// ADDED:
+ if (bufferSize < sizeof(MY_IOCTL_INPUT))
+     return STATUS_BUFFER_TOO_SMALL;
```

**Why it matters:** When a driver reads a complex structure from an IOCTL input buffer without first verifying the buffer is large enough, it can read past the end of the allocation. Depending on context this yields either an information leak (reading adjacent pool data), a kernel pool corruption (writing response data past the buffer), or a controlled out-of-bounds read that feeds attacker data into subsequent logic. The `sizeof` check is the standard idiom to prevent this entire class of issues.

---

#### `added_index_bounds_check`

| Field | Value |
|---|---|
| Category | `bounds_check` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `change_type: guard_added`, `guard_kind: index_bounds` |

**What it detects:** An index or array bounds check was added (e.g., `if (index >= count)`).

**Example patch:**
```c
// ADDED:
+ if (idx >= MAX_ENTRIES)
+     return STATUS_INVALID_PARAMETER;
  table[idx] = value;
```

**Why it matters:** Unchecked array or table indices supplied from user-controlled input (IOCTL buffers, IRP parameters) allow an attacker to read or write at an arbitrary offset relative to the base of the array. In kernel pool memory, this is a direct primitive for pool corruption, arbitrary write, or information disclosure depending on the access pattern.

---

### Lifetime Fix Rules

#### `null_after_free_added`

| Field | Value |
|---|---|
| Category | `lifetime_fix` |
| Confidence | 0.88 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: pool_free`, `change_type: post_free_hardening`, `hardening_kind: null_assignment`, `proximity: immediately_after_sink` |

**What it detects:** A pointer is set to `NULL` within 3 lines immediately after an `ExFreePool`/`ExFreePoolWithTag` call. This is the classic use-after-free mitigation pattern.

**Example patch:**
```c
  ExFreePoolWithTag(buffer, TAG);
// ADDED:
+ buffer = NULL;
```

**Why it matters:** Setting freed pointers to NULL prevents use-after-free exploitation by converting dangling pointer dereferences into NULL dereferences (which are typically non-exploitable in kernel mode).

---

#### `guard_before_free_added`

| Field | Value |
|---|---|
| Category | `lifetime_fix` |
| Confidence | 0.86 |
| Base Score Weight | 4.0 |
| Required Signals | `sink_group: pool_free`, `change_type: guard_added`, `guard_kind: null_check`, `proximity: near_sink` |

**What it detects:** A NULL check was added before a free operation, preventing double-free or free-of-invalid-pointer.

**Example patch:**
```c
// ADDED:
+ if (ptr != NULL) {
      ExFreePoolWithTag(ptr, TAG);
+     ptr = NULL;
+ }
```

**Why it matters:** Double-free vulnerabilities occur when a driver frees the same pool allocation twice. The Windows kernel pool allocator may have already reassigned that memory to another object, so freeing it again corrupts the pool metadata or destroys a live object. Attackers exploit this by spraying controlled objects into the freed slot between the first and second free, gaining arbitrary write or code execution. The NULL guard breaks the double-free chain entirely.

---

### User/Kernel Boundary Rules

#### `probe_for_read_or_write_added`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.93 (highest) |
| Base Score Weight | 6.0 |
| Required Signals | `sink_group: user_probe`, `change_type: validation_added`, `validation_kind: probe` |

**What it detects:** `ProbeForRead` or `ProbeForWrite` calls were added to validate user-mode pointers before kernel-mode access.

**Example patch:**
```c
// ADDED:
+ ProbeForRead(userBuffer, bufferLength, sizeof(UCHAR));
  RtlCopyMemory(kernelBuffer, userBuffer, bufferLength);
```

**Why it matters:** Missing probe calls allow user-mode code to pass arbitrary kernel pointers, potentially leading to arbitrary read/write primitives.

---

#### `previous_mode_gating_added`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.90 |
| Base Score Weight | 5.0 |
| Required Signals | `sink_group: user_probe`, `change_type: validation_added`, `validation_kind: previous_mode_gate` |

**What it detects:** `ExGetPreviousMode` gating was added to distinguish user-mode callers from kernel-mode callers.

**Example patch:**
```c
// ADDED:
+ if (ExGetPreviousMode() != KernelMode) {
+     ProbeForRead(buffer, length, 1);
+ }
```

**Why it matters:** Without previous-mode checking, a driver treats all callers identically. An attacker in user-mode can invoke a kernel path that was designed to only be called by other kernel components, bypassing trust assumptions. The classic exploitation pattern is supplying kernel-mode addresses through an IOCTL that skips `ProbeForRead`/`ProbeForWrite` because it assumed the caller was already in kernel mode. Adding `ExGetPreviousMode` gating ensures user-mode callers go through the full validation path.

---

#### `seh_guard_added_around_user_deref`

| Field | Value |
|---|---|
| Category | `user_boundary_check` |
| Confidence | 0.82 |
| Base Score Weight | 3.5 |
| Required Signals | `sink_group: exceptions`, `change_type: validation_added`, `validation_kind: seh_guard` |

**What it detects:** Structured exception handling (`__try`/`__except`) was added around pointer access, typically to safely handle user-mode pointer dereferences.

**Example patch:**
```c
// ADDED:
+ __try {
      value = *(PULONG)userPointer;
+ } __except(EXCEPTION_EXECUTE_HANDLER) {
+     return GetExceptionCode();
+ }
```

**Why it matters:** When a kernel driver dereferences a user-supplied pointer without SEH, the user can supply an invalid address (unmapped, paged-out, or a kernel address) causing an unhandled exception that blue-screens the system (denial of service) or, worse, is exploitable through controlled fault handling. Wrapping user pointer access in `__try`/`__except` ensures the driver gracefully handles invalid pointers instead of crashing. This is especially critical for `METHOD_NEITHER` IOCTLs where the driver receives raw user-mode pointers.

---

### Integer Overflow Rules

#### `safe_size_math_helper_added`

| Field | Value |
|---|---|
| Category | `int_overflow` |
| Confidence | 0.88 |
| Base Score Weight | 4.5 |
| Required Signals | `sink_group: io_sanitization`, `change_type: validation_added`, `validation_kind: safe_math_helper` |

**What it detects:** Raw arithmetic was replaced with safe math helpers like `RtlULongAdd`, `RtlSizeTMult`, etc.

**Example patch:**
```c
// REMOVED:
- totalSize = count * elementSize;
// ADDED:
+ if (!NT_SUCCESS(RtlSizeTMult(count, elementSize, &totalSize)))
+     return STATUS_INTEGER_OVERFLOW;
```

**Why it matters:** Integer overflows in size calculations lead to undersized allocations, which become exploitable heap overflows.

---

#### `alloc_size_overflow_check_added`

| Field | Value |
|---|---|
| Category | `int_overflow` |
| Confidence | 0.90 |
| Base Score Weight | 5.5 |
| Required Signals | `sink_group: pool_alloc`, `change_type: guard_added`, `guard_kind: overflow_check`, `proximity: near_sink` |

**What it detects:** An overflow or size check was added before a pool allocation (`ExAllocatePool*`).

**Example patch:**
```c
// ADDED:
+ if (count > ULONG_MAX / elementSize)
+     return STATUS_INTEGER_OVERFLOW;
  totalSize = count * elementSize;
  buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, totalSize, 'fooB');
```

**Why it matters:** If an attacker controls `count` or `elementSize` through an IOCTL, they can trigger an integer overflow in the multiplication so that `totalSize` wraps to a small value. The kernel then allocates a tiny buffer while the driver proceeds to fill it with `count * elementSize` bytes of data, causing a heap buffer overflow. These are among the most reliably exploitable kernel vulnerabilities because the attacker controls both the overflow amount and the data written. Adding an explicit overflow check before allocation completely prevents this class of attack.

---

### State Hardening Rules

#### `interlocked_refcount_added`

| Field | Value |
|---|---|
| Category | `state_hardening` |
| Confidence | 0.78 (lowest) |
| Base Score Weight | 3.0 |
| Required Signals | `sink_group: refcounting`, `change_type: hardening_added`, `hardening_kind: refcount` |

**What it detects:** `InterlockedIncrement`/`InterlockedDecrement`/`InterlockedExchange`/`InterlockedCompareExchange` operations were added to protect shared object lifetime.

**Example patch:**
```c
// ADDED:
+ InterlockedIncrement(&pObject->RefCount);
  UseObject(pObject);
  // ... later ...
+ if (InterlockedDecrement(&pObject->RefCount) == 0) {
+     ExFreePoolWithTag(pObject, 'jbO');
+ }
```

**Why it matters:** Without atomic reference counting, concurrent access from multiple threads or IRP handlers can create a race condition: one thread frees an object while another is still using it, producing a use-after-free. In kernel drivers, this is particularly dangerous because IRP dispatch routines, DPC callbacks, and work items can execute concurrently on different processors. Adding `Interlocked*` operations ensures the reference count is modified atomically, preventing the race. This has lower confidence (0.78) than other rules because interlocked operations are also used for benign concurrency patterns that are not security-relevant.

---

## Sink Groups

Sinks are dangerous API symbols. When a patch adds guards near sinks, it becomes high-signal for vulnerability detection.

| Sink Group | Symbol Count | Sink Bonus | Description |
|---|---|---|---|
| `memory_copy` | 6 | +1.5 | `RtlCopyMemory`, `memcpy`, `memmove`, `RtlMoveMemory`, `RtlCopyBytes`, `RtlCopyMappedMemory` |
| `string_copy` | 13 | +0.8 | `RtlStringCb*`, `RtlStringCch*`, `strcpy`, `wcscpy`, `strncpy`, `wcsncpy`, `strcat` |
| `pool_alloc` | 7 | +1.2 | `ExAllocatePool`, `ExAllocatePoolWithTag`, `ExAllocatePool2/3`, `ExAllocatePoolZero`, quota variants |
| `pool_free` | 2 | +1.0 | `ExFreePool`, `ExFreePoolWithTag` |
| `user_probe` | 5 | +1.5 | `ProbeForRead`, `ProbeForWrite`, `ProbeForReadGeneric`, `ProbeForWriteGeneric`, `ExGetPreviousMode` |
| `io_sanitization` | 9 | +1.0 | `RtlULongAdd/Sub/Mult`, `RtlULongLongAdd/Mult`, `RtlSizeTAdd/Mult`, `RtlUIntPtrAdd/Sub` |
| `exceptions` | 3 | +0.6 | `__try`, `__except`, `ExRaiseAccessViolation` |
| `refcounting` | 5 | +0.4 | `InterlockedIncrement/Decrement/Exchange/CompareExchange/Add` |

---

## Rule Evaluation Pipeline

The `SemanticRuleEngine.evaluate()` method processes each changed function through this pipeline:

### Step 1: Global Exclusion Check

Before evaluating any rules, the engine checks whether the diff is exclusively logging/tracing changes. If all added lines (up to 4) match exclusion patterns, the function is skipped.

**Exclusion patterns:**
- `logging_only` — matches `DbgPrint`, `WPP`, `EventWrite`, `Etw`
- `refactor_only` — matches code reordering/renaming without new guards

### Step 2: Sink Detection

Scans every line of the diff for sink symbols. Records:
- Which sink group matched
- The exact symbol name
- The line number in the diff
- Whether the line is added (`+`) or context

### Step 3: Guard Detection

Scans only added lines (`+` prefix) for guard/validation patterns. Each guard type has compiled regex patterns:

| Guard Type | What It Matches |
|---|---|
| `length_check` | `InputBufferLength <`, `sizeof() >`, `if (.*Len <` |
| `sizeof_check` | `sizeof(...)`, `RtlSizeT*` |
| `index_bounds` | `if (index < N)`, `idx >= count` |
| `null_check` | `if (ptr != NULL)`, `if (!ptr)`, `if (ptr)` |
| `null_assignment` | `ptr = NULL;`, `ptr = 0;` |
| `probe` | `ProbeForRead`, `ProbeForWrite` |
| `previous_mode_gate` | `ExGetPreviousMode`, `PreviousMode`, `KernelMode.*UserMode` |
| `seh_guard` | `__try`, `__except`, `ExRaiseAccessViolation` |
| `safe_math_helper` | `Rtl(ULong|SizeT|UIntPtr)(Add|Sub|Mult)`, `NT_SUCCESS(Rtl*` |
| `overflow_check` | `overflow`, `ULONG_MAX`, `SIZE_T_MAX`, `Rtl*Mult` |
| `refcount` | `Interlocked(Increment|Decrement|Exchange|CompareExchange)` |

### Step 4: Per-Rule Signal Matching

Each rule defines `required_signals` — a list of conditions that must ALL be satisfied:

| Signal Key | What It Checks |
|---|---|
| `sink_group: <group>` | At least one sink from the specified group exists in the diff |
| `change_type: guard_added` | At least one guard/validation type was detected in added lines |
| `guard_kind: <type>` | A specific guard type (e.g., `length_check`) was detected |
| `validation_kind: <type>` | Alias for guard_kind, used for user boundary rules |
| `hardening_kind: <type>` | Alias for guard_kind, used for lifetime/state rules |
| `proximity: <mode>` | Guard and sink are within required proximity (see below) |

If ANY required signal fails, the rule does not match.

### Step 5: Proximity Check

Proximity constraints ensure the guard is actually related to the sink, not just coincidentally present in the same function:

| Proximity Mode | Constraint | Typical Use |
|---|---|---|
| `near_sink` | Guard within 10 lines of sink | Bounds checks before memcpy |
| `immediately_after_sink` | Guard 0-3 lines after sink | NULL assignment after free |
| `before_sink` | Guard 1-10 lines before sink | Overflow check before alloc |

---

## Scoring Model

After rule evaluation, findings are scored to rank them by exploit relevance.

### Score Composition

```
final_score = (semantic_score + reachability_score + sink_score) - penalties
```

Clamped to `[0.0, 15.0]`.

### Semantic Score

```
semantic_score = rule_base_weight * rule_confidence * category_multiplier
```

**Rule base weights** (from `scoring.yaml`):

| Rule | Weight |
|---|---|
| `added_len_check_before_memcpy` | 6.0 |
| `probe_for_read_or_write_added` | 6.0 |
| `alloc_size_overflow_check_added` | 5.5 |
| `null_after_free_added` | 5.0 |
| `previous_mode_gating_added` | 5.0 |
| `added_struct_size_validation` | 4.5 |
| `safe_size_math_helper_added` | 4.5 |
| `guard_before_free_added` | 4.0 |
| `added_index_bounds_check` | 4.0 |
| `seh_guard_added_around_user_deref` | 3.5 |
| `interlocked_refcount_added` | 3.0 |

**Category multipliers:**

| Category | Multiplier |
|---|---|
| `user_boundary_check` | 1.10x |
| `bounds_check` | 1.05x |
| `int_overflow` | 1.05x |
| `lifetime_fix` | 1.05x |
| `state_hardening` | 0.95x |

### Reachability Score

```
reachability_score = reachability_bonus[class]
```

| Reachability Class | Bonus |
|---|---|
| `ioctl` | +4.0 |
| `irp` | +2.5 |
| `pnp` | +2.0 |
| `internal` | +0.5 |
| `unknown` | +0.0 |

When full reachability analysis (Stage 5) has not run, the engine uses `surface_area` heuristics as a proxy — if the function code contains IOCTL-related strings, it approximates as `ioctl`.

### Sink Score

```
sink_score = sum(sink_bonus[group]) * min(1.0, semantic_confidence)
```

### Penalties

| Penalty Source | Values |
|---|---|
| Pairing decision | accept: 0, quarantine: -2.0, reject: -999 |
| Noise risk | low: 0, medium: -1.0, high: -2.5 |
| Matching quality | high: 0, medium: -0.8, low: -1.8 |

### Gating

Gates cap or drop findings that fail confidence thresholds:

| Gate | Threshold | Effect |
|---|---|---|
| Semantic confidence hard min | < 0.45 | Finding dropped entirely |
| Semantic confidence soft min | < 0.60 | Score capped at 5.0 |
| Matching confidence min | < 0.40 | Score capped at 3.0 |
| Reachability confidence soft min | < 0.55 | Reachability bonus multiplied by 0.70 |

---

## Rule YAML Schema

Each rule in `semantic_rules.yaml` must follow this structure:

```yaml
- rule_id: <snake_case_identifier>      # Stable, unique ID
  category: <category_id>               # One of the 5 categories
  confidence: <0.0-1.0>                 # Rule's inherent precision
  required_signals:                      # ALL must be satisfied
    - sink_group: <group_name>           # Optional: require sink presence
    - change_type: <type>                # guard_added | validation_added | hardening_added | post_free_hardening
    - guard_kind: <guard_type>           # Specific guard pattern to require
    - proximity: <mode>                  # near_sink | immediately_after_sink | before_sink
  excluded_patterns:                     # Global exclusions that apply
    - logging_only
    - refactor_only
  plain_english_summary: <string>        # Human-readable explanation
  report:                                # Fields for report generation
    sinks: [<sink_group>]
    added_checks: [<check_type>]
```

---

## Adding New Rules

To add a new semantic rule:

1. **Choose a category** from the 5 existing categories, or propose a new one in `semantic_rules.yaml` under `categories:`.

2. **Define required signals** — what must be present in the diff for the rule to fire. Be conservative: require at least a `change_type` and a specific `guard_kind` or `sink_group`.

3. **Set confidence** based on expected precision:
   - 0.90-0.95 — Very high precision, direct guard before known-dangerous sink
   - 0.85-0.90 — High precision, clear security-relevant hardening
   - 0.78-0.85 — Moderate precision, pattern is security-relevant but may occasionally match benign changes

4. **Add guard patterns** if the rule uses a new guard type. Edit `_compile_guard_patterns()` in `rule_engine.py` to add regex patterns for the new guard type.

5. **Add sink symbols** if the rule references a new sink group. Edit `rules/sinks.yaml` to add the group and its symbols.

6. **Add scoring weight** in `rules/scoring.yaml` under `weights.semantic_rule_base`.

7. **Write tests** in `tests/unit/test_rule_engine.py` — include both positive (rule should fire) and negative (rule should not fire) test cases.

---

## Output Format

When a rule matches, it produces a `RuleHit`:

```json
{
  "rule_id": "added_len_check_before_memcpy",
  "category": "bounds_check",
  "confidence": 0.92,
  "sinks": ["memory_copy"],
  "indicators": ["RtlCopyMemory", "InputBufferLength <"],
  "why_matters": "Added a length/bounds check before a memory copy operation.",
  "diff_snippet": "..."
}
```

After scoring, each finding gains additional fields:

```json
{
  "final_score": 8.42,
  "score_breakdown": {
    "semantic": 5.80,
    "reachability": 4.0,
    "sinks": 1.5,
    "penalties": 0.0,
    "gates": []
  }
}
```

---

## Design Principles

1. **Conservative** — Fewer findings, higher confidence. If in doubt, do not trigger.
2. **Explainable** — Every hit includes a plain-English rationale, detected sinks, and added checks.
3. **Sink-aware** — Rules consider proximity to dangerous APIs, not just pattern presence.
4. **Transparent scoring** — Every score is reproducible from `scoring.yaml` with a full breakdown.
5. **Non-speculative** — Rules detect explicit code changes, not inferred intent.
