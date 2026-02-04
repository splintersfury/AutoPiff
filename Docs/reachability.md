# AutoPiff – Reachability Tagging Specification (v1, Conservative)

## Purpose

Reachability tagging estimates **whether a changed function can be reached from
external inputs** (primarily user-mode) versus being reachable only through
internal driver logic.

This stage exists to **reduce noise**, not to prove exploitability.

Reachability is:

* **Heuristic**
* **Evidence-based**
* **Conservative by default**

If reachability cannot be justified with clear evidence, it must be marked
`unknown`.

---

## Scope (v1)

This specification covers **Windows kernel drivers** using standard IRP-based
dispatch.

Explicitly in scope:

* IRP major function dispatch
* IOCTL-based device control paths
* Direct callgraph reachability

Explicitly out of scope (v1):

* Network reachability claims
* Fast I/O callbacks
* Minifilter callbacks
* WMI, ETW, or undocumented callback frameworks
* Dynamic dispatch via opaque function pointers without static anchors

---

## Inputs

### Required Artifacts

* `matching.json`
* `semantic_deltas.json`

### Required Binary

* Driver binary (preferably the **new** version)

### Optional Artifacts

* `symbols.json` (improves naming and confidence only)

---

## Outputs

### Artifact: `reachability.json`

Each semantic delta must receive **exactly one reachability tag** with supporting
evidence.

High-level schema:

```json
{
  "autopiff_stage": "reachability",
  "driver": {
    "sha256": "",
    "arch": ""
  },
  "dispatch": {
    "driver_entry": "",
    "major_functions": {
      "IRP_MJ_CREATE": "",
      "IRP_MJ_CLOSE": "",
      "IRP_MJ_DEVICE_CONTROL": "",
      "IRP_MJ_INTERNAL_DEVICE_CONTROL": ""
    }
  },
  "ioctls": [
    {
      "ioctl": "0xXXXXXXXX",
      "handler": "",
      "confidence": 0.0,
      "evidence": []
    }
  ],
  "tags": [
    {
      "function": "",
      "reachability_class": "ioctl | irp | pnp | internal | unknown",
      "confidence": 0.0,
      "paths": [],
      "evidence": []
    }
  ],
  "notes": []
}
```

---

## Reachability Classes (Authoritative)

### `ioctl`

The function is reachable via:

* `IRP_MJ_DEVICE_CONTROL` or `IRP_MJ_INTERNAL_DEVICE_CONTROL`, and
* One of the following is true:

  * The function **is** the device-control dispatch handler
  * The function is directly called from an IOCTL case handler
  * The function is within **N hops** (default: `N = 2`) from an IOCTL case handler

IOCTL value extraction is **preferred but not required**.

---

### `irp`

The function is reachable via a major IRP handler **other than device control**,
for example:

* `IRP_MJ_CREATE`
* `IRP_MJ_CLOSE`
* `IRP_MJ_READ`
* `IRP_MJ_WRITE`

The function must be:

* The IRP handler itself, or
* Within **N hops** from the handler via direct calls

---

### `pnp`

The function is reachable via:

* PnP, power, or device lifecycle dispatch paths

This classification requires **explicit evidence** (e.g. handler assignment or
direct calls). If evidence is weak, prefer `unknown`.

---

### `internal`

The function appears reachable only through:

* Internal helpers
* Worker threads
* Timers, DPCs, or deferred execution
* Code paths with no clear external entry point

This class indicates **low external exposure**.

---

### `unknown`

Reachability cannot be determined with sufficient confidence.

This is the **default** when:

* Dispatch handlers cannot be reliably identified
* Callgraph resolution fails
* Evidence is indirect or speculative

---

## Extraction Workflow

### Step 1 — Identify `DriverEntry`

Preferred indicators:

* Entry-point function writes to `DriverObject->MajorFunction[...]`
* Calls to `IoCreateDevice`, `IoCreateDeviceSecure`, or `IoCreateSymbolicLink`
* PDB symbol `DriverEntry` (if available)

Fallback:

* Use PE entry point with **reduced confidence**

---

### Step 2 — Extract Major Function Handlers

Detect assignments of the form:

```
DriverObject->MajorFunction[i] = Handler
```

At minimum, attempt to resolve:

* `IRP_MJ_DEVICE_CONTROL`
* `IRP_MJ_INTERNAL_DEVICE_CONTROL`
* `IRP_MJ_CREATE`
* `IRP_MJ_CLOSE`

If handlers are assigned via table copy or indirection:

* Attempt to resolve the table
* If unsuccessful, record the major function as **unknown**

---

### Step 3 — Identify IOCTL Dispatch Logic

Within the device-control handler:

* Identify the source of `IoControlCode`
* Detect switch/jump-table patterns over `IoControlCode`
* Extract constant IOCTL values when possible
* Identify per-case call targets as IOCTL handlers

If:

* IOCTL values cannot be recovered, but
* Device-control structure is clearly present,

Then:

* Tag reachability as `ioctl`
* Reduce confidence
* Record evidence: `ioctl_values_unknown`

---

### Step 4 — Callgraph-Based Tagging

For each function in `semantic_deltas.json`:

1. If the function **is** a major handler → tag accordingly
2. Else if the function is called from an IOCTL case handler within `N` hops → `ioctl`
3. Else if called from another IRP handler within `N` hops → `irp`
4. Else → `internal` or `unknown`

Only **direct callgraph edges** are allowed.
No speculative edges.

---

## Confidence Guidance

| Situation                          | Confidence |
| ---------------------------------- | ---------- |
| Function is device-control handler | 0.95       |
| Direct call from IOCTL case        | 0.85       |
| Within 2 hops from IOCTL case      | 0.70       |
| Direct IRP handler                 | 0.85       |
| Within 2 hops from IRP handler     | 0.65       |
| Indirect / table-based inference   | ≤ 0.55     |
| Weak or ambiguous evidence         | ≤ 0.40     |

Confidence must always be justified by evidence.

---

## Conservative Rules (Hard Requirements)

* Do **not** claim network reachability
* Do **not** infer reachability from strings alone
* Do **not** assume user-mode reachability without an IRP path
* Prefer `unknown` over speculative tagging
* Every tag must include **explicit evidence**

---

## Evidence Examples

Valid evidence strings include:

* `major_function_assignment`
* `switch_on_IoControlCode`
* `ioctl_case_call`
* `direct_callgraph_edge`
* `driver_entry_dispatch_setup`

Evidence must be concrete and auditable.

---

## Notes & Diagnostics

This stage must emit human-readable notes, e.g.:

* “Identified IRP_MJ_DEVICE_CONTROL handler: sub_140012340”
* “Recovered 4 IOCTL constants; 1 maps to semantic deltas”
* “Indirect handler table detected; reachability confidence reduced”

---

## Failure Handling

If reachability analysis fails entirely:

* Tag all findings as `unknown`
* Emit a clear note explaining why

Example:

> “MajorFunction assignments could not be resolved; reachability tagging skipped.”

---

## Success Criteria

Reachability tagging is successful if:

* Obvious externally reachable paths are identified
* Internal-only helpers are deprioritized
* Uncertainty is made explicit, not hidden

---

## Versioning

This document defines **Reachability Specification v1**.

All changes must be recorded in `docs/DECISIONS.md`.

