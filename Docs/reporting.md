# AutoPiff – Reporting & Output Specification

## Purpose

The reporting stage converts AutoPiff’s internal analysis artifacts into:

1. A **concise, human-readable report** for vulnerability researchers
2. A **structured, machine-readable report** for downstream automation

This stage is intentionally opinionated. Reports must be:

* **Short**
* **Ranked**
* **Justified**
* **Actionable**

If a human cannot decide *where to look first* in under **2 minutes**,
the report has failed.

---

## Inputs (Required Artifacts)

The reporting stage consumes the following artifacts:

* `pairing.json`
* `matching.json`
* `semantic_deltas.json`
* `reachability.json`
* `ranking.json`

If any required artifact is missing:

* Emit a **partial report**
* Clearly state which stages were unavailable and how this impacts results

---

## Outputs

### 1) Human Report (Primary)

**File:** `report.md`

**Audience:**

* CVE hunters
* Driver reverse engineers
* Exploit developers

This report must be understandable **without any AutoPiff context**.

---

### 2) Machine Report (Secondary)

**File:** `report.json`

**Audience:**

* Automation pipelines
* Triage dashboards
* Validation harnesses

Must conform to `schemas/report.schema.json`.

---

## Human Report Structure (`report.md`)

### Header

```md
# AutoPiff Patch Intelligence Report

Driver: <original_filename or fallback name>
Architecture: <x64 | x86 | arm64>
Old Version: <version / timestamp / sha>
New Version: <version / timestamp / sha>

Pairing Decision: <accept | quarantine>
Noise Risk: <low | medium | high>
Pair Confidence: <0.00–1.00>
```

---

### Executive Summary (Mandatory)

```md
## Executive Summary

AutoPiff identified <N> security-relevant logic changes.
Of these, <M> are externally reachable.

Top risk category:
- <e.g. bounds check added before memcpy>

Recommended starting point:
- <FunctionName> (Score: X.XX)
```

Rules:

* ≤ **6 sentences or bullet points**
* No technical detail beyond what is needed to orient the reader

---

### Top Findings (Mandatory)

```md
## Top Findings
```

Rules:

* Show **at most 10 findings**
* Sorted by **final score (descending)**
* Each finding must fit on **one screen** (~15–20 lines)

---

#### Finding Template

```md
### [Rank #1] <FunctionName>
Score: <X.XX> | Confidence: <0.00–1.00>

**Why this matters**
- <Plain-language explanation of the fix>

**What changed**
- <Guard added / size math fixed / lifetime fix>
- <Rule IDs that fired>

**Reachability**
- Path: <IRP_MJ_DEVICE_CONTROL → IOCTL 0xXXXX → FunctionName>
- Reachability Class: <ioctl | irp | pnp | internal | unknown>

**Key Indicators**
- Sink(s): <RtlCopyMemory, memcpy, ExFreePool, etc.>
- Added Check(s): <length check, NULL check, ProbeForRead, etc.>

**Diff Hint**
- <One-line hint telling the analyst what to inspect>
```

**Hard rule:**
If a finding cannot explain *why it matters* in plain English,
**it must not be included**.

---

### Secondary Findings (Optional)

```md
## Secondary Findings
```

* Lower-ranked or lower-confidence changes
* Maximum **10 entries**
* Reduced detail (reachability trace optional)

---

### Skipped or Deprioritized Changes (Mandatory)

```md
## Skipped or Deprioritized Changes
```

Examples:

* “Large refactor detected; semantic diff suppressed”
* “Logging-only changes ignored”
* “Unreachable internal helper changes”

Purpose:

* Build analyst trust
* Explain *why silence exists*

---

### Analyst Notes (Optional)

```md
## Analyst Notes
```

Only include important caveats, e.g.:

* “Driver uses custom IOCTL encoding”
* “No symbols available; function names inferred”

---

## Machine Report (`report.json`) – High-Level Schema

```json
{
  "driver": {
    "name": "",
    "arch": "",
    "old": { "sha256": "", "version": "" },
    "new": { "sha256": "", "version": "" }
  },

  "pairing": {
    "decision": "",
    "noise_risk": "",
    "confidence": 0.0
  },

  "summary": {
    "total_findings": 0,
    "reachable_findings": 0,
    "top_categories": ["bounds_check", "lifetime_fix"]
  },

  "findings": [
    {
      "rank": 1,
      "function": "",
      "score": 0.0,
      "confidence": 0.0,
      "rule_ids": [],
      "category": "",
      "reachability": {
        "class": "",
        "path": []
      },
      "sinks": [],
      "added_checks": [],
      "why": ""
    }
  ],

  "metadata": {
    "autopiff_version": "",
    "generated_at": ""
  }
}
```

---

## Ranking Presentation Rules

* Scores must be reproducible from `rules/scoring.yaml`
* **Confidence ≠ score**

  * Confidence reflects rule reliability
  * Score reflects prioritization
* Do **not** imply exploitability or severity
* Avoid CVSS or severity language

---

## Style Rules (Strict)

* Plain English; minimal jargon
* No assembly dumps
* No raw decompiler output
* No screenshots
* No speculation framed as fact

Preferred phrasing:

* “suggests”
* “likely indicates”
* “appears consistent with”

---

## Failure Modes & Fallbacks

If critical stages failed:

* Clearly state limitations at the top of the report
* Still list any high-confidence findings available

Example:

> “Reachability analysis unavailable; findings are unranked by exposure.”

---

## Success Criteria

A report is successful if:

* A researcher can choose a starting function in under **2 minutes**
* Each finding’s rationale is understandable **without reading code**
* False positives are explainable, not confusing

---

## Non-Goals

The report must **not**:

* Attempt exploit walkthroughs
* Provide PoC code
* Claim a vulnerability exists
* Replace manual analysis

All future changes must be recorded in `docs/DECISIONS.md`.

