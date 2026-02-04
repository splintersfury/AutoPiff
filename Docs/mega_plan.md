# AutoPiff – Automated Patch Intelligence & Fix Finder

## Mission
AutoPiff automatically compares two adjacent versions of a Windows kernel driver
and produces a high-signal report of security-relevant changes:
bounds checks, pointer lifetime fixes, user/kernel boundary validation, and
size math hardening.

It answers:
> “What changed that looks like a vulnerability fix, how reachable is it, and why?”

---

## Primary Use Case
Input: two driver binaries (old/new) that are likely the same product + arch and close in version.
Output: a ranked shortlist of changed, reachable functions and the semantic reasons they matter.

Optimization target: **precision + actionable ranking**, not exhaustive diff coverage.

---

## Non-Goals
AutoPiff does NOT:
- guarantee exploitability
- generate exploits or PoCs
- replace human RCA
- attempt full semantic equivalence of refactors
- attempt cross-architecture diffing

---

## Repository Layout (Authoritative)

```
autopiff/
├── Docs/
│   ├── mega_plan.md           # This file - master specification
│   ├── decisions.md           # Design decision log
│   ├── semantic_rules.md      # Rule philosophy & categories
│   ├── reachability.md        # Reachability algorithm spec
│   └── reporting.md           # Report format specification
├── rules/
│   ├── semantic_rules.yaml    # 10 conservative semantic rules
│   ├── sinks.yaml             # Dangerous API catalog
│   └── scoring.yaml           # Ranking/scoring model
├── schemas/
│   ├── pairing.schema.json    # Stage 1 output contract
│   ├── symbols.schema.json    # Stage 2 output contract
│   ├── matching.schema.json   # Stage 3 output contract
│   ├── semantic_deltas.schema.json  # Stage 4 output contract
│   └── reachability.schema.json     # Stage 5 output contract
├── services/
│   ├── karton-patch-differ/   # Stages 1-4 (combined)
│   │   ├── karton_patch_differ.py   # Main Karton service
│   │   ├── rule_engine.py           # YAML rule evaluator
│   │   ├── ExportDecompiled.py      # Ghidra script
│   │   ├── requirements.txt
│   │   └── Dockerfile
│   └── karton-reachability/   # Stage 5
│       ├── karton_reachability.py
│       └── Dockerfile
├── ghidra/
│   └── scripts/
│       └── autopiff_reachability.py  # Binary reachability analysis
└── tests/
    └── unit/
        ├── test_reachability_schema.py
        ├── test_patch_differ_schemas.py
        └── test_rule_engine.py
```


---

## Pipeline Stages (Karton-first)

AutoPiff is a sequence of stages. Each stage:
1) consumes prior artifacts (from MWDB)
2) emits a JSON artifact + metadata
3) never relies on chat memory

### Stage 1 — Pairing & Noise Gating
Goal: ensure old/new are diff-worthy; reject or quarantine noisy rebuilds.

Outputs:
- `pairing.json` (decision, confidence, noise_risk)
- normalized PE metadata + hashes

Docs: `docs/pairing.md`  
Rules: `rules/pairing.yaml`

### Stage 2 — Symbolization & Anchoring
Goal: maximize stable function identity.
Sources: PDB (if available), Ghidra FunctionID/BSim, signature heuristics.

Outputs:
- `symbols.json` (coverage, pdb_found, anchors)
- updated Ghidra project artifacts (cached)

Docs: `docs/symbols.md`

### Stage 3 — Function Matching
Goal: map old ↔ new functions with confidence scores (reduce cascaded diffs).

Outputs:
- `matching.json` (matched pairs, unmatched lists, confidence)

Docs: `docs/matching.md`

### Stage 4 — Semantic Delta Extraction
Goal: turn raw diffs into semantic signals (guards added, size math fixes, lifetime fixes).

Outputs:
- `semantic_deltas.json` (rule hits per function pair, rationale, confidence)

Docs: `docs/semantic_rules.md`  
Rules: `rules/semantic_rules.yaml`, `rules/sinks.yaml`

### Stage 5 — Reachability Tagging
Goal: determine external reachability via IRP major funcs, IOCTL switch cases, dispatch tables.
Tag deltas by reachability class: `ioctl`, `irp`, `pnp`, `internal`, `unknown`.

Outputs:
- `reachability.json` (paths, tags, extracted IOCTLs)

Docs: `docs/reachability.md`

### Stage 6 — Scoring & Ranking
Goal: rank findings by exploit relevance using a transparent scoring model.

Outputs:
- `ranking.json` (top findings, score breakdown)

Docs: `docs/scoring.md`  
Rules: `rules/scoring.yaml`

### Stage 7 — Report Generation
Goal: produce one compact human report + machine report.
Human report should be “CVE-hunter friendly”.

Outputs:
- `report.md`
- `report.json`

Docs: `docs/reporting.md`

---

## Artifact Contracts (Hard Rule)
Each stage must emit:
- a JSON artifact conforming to `schemas/*.schema.json`
- minimal “explainability” fields:
  - what changed
  - which rule fired
  - confidence
  - why it matters
  - where it’s reachable (if known)

No stage is allowed to output only free-form logs.

---

## Design Principles (Hard Rule)
- Prefer skipping pairs over generating noisy diffs
- Reachability beats raw “changed bytes”
- Rules must be declarative (YAML) whenever possible
- Every finding must include rationale + rule IDs
- Keep the report short: “top 10 with receipts”
- Assume iterative tuning; record changes in `docs/DECISIONS.md`

---

## Agent Navigation Contract
AI agents must:
1) start at `docs/MEGA_PLAN.md`
2) read the stage doc they implement
3) treat `rules/*.yaml` as authoritative
4) implement schemas exactly; do not invent new fields
5) update `docs/DECISIONS.md` when making design changes

---

## Implementation Status

| Stage | Service | Status | Notes |
|-------|---------|--------|-------|
| 1 | karton-patch-differ | **Implemented** | Pairing, noise gating, arch matching |
| 2 | karton-patch-differ | **Implemented** | Ghidra decompilation, function extraction |
| 3 | karton-patch-differ | **Implemented** | Hash-based LCS alignment |
| 4 | karton-patch-differ | **Implemented** | YAML rule evaluation, semantic deltas |
| 5 | karton-reachability | **Implemented** | IRP/IOCTL dispatch analysis |
| 6 | karton-ranking | Planned | Scoring model defined in rules/scoring.yaml |
| 7 | karton-report | Planned | Report spec in docs/reporting.md |

### Integration Notes (v1.1)

Stages 1-4 have been consolidated into a single `karton-patch-differ` service,
adapted from driver_analyzer with AutoPiff enhancements:

- **YAML-driven rules**: Semantic rules in `rules/semantic_rules.yaml`
- **Sink awareness**: Dangerous API catalog in `rules/sinks.yaml`
- **Schema validation**: All outputs validated against `schemas/*.schema.json`
- **Explainability**: Every delta includes rule_id, confidence, why_matters
- **MWDB integration**: Artifacts uploaded with proper parent/child relationships

---

## Current Focus (v1)
AutoPiff v1 prioritizes:
- correct pairing/noise gating
- reachability extraction (DeviceControl/IOCTL)
- guard+sink semantic rules + ranking
- readable reporting

Advanced goals (future):
- fuzzy `.text` similarity and build-chain clustering
- deeper semantic equivalence (refactor suppression)
- partial callgraph reachability scoring