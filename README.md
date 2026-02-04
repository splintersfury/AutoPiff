# AutoPiff

**Automated Patch Intelligence and Finding Framework**

A semantic analysis engine for detecting vulnerability fixes in Windows kernel driver patches. AutoPiff uses conservative YAML-defined rules to identify security-relevant code changes with high precision and explainability.

## Overview

AutoPiff analyzes the differences between vulnerable and patched driver versions to automatically detect:

- **Use-After-Free fixes** (null assignments after `ExFreePool`)
- **Bounds check additions** (length validation before `memcpy`)
- **User/kernel boundary hardening** (`ProbeForRead`/`ProbeForWrite`)
- **Integer overflow protections** (safe math helpers)
- **State hardening** (interlocked refcounting)

### Key Features

- **High Precision**: Conservative rules minimize false positives
- **Explainable**: Every finding includes rationale and evidence
- **Sink-Aware**: Rules consider proximity to dangerous APIs
- **Scoring Model**: Ranks findings by exploitability and reachability
- **Karton Integration**: Runs as a service in malware analysis pipelines

## Why AutoPiff?

### The Problem: Needle in a Haystack

```
Vendor releases 500 driver updates/year
├── 490 are feature/performance/cosmetic changes
├── 8 are minor bug fixes
└── 2 are silent security fixes (no CVE assigned)

Without automation: Manually review 500 to find 2
With AutoPiff:      Review 10 high-scorers to find 2
```

Security patches are often released without CVE assignments. Manually reverse engineering every driver update to find the security-relevant ones is not feasible. AutoPiff solves this asymmetry problem by automatically surfacing the changes that matter.

### What AutoPiff Automates

| Phase | Manual Effort | With AutoPiff | Time Saved |
|-------|---------------|---------------|------------|
| Version pairing | 5-15 min/driver | Automatic | ~100% |
| Decompilation | 2-10 min/binary | Batched, parallel | ~95% |
| Function matching | 30-60 min/pair | Instant | ~100% |
| Identifying security changes | 2-8 hours/pair | Seconds | ~99% |
| Initial triage & ranking | 1-2 hours | Instant | ~100% |
| Report generation | 30-60 min | Instant | ~100% |

**Total: 4-12 hours per driver pair → 2-5 minutes**

### What Still Requires Human Expertise

```
┌─────────────────────────────────────────────────────────────────┐
│  AUTOMATED by AutoPiff                                          │
│  ├── Find the needle: "This function changed near ExFreePool"   │
│  ├── Classify: "Looks like a use-after-free fix"                │
│  └── Rank: "Score 5.5 - worth investigating"                    │
├─────────────────────────────────────────────────────────────────┤
│  STILL MANUAL (Your expertise)                                  │
│  ├── Confirm exploitability: "Can I actually trigger this?"     │
│  ├── Root cause analysis: "Why was this vulnerable?"            │
│  ├── Exploit development: "How do I reach this sink?"           │
│  └── Impact assessment: "What's the real-world risk?"           │
└─────────────────────────────────────────────────────────────────┘
```

AutoPiff doesn't replace exploitation research—it makes it **feasible at scale** by automating the reconnaissance phase.

### Use Cases

**1. Silent Patch Detection**
- Monitor drivers for security fixes released without CVEs
- Get alerts when high-scoring semantic deltas appear
- Catch vulnerabilities before they're publicly disclosed

**2. 1-Day Vulnerability Research**
- When a CVE is announced, quickly identify the exact patch
- Correlate patch patterns with vulnerability classes
- Accelerate exploit development timelines

**3. Vendor Security Auditing**
- Analyze all versions of a driver family over time
- Generate timelines showing when fixes appeared
- Identify patterns in how vendors address vulnerabilities

**4. Historical CVE Corpus Building**
- Process known CVE driver pairs to build training data
- Validate and improve detection rules
- Create a knowledge base of patch signatures

## Architecture

```
Driver Upload (MWDB)
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│                   AutoPiff Pipeline                      │
├─────────────────────────────────────────────────────────┤
│  Stage 1: Version Pairing                               │
│  └─ Find prior version by product tag + version attr    │
├─────────────────────────────────────────────────────────┤
│  Stage 2: Decompilation (Ghidra)                        │
│  └─ Headless decompile both versions to C               │
├─────────────────────────────────────────────────────────┤
│  Stage 3: Function Matching                             │
│  └─ Hash-based matching, compute match rate             │
├─────────────────────────────────────────────────────────┤
│  Stage 4: Semantic Delta Extraction                     │
│  └─ Run rule engine on changed functions                │
├─────────────────────────────────────────────────────────┤
│  Stage 5: Scoring & Ranking                             │
│  └─ Apply scoring.yaml model, rank by final_score       │
└─────────────────────────────────────────────────────────┘
       │
       ▼
  JSON Report (attached to MWDB sample)
```

## Semantic Rules

AutoPiff includes 11 conservative rules across 5 categories:

| Category | Rules | Example Detection |
|----------|-------|-------------------|
| `bounds_check` | 3 | Added length check before memcpy |
| `lifetime_fix` | 2 | Null assignment after ExFreePool |
| `user_boundary_check` | 3 | Added ProbeForRead/ProbeForWrite |
| `int_overflow` | 2 | Safe math helper usage |
| `state_hardening` | 1 | Interlocked refcount operations |

### Sink Groups

The rule engine tracks 50+ dangerous API symbols across 8 sink groups:

- `memory_copy`: RtlCopyMemory, memcpy, memmove
- `pool_alloc`: ExAllocatePool, ExAllocatePoolWithTag
- `pool_free`: ExFreePool, ExFreePoolWithTag
- `user_probe`: ProbeForRead, ProbeForWrite
- `io_sanitization`: RtlULongAdd, RtlSizeTMult
- `exceptions`: __try, __except
- `string_copy`: strcpy, wcsncpy
- `refcounting`: InterlockedIncrement/Decrement

## Scoring Model

Findings are scored using a configurable model (`rules/scoring.yaml`):

```
final_score = semantic_score + reachability_bonus + sink_bonus - penalties
```

**Score Components:**
- **Semantic Score**: Rule weight × confidence × category multiplier
- **Reachability Bonus**: IOCTL (+4.0), IRP (+2.5), PnP (+2.0), Internal (+0.5)
- **Sink Bonus**: memory_copy (+1.5), user_probe (+1.5), pool_alloc (+1.2)
- **Penalties**: Low matching quality, high noise risk

**Gating:**
- Findings with confidence < 0.45 are dropped
- Matching confidence < 0.40 caps score at 3.0

## Installation

### As Karton Service (Recommended)

```bash
# Clone the repository
git clone https://github.com/splintersfury/AutoPiff.git
cd AutoPiff

# Build and run with Docker Compose
docker-compose up -d
```

### Standalone Library

```bash
pip install pyyaml

# Use the rule engine directly
from services.karton_patch_differ.rule_engine import SemanticRuleEngine

engine = SemanticRuleEngine('rules/semantic_rules.yaml', 'rules/sinks.yaml')
hits = engine.evaluate(func_name, old_code, new_code, diff_lines)
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MWDB_API_URL` | MWDB Core API endpoint | `http://mwdb-core:8080/api/` |
| `KARTON_REDIS_HOST` | Redis host for Karton | `karton-redis` |
| `AUTOPIFF_GHIDRA_TIMEOUT` | Ghidra decompilation timeout (sec) | `2400` |

### Rule Customization

Edit `rules/semantic_rules.yaml` to add or modify rules:

```yaml
rules:
  - rule_id: my_custom_rule
    category: bounds_check
    confidence: 0.85
    required_signals:
      - sink_group: memory_copy
      - change_type: guard_added
      - guard_kind: length_check
    plain_english_summary: Added length validation before memory copy.
```

## Output Format

AutoPiff produces JSON reports attached to MWDB samples:

```json
{
  "pairing": {
    "driver_new": {"sha256": "...", "version": "2.0.9.0"},
    "driver_old": {"sha256": "...", "version": "2.0.8.0"},
    "decision": "accept",
    "confidence": 0.95
  },
  "semantic_deltas": {
    "deltas": [
      {
        "function": "HandleIoctl",
        "rule_id": "null_after_free_added",
        "category": "lifetime_fix",
        "confidence": 0.88,
        "sinks": ["pool_free"],
        "final_score": 5.5,
        "why_matters": "Pointer is now set to NULL after freeing memory."
      }
    ],
    "summary": {
      "total_deltas": 1,
      "top_score": 5.5,
      "match_rate": 100.0
    }
  }
}
```

## Integration with driver_analyzer

AutoPiff is designed to work with [driver_analyzer](https://github.com/splintersfury/driver_analyzer):

```yaml
# In driver_analyzer/docker-compose.yml
karton-driver-patch-differ:
  build:
    context: ../AutoPiff
    dockerfile: services/karton-patch-differ/Dockerfile
  volumes:
    - ../AutoPiff/rules:/app/rules:ro
```

## Project Structure

```
AutoPiff/
├── rules/
│   ├── semantic_rules.yaml    # 11 detection rules
│   ├── sinks.yaml             # 50 dangerous API symbols
│   └── scoring.yaml           # Scoring model configuration
├── services/
│   └── karton-patch-differ/
│       ├── karton_patch_differ.py  # Main Karton service
│       ├── rule_engine.py          # Semantic rule evaluator
│       ├── ExportDecompiled.py     # Ghidra script
│       ├── Dockerfile
│       └── requirements.txt
├── schemas/
│   └── autopiff_report.schema.json
├── tests/
├── docker-compose.yml
└── README.md
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Karton](https://github.com/CERT-Polska/karton) - Distributed malware processing framework
- [MWDB Core](https://github.com/CERT-Polska/mwdb-core) - Malware repository
- [Ghidra](https://ghidra-sre.org/) - NSA's software reverse engineering framework
