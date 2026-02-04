"""
AutoPiff Patch Differ Service

Implements Stages 1-4 of the AutoPiff pipeline:
- Stage 1: Pairing & Noise Gating
- Stage 2: Symbolization & Anchoring
- Stage 3: Function Matching
- Stage 4: Semantic Delta Extraction

Adapted from driver_analyzer with AutoPiff enhancements:
- YAML-driven semantic rules
- Schema-validated JSON artifacts
- Confidence scoring and explainability
"""

from .karton_patch_differ import PatchDifferKarton
from .rule_engine import SemanticRuleEngine

__all__ = ["PatchDifferKarton", "SemanticRuleEngine"]
