"""
AutoPiff Semantic Rule Engine

Evaluates YAML-defined semantic rules against function diffs.
Produces high-precision, explainable delta detections.
"""

import re
import yaml
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field

logger = logging.getLogger("autopiff.rule_engine")


@dataclass
class SinkMatch:
    """A detected sink in the code."""
    group: str
    symbol: str
    line_num: int
    in_added: bool  # True if in added lines, False if context


@dataclass
class RuleHit:
    """A semantic rule that matched."""
    rule_id: str
    category: str
    confidence: float
    sinks: List[str]
    indicators: List[str]
    why_matters: str
    diff_snippet: str


class SemanticRuleEngine:
    """
    Evaluates AutoPiff semantic rules against function diffs.

    Design principles:
    - Conservative: prefer precision over recall
    - Explainable: every hit includes rationale
    - Sink-aware: rules consider proximity to dangerous APIs
    """

    def __init__(self, rules_path: str, sinks_path: str):
        with open(rules_path, 'r') as f:
            self.rules_config = yaml.safe_load(f)
        with open(sinks_path, 'r') as f:
            self.sinks_config = yaml.safe_load(f)

        self.rules = self.rules_config.get('rules', [])
        self.categories = {c['id']: c for c in self.rules_config.get('categories', [])}
        self.global_exclusions = self.rules_config.get('global_exclusions', [])

        # Build sink lookup: symbol -> group
        self.sink_lookup: Dict[str, str] = {}
        for group, data in self.sinks_config.get('sinks', {}).items():
            for sym in data.get('symbols', []):
                self.sink_lookup[sym] = group

        # Compile exclusion patterns
        self.exclusion_patterns = self._compile_exclusions()

        # Detection patterns for each guard/validation type
        self.guard_patterns = self._compile_guard_patterns()

    def _compile_exclusions(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for global exclusions."""
        patterns = {}
        for excl in self.global_exclusions:
            pid = excl['pattern_id']
            hints = excl.get('hints', [])
            patterns[pid] = [re.compile(re.escape(h), re.IGNORECASE) for h in hints]
        return patterns

    def _compile_guard_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile patterns for detecting guards/validations."""
        return {
            'length_check': [
                re.compile(r'\b(InputBufferLength|OutputBufferLength|InformationBufferLength|BufferLength|Length)\s*(<|>|<=|>=|==|!=)', re.IGNORECASE),
                re.compile(r'\bsizeof\s*\(.*\)\s*(<|>|<=|>=)', re.IGNORECASE),
                re.compile(r'\bif\s*\(.*[Ll]en(gth)?\s*(<|>|<=|>=)', re.IGNORECASE),
            ],
            'sizeof_check': [
                re.compile(r'\bsizeof\s*\([^)]+\)', re.IGNORECASE),
                re.compile(r'\bRtlSizeT', re.IGNORECASE),
            ],
            'index_bounds': [
                re.compile(r'\bif\s*\([^)]*\b(index|idx|i|j)\s*(<|>|<=|>=)\s*\d+', re.IGNORECASE),
                re.compile(r'\b(index|idx)\s*(<|>=)\s*\w+', re.IGNORECASE),
            ],
            'null_check': [
                re.compile(r'\bif\s*\(\s*\w+\s*(!=|==)\s*NULL', re.IGNORECASE),
                re.compile(r'\bif\s*\(\s*!\s*\w+\s*\)', re.IGNORECASE),
                re.compile(r'\bif\s*\(\s*\w+\s*\)', re.IGNORECASE),  # if (ptr)
            ],
            'null_assignment': [
                re.compile(r'\w+\s*=\s*NULL\s*;', re.IGNORECASE),
                re.compile(r'\w+\s*=\s*0\s*;'),  # ptr = 0
            ],
            'probe': [
                re.compile(r'\bProbeForRead\b', re.IGNORECASE),
                re.compile(r'\bProbeForWrite\b', re.IGNORECASE),
            ],
            'previous_mode_gate': [
                re.compile(r'\bExGetPreviousMode\b', re.IGNORECASE),
                re.compile(r'\bPreviousMode\b', re.IGNORECASE),
                re.compile(r'\bKernelMode\b.*\bUserMode\b', re.IGNORECASE),
            ],
            'seh_guard': [
                re.compile(r'\b__try\b', re.IGNORECASE),
                re.compile(r'\b__except\b', re.IGNORECASE),
                re.compile(r'\bExRaiseAccessViolation\b', re.IGNORECASE),
            ],
            'safe_math_helper': [
                re.compile(r'\bRtl(ULong|SizeT|UIntPtr)(Add|Sub|Mult)\b', re.IGNORECASE),
                re.compile(r'\bNT_SUCCESS\s*\(\s*Rtl', re.IGNORECASE),
            ],
            'overflow_check': [
                re.compile(r'\b(overflow|Overflow)\b', re.IGNORECASE),
                re.compile(r'\bULONG_MAX\b', re.IGNORECASE),
                re.compile(r'\bSIZE_T_MAX\b', re.IGNORECASE),
                re.compile(r'\bRtl.*Mult\b', re.IGNORECASE),
            ],
            'refcount': [
                re.compile(r'\bInterlocked(Increment|Decrement|Exchange|CompareExchange)\b', re.IGNORECASE),
            ],
        }

    def _is_excluded(self, diff_lines: List[str]) -> Tuple[bool, Optional[str]]:
        """Check if diff matches global exclusion patterns (logging-only, etc.)."""
        added_lines = [l[1:] for l in diff_lines if l.startswith('+') and not l.startswith('+++')]
        added_text = '\n'.join(added_lines)

        for pattern_id, regexes in self.exclusion_patterns.items():
            matches = sum(1 for r in regexes if r.search(added_text))
            # If most added content is exclusion patterns, skip
            if matches > 0 and len(added_lines) < 5:
                # Check if there's substantial non-exclusion content
                non_match_lines = 0
                for line in added_lines:
                    if not any(r.search(line) for r in regexes):
                        non_match_lines += 1
                if non_match_lines == 0:
                    return True, pattern_id

        return False, None

    def _find_sinks(self, diff_lines: List[str]) -> List[SinkMatch]:
        """Find all sink symbols in the diff."""
        sinks = []
        for i, line in enumerate(diff_lines):
            is_added = line.startswith('+') and not line.startswith('+++')
            for symbol, group in self.sink_lookup.items():
                if symbol in line:
                    sinks.append(SinkMatch(
                        group=group,
                        symbol=symbol,
                        line_num=i,
                        in_added=is_added
                    ))
        return sinks

    def _detect_guard_type(self, added_lines: List[str]) -> Dict[str, List[str]]:
        """Detect which guard types are present in added lines."""
        detected = {}
        text = '\n'.join(added_lines)

        for guard_type, patterns in self.guard_patterns.items():
            matches = []
            for p in patterns:
                for m in p.finditer(text):
                    matches.append(m.group())
            if matches:
                detected[guard_type] = list(set(matches))

        return detected

    def _check_proximity(self, guard_line: int, sink_line: int, proximity: str) -> bool:
        """Check if guard is in required proximity to sink."""
        distance = abs(guard_line - sink_line)
        if proximity == 'near_sink':
            return distance <= 10
        elif proximity == 'immediately_after_sink':
            return 0 <= (guard_line - sink_line) <= 3
        elif proximity == 'before_sink':
            return -10 <= (guard_line - sink_line) < 0
        return True

    def _classify_surface_area(self, code: str) -> List[str]:
        """Classify the attack surface area of the code."""
        surfaces = []
        code_lower = code.lower()

        if any(s in code_lower for s in ['irp_mj_device_control', 'iocontrolcode', 'systembuffer', 'type3inputbuffer']):
            surfaces.append('ioctl')
        if any(s in code_lower for s in ['ndis', 'miniportoidrequest', 'filteroidrequest']):
            surfaces.append('ndis')
        if any(s in code_lower for s in ['storport', 'scsi', 'srb']):
            surfaces.append('storage')
        if any(s in code_lower for s in ['flt', 'fsctl', 'irp_mj_create', 'irp_mj_read', 'irp_mj_write']):
            surfaces.append('filesystem')

        return surfaces if surfaces else ['unknown']

    def evaluate(self, func_name: str, old_code: str, new_code: str,
                 diff_lines: List[str]) -> List[RuleHit]:
        """
        Evaluate all semantic rules against a function diff.

        Returns list of RuleHit for each matching rule.
        """
        hits = []

        # Check global exclusions first
        is_excluded, excl_reason = self._is_excluded(diff_lines)
        if is_excluded:
            logger.debug(f"Function {func_name} excluded: {excl_reason}")
            return []

        # Parse added lines
        added_lines = [l[1:] for l in diff_lines if l.startswith('+') and not l.startswith('+++')]
        if not added_lines:
            return []

        # Find sinks and guards
        sinks = self._find_sinks(diff_lines)
        guards = self._detect_guard_type(added_lines)

        # Evaluate each rule
        for rule in self.rules:
            hit = self._evaluate_rule(rule, func_name, diff_lines, added_lines,
                                       new_code, sinks, guards)
            if hit:
                hits.append(hit)

        return hits

    def _evaluate_rule(self, rule: Dict, func_name: str, diff_lines: List[str],
                       added_lines: List[str], new_code: str,
                       sinks: List[SinkMatch], guards: Dict[str, List[str]]) -> Optional[RuleHit]:
        """Evaluate a single rule against the diff."""
        rule_id = rule['rule_id']
        required = rule.get('required_signals', [])

        matched_sinks = set()
        matched_indicators = []

        for signal in required:
            if isinstance(signal, dict):
                key = list(signal.keys())[0]
                value = signal[key]
            else:
                # String signal format: "key: value"
                if ':' in str(signal):
                    key, value = str(signal).split(':', 1)
                    key = key.strip()
                    value = value.strip()
                else:
                    continue

            if key == 'sink_group':
                # Check if any sink matches
                matching = [s for s in sinks if s.group == value]
                if not matching:
                    return None
                matched_sinks.update(s.group for s in matching)
                matched_indicators.extend(s.symbol for s in matching)

            elif key == 'change_type':
                # Check for guard_added, validation_added, etc.
                if value in ['guard_added', 'validation_added', 'hardening_added', 'post_free_hardening']:
                    if not guards:
                        return None

            elif key == 'guard_kind' or key == 'validation_kind' or key == 'hardening_kind':
                # Check specific guard type
                if value not in guards:
                    return None
                matched_indicators.extend(guards[value])

            elif key == 'proximity':
                # Check proximity (simplified - assume pass if we have matching sinks and guards)
                pass

        # If we get here, rule matched
        diff_snippet = '\n'.join(diff_lines[:30])  # First 30 lines
        if len(diff_lines) > 30:
            diff_snippet += '\n... (truncated)'

        return RuleHit(
            rule_id=rule_id,
            category=rule['category'],
            confidence=rule.get('confidence', 0.8),
            sinks=list(matched_sinks),
            indicators=list(set(matched_indicators))[:10],
            why_matters=rule.get('plain_english_summary', ''),
            diff_snippet=diff_snippet
        )

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict]:
        """Get rule definition by ID."""
        for rule in self.rules:
            if rule['rule_id'] == rule_id:
                return rule
        return None

    def get_category_description(self, category_id: str) -> str:
        """Get category description."""
        cat = self.categories.get(category_id, {})
        return cat.get('description', category_id)
