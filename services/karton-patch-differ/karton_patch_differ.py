"""
AutoPiff Patch Differ Karton Service

Implements Stages 1-4 of the AutoPiff pipeline as a single Karton service.
Adapted from driver_analyzer/patch_differ with AutoPiff enhancements.

Stages:
1. Pairing & Noise Gating - Find closest prior version, assess diff quality
2. Symbolization & Anchoring - Decompile both versions via Ghidra
3. Function Matching - Align functions using hash-based LCS
4. Semantic Delta Extraction - Evaluate YAML rules, produce findings
"""

import os
import re
import json
import logging
import hashlib
import difflib
import tempfile
import subprocess
import itertools
import uuid
from typing import Optional, Tuple, List, Dict, Set, Any
from dataclasses import dataclass, asdict

import pefile
import yaml
from karton.core import Karton, Task, Resource
from mwdblib import MWDB, MWDBFile
from jsonschema import validate, ValidationError

from .rule_engine import SemanticRuleEngine, RuleHit
from .exploit_mapper import ExploitMapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("autopiff.patch_differ")

_ADDR_TOKEN_RE = re.compile(r'\b(FUN|DAT|PTR_LOOP|LAB|switchD)_[0-9a-fA-F]{4,}\b')


def normalize_address_tokens(code: str) -> str:
    """Replace Ghidra auto-generated address tokens with stable placeholders.

    Stripped binaries get names like FUN_1c001ca80 that change between builds
    even when the underlying logic is identical.  Normalizing these to
    FUN_ADDR (etc.) lets hash-based matching and diffing ignore relocation
    noise.
    """
    return _ADDR_TOKEN_RE.sub(lambda m: m.group(1) + '_ADDR', code)


@dataclass
class DriverInfo:
    """Extracted driver metadata."""
    sha256: str
    product: Optional[str]
    version: Optional[str]
    arch: str


@dataclass
class DetailedDiff:
    """Function diff analysis results."""
    old_funcs: Dict[str, str]
    new_funcs: Dict[str, str]
    matched_funcs: Set[str]
    added_funcs: Set[str]
    removed_funcs: Set[str]
    diffs: Dict[str, List[str]]
    delta_scores: Dict[str, int]
    changed_funcs: Set[str]

    @classmethod
    def create(cls, old_functions: Dict[str, str], new_functions: Dict[str, str]) -> 'DetailedDiff':
        """Create diff analysis from function dictionaries."""
        matched = set(old_functions.keys()) & set(new_functions.keys())
        added = set(new_functions.keys()) - set(old_functions.keys())
        removed = set(old_functions.keys()) - set(new_functions.keys())

        diffs = {}
        delta_scores = {}
        changed = set()

        for func in matched:
            old_code = normalize_address_tokens(old_functions[func]).splitlines()
            new_code = normalize_address_tokens(new_functions[func]).splitlines()

            diff = list(difflib.unified_diff(old_code, new_code, n=3, lineterm=''))

            if diff:
                diffs[func] = diff
                changed.add(func)
                # Delta score: count of changed lines
                score = sum(1 for line in diff
                           if (line.startswith('+') and not line.startswith('+++')) or
                              (line.startswith('-') and not line.startswith('---')))
                delta_scores[func] = score

        return cls(
            old_funcs=old_functions,
            new_funcs=new_functions,
            matched_funcs=matched,
            added_funcs=added,
            removed_funcs=removed,
            diffs=diffs,
            delta_scores=delta_scores,
            changed_funcs=changed
        )


class PatchDifferKarton(Karton):
    """
    Karton service implementing AutoPiff Stages 1-4.

    Consumes: type=driver, kind=driver:windows
    Produces: type=autopiff, kind=semantic_deltas (JSON artifact)
    """

    identity = "AutoPiff.PatchDiffer"
    filters = [
        {"type": "driver", "kind": "driver:windows"},
        {"type": "analysis", "kind": "patch_differ"}
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # MWDB connection
        self.mwdb = MWDB(
            api_url=os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/"),
            api_key=os.environ.get("MWDB_API_KEY")
        )

        # Load schemas
        schema_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'schemas')
        self.schemas = {}
        for stage in ['pairing', 'symbols', 'matching', 'semantic_deltas']:
            schema_path = os.path.join(schema_dir, f'{stage}.schema.json')
            if os.path.exists(schema_path):
                with open(schema_path, 'r') as f:
                    self.schemas[stage] = json.load(f)

        # Load rule engine
        rules_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'rules')
        rules_path = os.path.join(rules_dir, 'semantic_rules.yaml')
        sinks_path = os.path.join(rules_dir, 'sinks.yaml')

        if os.path.exists(rules_path) and os.path.exists(sinks_path):
            self.rule_engine = SemanticRuleEngine(rules_path, sinks_path)
            logger.info(f"AutoPiff rule engine loaded: {len(self.rule_engine.rules)} rules, {len(self.rule_engine.sink_lookup)} sinks")
        else:
            logger.warning("Rules/sinks YAML not found, using basic pattern matching")
            self.rule_engine = None

        # Load scoring model
        scoring_path = os.path.join(rules_dir, 'scoring.yaml')
        self.scoring_config = None
        if os.path.exists(scoring_path):
            try:
                with open(scoring_path, 'r') as f:
                    self.scoring_config = yaml.safe_load(f)
                logger.info("Scoring model loaded")
            except Exception as e:
                logger.warning(f"Failed to load scoring model: {e}")

        # Load exploit mapper
        exploit_map_path = os.path.join(rules_dir, 'exploit_map.yaml')
        self.exploit_mapper = ExploitMapper(exploit_map_path)

    # =========================================================================
    # Stage 1: Pairing & Noise Gating
    # =========================================================================

    def _get_version_info(self, file_path: str) -> DriverInfo:
        """Extract product name, version, and architecture from PE."""
        with open(file_path, 'rb') as fh:
            sha256 = hashlib.sha256(fh.read()).hexdigest()

        try:
            pe = pefile.PE(file_path, fast_load=True)

            # Architecture
            arch = "Unknown"
            if pe.FILE_HEADER.Machine == 0x8664:
                arch = "x64"
            elif pe.FILE_HEADER.Machine == 0x014c:
                arch = "x86"
            elif pe.FILE_HEADER.Machine == 0xAA64:
                arch = "ARM64"

            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
            )

            product_name = None
            file_version = None

            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    for child in entry:
                        if hasattr(child, 'StringTable'):
                            for st in child.StringTable:
                                for key, val in st.entries.items():
                                    k = key.decode('utf-8', errors='ignore')
                                    v = val.decode('utf-8', errors='ignore')
                                    if k == 'ProductName':
                                        product_name = v
                                    elif k == 'FileVersion':
                                        file_version = v

            return DriverInfo(sha256=sha256, product=product_name,
                            version=file_version, arch=arch)

        except Exception as e:
            logger.warning(f"Failed to extract PE info: {e}")
            return DriverInfo(sha256=sha256, product=None, version=None, arch="Unknown")

    def _parse_version(self, version_str: str) -> List[int]:
        """Parse version string to comparable tuple."""
        if not version_str:
            return []
        clean_ver = re.sub(r'[^0-9\.]', '', version_str)
        try:
            return [int(x) for x in clean_ver.split('.') if x]
        except (ValueError, TypeError):
            return []

    @staticmethod
    def _normalize_signing_date(raw: str) -> Optional[str]:
        """Extract a YYYY-MM-DD date from a Sigcheck date string.

        Sigcheck formats vary (e.g. '12:00 AM 1/5/2026', '1/5/2026 12:00 AM',
        '2026-01-05').  We only need the calendar day so we look for a
        recognisable date component and return it as ISO date.
        """
        if not raw:
            return None
        raw = raw.strip()
        # Try ISO first (2026-01-05)
        m = re.search(r'(\d{4})-(\d{1,2})-(\d{1,2})', raw)
        if m:
            return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
        # US format: M/D/YYYY or MM/DD/YYYY (with optional time around it)
        m = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4})', raw)
        if m:
            return f"{m.group(3)}-{int(m.group(1)):02d}-{int(m.group(2)):02d}"
        return None

    def _get_signing_date(self, sample: MWDBFile) -> Optional[str]:
        """Return normalised signing date (YYYY-MM-DD) from MWDB attributes."""
        for key in ['sig_date', 'sig_signing_date']:
            vals = sample.attributes.get(key, [])
            if vals:
                raw = vals[0] if isinstance(vals, list) else vals
                d = self._normalize_signing_date(str(raw))
                if d:
                    return d
        return None

    def _find_closest_prior_version(self, info: DriverInfo) -> Optional[MWDBFile]:
        """Find the closest older version of the same driver in MWDB.

        Skips candidates signed on the same day as the new sample — those are
        almost certainly different-architecture builds of the same release.
        """
        if not info.product or not info.version:
            return None

        product_tag = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', info.product).strip("_")[:50]
        query = f'tag:"product:{product_tag.lower()}"'

        target_ver = self._parse_version(info.version)
        if not target_ver:
            return None

        # Get the new sample's signing date for same-day filtering
        try:
            new_mwdb = self.mwdb.query_file(info.sha256)
            new_sign_date = self._get_signing_date(new_mwdb) if new_mwdb else None
        except Exception:
            new_sign_date = None

        candidates = []

        for sample in itertools.islice(self.mwdb.search_files(query), 50):
            if sample.sha256 == info.sha256:
                continue

            # Get version attribute
            version_attr = None
            for key in ['sig_file_version', 'file_version']:
                if key in sample.attributes and sample.attributes[key]:
                    version_attr = sample.attributes[key]
                    if isinstance(version_attr, list):
                        version_attr = version_attr[0]
                    break

            # Architecture check
            sample_arch = next((t for t in sample.tags if t.startswith("arch:")), None)
            expected_arch = f"arch:{info.arch.lower()}"

            if sample_arch and sample_arch != expected_arch:
                continue  # Skip architecture mismatch

            if version_attr:
                cand_ver = self._parse_version(version_attr)
                # Accept strictly older versions only
                if cand_ver and cand_ver < target_ver:
                    # Same-day signing → likely a different-arch build, not a
                    # real version predecessor.  Skip it.
                    if new_sign_date:
                        cand_sign_date = self._get_signing_date(sample)
                        if cand_sign_date and cand_sign_date == new_sign_date:
                            logger.info(
                                f"Skipping same-day-signed candidate "
                                f"{sample.sha256[:12]} (signed {cand_sign_date})"
                            )
                            continue

                    candidates.append((cand_ver, sample))

        if not candidates:
            return None

        # Return closest (highest version that's still older)
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    def _stage1_pairing(self, new_info: DriverInfo, old_sample: Optional[MWDBFile],
                        old_info: Optional[DriverInfo]) -> Dict:
        """Stage 1: Assess pairing quality and noise risk."""

        if not old_sample or not old_info:
            return {
                "autopiff_stage": "pairing",
                "driver_new": {
                    "sha256": new_info.sha256,
                    "product": new_info.product,
                    "version": new_info.version,
                    "arch": new_info.arch
                },
                "driver_old": None,
                "decision": "reject",
                "confidence": 1.0,
                "noise_risk": "high",
                "rationale": ["No prior version found in corpus"],
                "arch_mismatch": False
            }

        # Assess noise risk
        noise_risk = "low"
        rationale = []
        confidence = 0.85

        # Check architecture mismatch
        arch_mismatch = new_info.arch != old_info.arch
        if arch_mismatch:
            noise_risk = "high"
            rationale.append(f"Architecture mismatch: {new_info.arch} vs {old_info.arch}")
            confidence = 0.5

        # Check version delta
        new_ver = self._parse_version(new_info.version)
        old_ver = self._parse_version(old_info.version)

        if new_ver and old_ver:
            # Same major version = likely a patch
            if new_ver[0] == old_ver[0]:
                rationale.append("Same major version - likely a patch release")
                confidence = min(confidence + 0.1, 1.0)
            else:
                noise_risk = "medium" if noise_risk == "low" else noise_risk
                rationale.append("Different major versions - may include refactoring")

        # Determine decision
        if arch_mismatch:
            decision = "quarantine"
        elif noise_risk == "high":
            decision = "quarantine"
        else:
            decision = "accept"

        result = {
            "autopiff_stage": "pairing",
            "driver_new": {
                "sha256": new_info.sha256,
                "product": new_info.product,
                "version": new_info.version,
                "arch": new_info.arch
            },
            "driver_old": {
                "sha256": old_info.sha256,
                "product": old_info.product,
                "version": old_info.version,
                "arch": old_info.arch
            },
            "decision": decision,
            "confidence": confidence,
            "noise_risk": noise_risk,
            "rationale": rationale,
            "arch_mismatch": arch_mismatch
        }

        if 'pairing' in self.schemas:
            validate(instance=result, schema=self.schemas['pairing'])

        return result

    # =========================================================================
    # Stage 2: Symbolization & Anchoring
    # =========================================================================

    def _run_ghidra_decompile(self, file_path: str, temp_dir: str) -> Optional[str]:
        """Run Ghidra headless decompilation."""
        filename = os.path.basename(file_path)
        output_dir = os.path.join(temp_dir, f"ghidra_out_{filename}")
        os.makedirs(output_dir, exist_ok=True)

        ghidra_home = os.environ.get("GHIDRA_HOME", "/app/ghidra")
        headless_script = os.path.join(ghidra_home, "support", "analyzeHeadless")
        project_dir = os.path.join(temp_dir, f"ghidra_proj_{filename}")
        os.makedirs(project_dir, exist_ok=True)

        script_path = os.path.join(os.path.dirname(__file__), "ExportDecompiled.py")

        cmd = [
            headless_script, project_dir, "temp_project",
            "-import", file_path,
            "-scriptPath", os.path.dirname(script_path),
            "-postScript", "ExportDecompiled.py", output_dir,
            "-deleteProject"
        ]

        logger.info(f"Decompiling {filename}...")
        timeout = int(os.environ.get("AUTOPIFF_GHIDRA_TIMEOUT", "2400"))
        max_retries = int(os.environ.get("AUTOPIFF_GHIDRA_MAX_RETRIES", "3"))

        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=timeout)
                if proc.returncode == 0:
                    last_error = None
                    break
                last_error = f"exit code {proc.returncode}"
                logger.warning(
                    f"Ghidra exited with code {proc.returncode} for {filename} "
                    f"(attempt {attempt}/{max_retries})"
                )
                logger.debug(f"Ghidra stderr: {proc.stderr.decode(errors='replace')[:2000]}")
            except subprocess.TimeoutExpired:
                last_error = f"timeout after {timeout}s"
                logger.error(f"Ghidra timed out for {filename} (attempt {attempt}/{max_retries})")

            if attempt < max_retries:
                import time, shutil
                wait = 5 * (2 ** (attempt - 1))
                logger.info(f"Retrying decompilation in {wait}s...")
                # Clean up Ghidra project for retry
                proj_dir = os.path.join(output_dir, "..", "ghidra_proj")
                if os.path.exists(proj_dir):
                    shutil.rmtree(proj_dir, ignore_errors=True)
                time.sleep(wait)

        if last_error:
            logger.error(f"Decompilation of {filename} failed after {max_retries} attempts: {last_error}")
            return None

        expected_output = os.path.join(output_dir, filename + ".c")
        if os.path.exists(expected_output):
            return expected_output

        files = [f for f in os.listdir(output_dir) if f.endswith(".c")]
        if files:
            return os.path.join(output_dir, files[0])

        logger.error(f"Ghidra succeeded but produced no .c output for {filename}")
        return None

    def _get_decompiled_source(self, sample: MWDBFile, temp_dir: str) -> Optional[str]:
        """Get decompiled source, from cache or fresh decompilation."""
        # Check for cached decompilation
        for child in sample.children:
            if child.name.endswith(".c") and "ghidra_decompiled" in child.tags:
                out_path = os.path.join(temp_dir, f"{sample.sha256}.c")
                content = child.download()

                if b"// FUNCTION_START:" not in content:
                    logger.info(f"Legacy source for {sample.sha256}, re-decompiling")
                    continue

                with open(out_path, "wb") as f:
                    f.write(content)
                return out_path

        # Download and decompile
        sample_path = os.path.join(temp_dir, sample.sha256)
        content = sample.download()
        with open(sample_path, "wb") as f:
            f.write(content)

        return self._run_ghidra_decompile(sample_path, temp_dir)

    def _parse_ghidra_output(self, file_path: str) -> List[Tuple[str, str]]:
        """Parse Ghidra output into list of (function_name, code) tuples."""
        funcs = []
        current_func = None
        current_code = []

        with open(file_path, 'r', errors='ignore') as f:
            for line in f:
                if line.startswith("// FUNCTION_START:"):
                    parts = line.strip().split(":", 1)
                    if len(parts) > 1:
                        meta = parts[1].strip().split("@")
                        raw_name = meta[0].strip()
                        # Keep original names (including FUN_/sub_ with address)
                        # to preserve cross-binary matching via address similarity
                        current_func = raw_name
                        current_code = []

                elif line.startswith("// FUNCTION_END"):
                    if current_func:
                        funcs.append((current_func, "".join(current_code).strip()))
                        current_func = None
                else:
                    if current_func:
                        current_code.append(line)

        return funcs

    def _stage2_symbolization(self, new_info: DriverInfo, old_info: DriverInfo,
                              new_funcs: List[Tuple[str, str]],
                              old_funcs: List[Tuple[str, str]]) -> Dict:
        """Stage 2: Report symbolization quality."""
        # Count named vs generic functions
        def count_named(funcs):
            return sum(1 for name, _ in funcs if not name.startswith("sub_"))

        new_named = count_named(new_funcs)
        old_named = count_named(old_funcs)

        coverage = (new_named + old_named) / max(len(new_funcs) + len(old_funcs), 1)

        # Find anchor functions (present in both with same name)
        new_names = {name for name, _ in new_funcs if not name.startswith("sub_")}
        old_names = {name for name, _ in old_funcs if not name.startswith("sub_")}
        common_names = new_names & old_names

        anchors = [
            {"name": name, "addr_new": "unknown", "addr_old": "unknown", "confidence": 0.9}
            for name in list(common_names)[:20]
        ]

        result = {
            "autopiff_stage": "symbols",
            "driver_new": {
                "sha256": new_info.sha256,
                "function_count": len(new_funcs),
                "source_path": None,
                "pdb_found": False
            },
            "driver_old": {
                "sha256": old_info.sha256,
                "function_count": len(old_funcs),
                "source_path": None,
                "pdb_found": False
            },
            "symbolization": {
                "method": "ghidra_decompile",
                "coverage": round(coverage, 3),
                "anchors": anchors
            },
            "notes": [
                f"New: {new_named}/{len(new_funcs)} named functions",
                f"Old: {old_named}/{len(old_funcs)} named functions",
                f"Common anchors: {len(common_names)}"
            ]
        }

        if 'symbols' in self.schemas:
            validate(instance=result, schema=self.schemas['symbols'])

        return result

    # =========================================================================
    # Stage 3: Function Matching
    # =========================================================================

    def _align_functions(self, old_funcs: List[Tuple[str, str]],
                        new_funcs: List[Tuple[str, str]]) -> Tuple[Dict[str, str], Dict[str, str]]:
        """Align functions using hash-based LCS algorithm."""

        def get_hash(code):
            return hashlib.md5(normalize_address_tokens(code).encode('utf-8')).hexdigest()

        old_hashes = [get_hash(f[1]) for f in old_funcs]
        new_hashes = [get_hash(f[1]) for f in new_funcs]

        matcher = difflib.SequenceMatcher(None, old_hashes, new_hashes)

        old_dict = {}
        new_dict = {}

        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                for k in range(i2 - i1):
                    key = new_funcs[j1 + k][0]
                    old_dict[key] = old_funcs[i1 + k][1]
                    new_dict[key] = new_funcs[j1 + k][1]

            elif tag == 'replace':
                count = min(i2 - i1, j2 - j1)
                for k in range(count):
                    key = new_funcs[j1 + k][0]
                    old_dict[key] = old_funcs[i1 + k][1]
                    new_dict[key] = new_funcs[j1 + k][1]

                # Handle unmatched
                if (i2 - i1) > (j2 - j1):
                    for k in range(count, i2 - i1):
                        key = f"{old_funcs[i1 + k][0]}_REMOVED_{uuid.uuid4().hex[:4]}"
                        old_dict[key] = old_funcs[i1 + k][1]
                elif (j2 - j1) > (i2 - i1):
                    for k in range(count, j2 - j1):
                        key = new_funcs[j1 + k][0]
                        new_dict[key] = new_funcs[j1 + k][1]

            elif tag == 'delete':
                for k in range(i2 - i1):
                    key = f"{old_funcs[i1 + k][0]}_REMOVED_{uuid.uuid4().hex[:4]}"
                    old_dict[key] = old_funcs[i1 + k][1]

            elif tag == 'insert':
                for k in range(j2 - j1):
                    key = new_funcs[j1 + k][0]
                    new_dict[key] = new_funcs[j1 + k][1]

        # --- Relocated-function recovery ---
        # After LCS, some functions appear as _REMOVED_ in old_dict with no
        # counterpart in new_dict (and vice-versa) purely because their
        # address changed between builds.  Match them by normalized code hash.
        removed_keys = {k for k in old_dict if '_REMOVED_' in k and k not in new_dict}
        added_keys = {k for k in new_dict if k not in old_dict}

        if removed_keys and added_keys:
            # Build hash → key maps for unmatched entries
            removed_by_hash: Dict[str, List[str]] = {}
            for rk in removed_keys:
                h = get_hash(old_dict[rk])
                removed_by_hash.setdefault(h, []).append(rk)

            added_by_hash: Dict[str, List[str]] = {}
            for ak in added_keys:
                h = get_hash(new_dict[ak])
                added_by_hash.setdefault(h, []).append(ak)

            # Pair identical-hash entries (relocated but unchanged)
            for h, r_keys in list(removed_by_hash.items()):
                a_keys = added_by_hash.get(h, [])
                pairs = min(len(r_keys), len(a_keys))
                for i in range(pairs):
                    rk, ak = r_keys[i], a_keys[i]
                    # Re-key old code under the new function's name
                    old_dict[ak] = old_dict.pop(rk)
                # Remove paired entries so they aren't reused below
                if pairs >= len(r_keys):
                    del removed_by_hash[h]
                else:
                    removed_by_hash[h] = r_keys[pairs:]
                if pairs >= len(a_keys):
                    added_by_hash.pop(h, None)
                else:
                    added_by_hash[h] = a_keys[pairs:]

            # Pair remaining unmatched by closest normalized edit distance
            # (relocated *and* changed functions, e.g. CVE fixes).
            leftover_removed = [rk for rks in removed_by_hash.values() for rk in rks]
            leftover_added = [ak for aks in added_by_hash.values() for ak in aks]

            if leftover_removed and leftover_added:
                norm_old = {rk: normalize_address_tokens(old_dict[rk]) for rk in leftover_removed}
                norm_new = {ak: normalize_address_tokens(new_dict[ak]) for ak in leftover_added}
                used_added = set()

                for rk in leftover_removed:
                    best_ratio = 0.6  # minimum similarity threshold
                    best_ak = None
                    for ak in leftover_added:
                        if ak in used_added:
                            continue
                        ratio = difflib.SequenceMatcher(
                            None, norm_old[rk], norm_new[ak]
                        ).quick_ratio()
                        if ratio > best_ratio:
                            best_ratio = ratio
                            best_ak = ak
                    if best_ak:
                        old_dict[best_ak] = old_dict.pop(rk)
                        used_added.add(best_ak)

        return old_dict, new_dict

    def _stage3_matching(self, new_info: DriverInfo, old_info: DriverInfo,
                        diff: DetailedDiff) -> Dict:
        """Stage 3: Report function matching quality."""
        total_new = len(diff.new_funcs)
        total_old = len(diff.old_funcs)
        matched = len(diff.matched_funcs)
        changed = len(diff.changed_funcs)
        added = len(diff.added_funcs)
        removed = len(diff.removed_funcs)

        # Calculate confidence based on match ratio
        match_ratio = matched / max(total_new, 1)
        confidence = min(0.5 + match_ratio * 0.5, 1.0)

        # Determine quality bucket
        if confidence >= 0.80:
            quality = "high"
        elif confidence >= 0.60:
            quality = "medium"
        else:
            quality = "low"

        # Build matched pairs summary (top 20 by delta)
        top_changed = sorted(diff.changed_funcs,
                            key=lambda f: diff.delta_scores.get(f, 0),
                            reverse=True)[:20]

        matched_pairs = [
            {
                "function": func,
                "confidence": 0.85,
                "changed": func in diff.changed_funcs,
                "delta_score": diff.delta_scores.get(func, 0)
            }
            for func in top_changed
        ]

        result = {
            "autopiff_stage": "matching",
            "driver_new": {"sha256": new_info.sha256},
            "driver_old": {"sha256": old_info.sha256},
            "matching": {
                "method": "hash_lcs",
                "confidence": round(confidence, 3),
                "matched_count": matched,
                "added_count": added,
                "removed_count": removed,
                "changed_count": changed,
                "total_new": total_new,
                "total_old": total_old,
                "quality": quality,
                "matched_pairs": matched_pairs
            },
            "notes": [
                f"Match ratio: {match_ratio:.1%}",
                f"Top delta function: {top_changed[0] if top_changed else 'N/A'}"
            ]
        }

        if 'matching' in self.schemas:
            validate(instance=result, schema=self.schemas['matching'])

        return result

    # =========================================================================
    # Stage 4: Semantic Delta Extraction (with Scoring)
    # =========================================================================

    def _score_findings(self, deltas: List[Dict], match_rate: float = 80.0) -> List[Dict]:
        """Score semantic findings using the scoring.yaml model.

        Args:
            deltas: List of delta dicts from stage 4.
            match_rate: Function match rate percentage (0-100).

        Returns:
            List of deltas with 'final_score' and 'score_breakdown' added, sorted by score.
        """
        if not self.scoring_config or not deltas:
            return deltas

        weights = self.scoring_config.get('weights', {})
        gating = self.scoring_config.get('gating', {})
        composition = self.scoring_config.get('composition', {})
        quality_buckets = self.scoring_config.get('matching_quality_buckets', {})

        rule_base = weights.get('semantic_rule_base', {})
        cat_mult = weights.get('category_multiplier', {})
        change_type_mult = weights.get('change_type_multiplier', {})
        reach_bonus_map = weights.get('reachability_bonus', {})
        sink_bonus_map = weights.get('sink_bonus', {})
        penalty_cfg = weights.get('penalties', {})

        matching_confidence = match_rate / 100.0
        clamp_min = composition.get('clamp', {}).get('min', 0.0)
        clamp_max = composition.get('clamp', {}).get('max', 15.0)
        max_findings = composition.get('max_findings_in_report', 10)

        # Quality bucket for matching
        high_min = quality_buckets.get('high', {}).get('min_confidence', 0.80)
        med_min = quality_buckets.get('medium', {}).get('min_confidence', 0.60)
        if matching_confidence >= high_min:
            quality = "high"
        elif matching_confidence >= med_min:
            quality = "medium"
        else:
            quality = "low"

        scored = []
        for delta in deltas:
            semantic_confidence = delta.get('confidence', 0.5)

            # Gate: hard minimum semantic confidence
            hard_min = gating.get('semantic_confidence', {}).get('hard_min', 0.45)
            if semantic_confidence < hard_min:
                if gating.get('semantic_confidence', {}).get('drop_if_below_hard_min', True):
                    continue

            gates = []

            # Semantic score
            base_w = rule_base.get(delta.get('rule_id', ''), 3.0)
            semantic_total = base_w * semantic_confidence * cat_mult.get(delta.get('category', ''), 1.0)

            # Reachability: use per-delta reachability_class if set by Stage 5,
            # otherwise use surface_area heuristic as a proxy
            reach_class = delta.get('reachability_class', None)
            if not reach_class:
                # Heuristic: if surface_area includes 'ioctl', approximate as ioctl
                surfaces = delta.get('surface_area', [])
                if 'ioctl' in surfaces:
                    reach_class = 'ioctl'
                elif any(s in surfaces for s in ['ndis', 'storage', 'filesystem']):
                    reach_class = 'irp'
                else:
                    reach_class = 'unknown'
            reach_total = reach_bonus_map.get(reach_class, 0.0)

            reach_soft_min = gating.get('reachability_confidence', {}).get('soft_min', 0.55)
            if matching_confidence < reach_soft_min:
                reach_total *= gating.get('reachability_confidence', {}).get('multiplier_if_below', 0.70)
                gates.append(f"reachability_confidence_below_{reach_soft_min}")

            # Sink score
            sink_total = 0.0
            for sink in delta.get('sinks', []):
                sink_total += sink_bonus_map.get(sink, 0.0) * min(1.0, semantic_confidence)

            # Penalties
            penalty_total = 0.0
            quality_pen = penalty_cfg.get('matching_quality', {}).get(quality, 0.0)
            penalty_total += quality_pen

            # Apply change_type multiplier
            ct = delta.get('change_type', 'patch')
            ct_mult = change_type_mult.get(ct, 1.0)

            # Compose
            raw = (semantic_total + reach_total + sink_total - penalty_total) * ct_mult
            clamped = max(clamp_min, min(clamp_max, raw))

            # Gating caps
            match_min = gating.get('matching_confidence', {}).get('min_required', 0.40)
            match_cap = gating.get('matching_confidence', {}).get('cap_if_below', 3.0)
            if matching_confidence < match_min and clamped > match_cap:
                clamped = match_cap
                gates.append(f"matching_confidence_cap_{match_cap}")

            soft_min = gating.get('semantic_confidence', {}).get('soft_min', 0.60)
            soft_cap = gating.get('semantic_confidence', {}).get('cap_if_below_soft_min', 5.0)
            if semantic_confidence < soft_min and clamped > soft_cap:
                clamped = soft_cap
                gates.append(f"semantic_confidence_cap_{soft_cap}")

            scored_delta = dict(delta)
            scored_delta['final_score'] = round(clamped, 2)
            scored_delta['score_breakdown'] = {
                'semantic': round(semantic_total, 2),
                'reachability': round(reach_total, 2),
                'sinks': round(sink_total, 2),
                'penalties': round(penalty_total, 2),
                'gates': gates,
            }
            scored.append(scored_delta)

        scored.sort(key=lambda x: x['final_score'], reverse=True)
        return scored[:max_findings]

    def _classify_surface(self, code: str) -> List[str]:
        """Classify attack surface area. Delegates to rule engine if available."""
        if self.rule_engine:
            return self.rule_engine.classify_surface_area(code)
        surfaces = []
        code_lower = code.lower()
        if any(s in code_lower for s in ['irp_mj_device_control', 'iocontrolcode',
                                          'systembuffer', 'type3inputbuffer']):
            surfaces.append('ioctl')
        if any(s in code_lower for s in ['ndis', 'miniportoidrequest', 'filteroidrequest']):
            surfaces.append('ndis')
        if any(s in code_lower for s in ['storport', 'scsi', 'srb']):
            surfaces.append('storage')
        if any(s in code_lower for s in ['flt', 'fsctl', 'irp_mj_create', 'irp_mj_read', 'irp_mj_write']):
            surfaces.append('filesystem')
        return surfaces if surfaces else ['unknown']

    def _fallback_pattern_detection(self, diff_lines: List[str]) -> List[Dict]:
        """Fallback pattern detection when rule engine unavailable."""
        patterns = []
        added = [l for l in diff_lines if l.startswith('+') and not l.startswith('+++')]
        added_text = '\n'.join(added)

        # Length validation
        if any(s in added_text for s in ['InputBufferLength', 'OutputBufferLength',
                                          'BufferLength']) and any(c in added_text for c in ['<', '>', '==']):
            patterns.append({
                "type": "bounds_check",
                "rule_id": "added_len_check_before_memcpy",
                "confidence": 0.75,
                "indicator": "Buffer length comparison added"
            })

        # Probe added
        if 'ProbeFor' in added_text:
            patterns.append({
                "type": "user_boundary_check",
                "rule_id": "probe_for_read_or_write_added",
                "confidence": 0.85,
                "indicator": "ProbeForRead/Write added"
            })

        # Safe math
        if any(s in added_text for s in ['RtlULongAdd', 'RtlULongMult', 'RtlSizeTMult']):
            patterns.append({
                "type": "int_overflow",
                "rule_id": "safe_size_math_helper_added",
                "confidence": 0.80,
                "indicator": "Safe math helper added"
            })

        # NULL after free
        if '= NULL' in added_text or '= 0;' in added_text:
            if 'ExFreePool' in '\n'.join(diff_lines):
                patterns.append({
                    "type": "lifetime_fix",
                    "rule_id": "null_after_free_added",
                    "confidence": 0.70,
                    "indicator": "NULL assignment near free"
                })

        return patterns

    def _stage4_semantic_deltas(self, new_info: DriverInfo, old_info: DriverInfo,
                                diff: DetailedDiff) -> Dict:
        """Stage 4: Extract semantic deltas using rule engine."""
        deltas = []
        by_category = {}
        by_rule = {}

        # Process changed functions (patches)
        for func_name in diff.changed_funcs:
            diff_lines = diff.diffs.get(func_name, [])
            old_code = diff.old_funcs.get(func_name, "")
            new_code = diff.new_funcs.get(func_name, "")

            if self.rule_engine:
                hits = self.rule_engine.evaluate(func_name, old_code, new_code, diff_lines)
                for hit in hits:
                    delta = {
                        "function": func_name,
                        "rule_id": hit.rule_id,
                        "category": hit.category,
                        "confidence": hit.confidence,
                        "sinks": hit.sinks,
                        "indicators": hit.indicators,
                        "diff_snippet": hit.diff_snippet,
                        "why_matters": hit.why_matters,
                        "surface_area": self._classify_surface(new_code),
                        "change_type": "patch",
                    }
                    deltas.append(delta)

                    by_category[hit.category] = by_category.get(hit.category, 0) + 1
                    by_rule[hit.rule_id] = by_rule.get(hit.rule_id, 0) + 1
            else:
                # Fallback pattern detection
                patterns = self._fallback_pattern_detection(diff_lines)
                for p in patterns:
                    delta = {
                        "function": func_name,
                        "rule_id": p["rule_id"],
                        "category": p["type"],
                        "confidence": p["confidence"],
                        "sinks": [],
                        "indicators": [p["indicator"]],
                        "diff_snippet": '\n'.join(diff_lines[:20]),
                        "why_matters": p["indicator"],
                        "surface_area": self._classify_surface(new_code),
                        "change_type": "patch",
                    }
                    deltas.append(delta)

                    by_category[p["type"]] = by_category.get(p["type"], 0) + 1
                    by_rule[p["rule_id"]] = by_rule.get(p["rule_id"], 0) + 1

        # Process added functions (new attack surface)
        if self.rule_engine:
            for func_name in diff.added_funcs:
                new_code = diff.new_funcs.get(func_name, "")
                # Skip trivially small functions
                if len(new_code) < 50:
                    continue

                hits = self.rule_engine.evaluate_new_function(func_name, new_code)
                for hit in hits:
                    delta = {
                        "function": func_name,
                        "rule_id": hit.rule_id,
                        "category": hit.category,
                        "confidence": hit.confidence,
                        "sinks": hit.sinks,
                        "indicators": hit.indicators,
                        "diff_snippet": hit.diff_snippet,
                        "why_matters": hit.why_matters,
                        "surface_area": self._classify_surface(new_code),
                        "change_type": "new_feature",
                    }
                    deltas.append(delta)

                    by_category[hit.category] = by_category.get(hit.category, 0) + 1
                    by_rule[hit.rule_id] = by_rule.get(hit.rule_id, 0) + 1

        # Calculate match rate for scoring
        match_rate = (len(diff.matched_funcs) / max(len(diff.new_funcs), 1)) * 100

        # Apply scoring if available
        scored_deltas = self._score_findings(deltas, match_rate)
        if scored_deltas and 'final_score' in scored_deltas[0]:
            # Use scored deltas (already sorted by score)
            final_deltas = scored_deltas
            top_score = scored_deltas[0]['final_score'] if scored_deltas else 0
        else:
            # Fall back to confidence sorting
            deltas.sort(key=lambda x: x["confidence"], reverse=True)
            final_deltas = deltas
            top_score = None

        # Enrich deltas with exploit context
        if self.exploit_mapper:
            self.exploit_mapper.enrich_deltas(final_deltas)

        # Top functions by delta count
        func_counts = {}
        for d in final_deltas:
            func_counts[d["function"]] = func_counts.get(d["function"], 0) + 1
        top_functions = sorted(func_counts.keys(),
                              key=lambda f: func_counts[f], reverse=True)[:10]

        # Collect unique exploit primitives across all deltas
        exploit_summary = {}
        for d in final_deltas:
            ctx = d.get("exploit_context")
            if not ctx:
                continue
            vc = ctx["vuln_class"]
            if vc not in exploit_summary:
                exploit_summary[vc] = {
                    "severity": ctx["severity"],
                    "primitives": [p["id"] for p in ctx["primitives"]],
                    "techniques": list({
                        t["id"]
                        for p in ctx["primitives"]
                        for t in p["techniques"]
                    }),
                }

        result = {
            "autopiff_stage": "semantic_deltas",
            "driver_new": {
                "sha256": new_info.sha256,
                "version": new_info.version
            },
            "driver_old": {
                "sha256": old_info.sha256,
                "version": old_info.version
            },
            "deltas": final_deltas,
            "summary": {
                "total_deltas": len(final_deltas),
                "by_category": by_category,
                "by_rule": by_rule,
                "top_functions": top_functions,
                "top_score": top_score,
                "match_rate": round(match_rate, 1),
                "exploit_summary": exploit_summary,
            },
            "notes": [
                f"Analyzed {len(diff.changed_funcs)} changed functions",
                f"Analyzed {len(diff.added_funcs)} added functions",
                f"Found {len(final_deltas)} semantic deltas",
                f"Match rate: {match_rate:.1f}%"
            ]
        }

        if 'semantic_deltas' in self.schemas:
            validate(instance=result, schema=self.schemas['semantic_deltas'])

        return result

    # =========================================================================
    # Main Process
    # =========================================================================

    def process(self, task: Task) -> None:
        """Main processing: run all 4 stages."""
        sample_resource = task.get_resource("sample")
        if not sample_resource:
            logger.error("No sample resource in task")
            return

        sha256 = sample_resource.sha256
        logger.info(f"Starting patch diff analysis for {sha256}")

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download current sample
                current_path = os.path.join(temp_dir, "current.sys")
                with open(current_path, "wb") as f:
                    f.write(sample_resource.content)

                # Stage 1: Get version info and find prior version
                new_info = self._get_version_info(current_path)
                new_info.sha256 = sha256

                if not new_info.product or not new_info.version:
                    logger.info("Skipping: No product/version info")
                    return

                logger.info(f"Identified: {new_info.product} v{new_info.version} ({new_info.arch})")

                # Tag with architecture
                if new_info.arch != "Unknown":
                    try:
                        self.mwdb.file(sha256).add_tag(f"arch:{new_info.arch.lower()}")
                    except Exception as e:
                        logger.debug(f"Failed to tag arch: {e}")

                # Find prior version
                old_sample = self._find_closest_prior_version(new_info)
                old_info = None

                if old_sample:
                    old_path = os.path.join(temp_dir, "old.sys")
                    with open(old_path, "wb") as f:
                        f.write(old_sample.download())
                    old_info = self._get_version_info(old_path)
                    old_info.sha256 = old_sample.sha256

                # Stage 1: Pairing
                pairing_result = self._stage1_pairing(new_info, old_sample, old_info)
                logger.info(f"Pairing decision: {pairing_result['decision']}")

                if pairing_result['decision'] == 'reject':
                    logger.info("No compatible prior version found")
                    return

                # Stage 2: Decompilation
                logger.info("Stage 2: Decompiling...")
                new_src_path = self._run_ghidra_decompile(current_path, temp_dir)
                old_src_path = self._get_decompiled_source(old_sample, temp_dir)

                if not new_src_path or not old_src_path:
                    failed = []
                    if not new_src_path:
                        failed.append(f"new binary ({new_info.sha256[:12]})")
                    if not old_src_path:
                        failed.append(f"old binary ({old_info.sha256[:12]})")
                    logger.error(f"Decompilation failed for: {', '.join(failed)}")
                    return

                # Parse functions
                new_funcs = self._parse_ghidra_output(new_src_path)
                old_funcs = self._parse_ghidra_output(old_src_path)

                logger.info(f"Parsed functions - New: {len(new_funcs)}, Old: {len(old_funcs)}")

                symbols_result = self._stage2_symbolization(new_info, old_info,
                                                            new_funcs, old_funcs)

                # Stage 3: Function matching
                logger.info("Stage 3: Matching functions...")
                old_dict, new_dict = self._align_functions(old_funcs, new_funcs)
                diff = DetailedDiff.create(old_dict, new_dict)

                matching_result = self._stage3_matching(new_info, old_info, diff)
                logger.info(f"Matching quality: {matching_result['matching']['quality']}")

                # Stage 4: Semantic delta extraction
                logger.info("Stage 4: Extracting semantic deltas...")
                deltas_result = self._stage4_semantic_deltas(new_info, old_info, diff)
                logger.info(f"Found {deltas_result['summary']['total_deltas']} deltas")

                # Combine all artifacts
                combined_artifact = {
                    "pairing": pairing_result,
                    "symbols": symbols_result,
                    "matching": matching_result,
                    "semantic_deltas": deltas_result
                }

                # Upload to MWDB
                artifact_filename = f"autopiff_stages1-4_{new_info.version}.json"
                self.mwdb.upload_file(
                    name=artifact_filename,
                    content=json.dumps(combined_artifact, indent=2).encode('utf-8'),
                    parent=sha256,
                    tags=["autopiff", "semantic_deltas"]
                )

                # Tag original sample
                try:
                    self.mwdb.file(sha256).add_tag("autopiff_analyzed")
                except Exception as e:
                    logger.debug(f"Failed to tag autopiff_analyzed: {e}")

                # Send to Stage 5 (Reachability)
                out_task = Task(
                    headers={"type": "autopiff", "kind": "semantic_deltas"},
                    payload={
                        "semantic_deltas": deltas_result
                    }
                )
                out_task.add_resource("sample", sample_resource)
                self.send_task(out_task)

                logger.info("Analysis complete, sent to Stage 5")

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)


if __name__ == "__main__":
    PatchDifferKarton().loop()
