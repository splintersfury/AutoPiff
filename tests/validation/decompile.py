"""
Ghidra headless decompilation wrapper for the CVE validation corpus.

Runs analyzeHeadless with ExportDecompiled.py and parses the output into
{function_name: code} dicts.  Results are cached in corpus/{CVE-ID}/cache/.
"""

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus"
EXPORT_SCRIPT = (
    Path(__file__).resolve().parent.parent.parent
    / "services" / "karton-patch-differ" / "ExportDecompiled.py"
)


def parse_ghidra_output(file_path: str) -> List[Tuple[str, str]]:
    """Parse Ghidra decompiled output into (function_name, code) tuples.

    Mirrors _parse_ghidra_output() from karton_patch_differ.py:410-436.
    """
    funcs = []
    current_func = None
    current_code: List[str] = []

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            if line.startswith("// FUNCTION_START:"):
                parts = line.strip().split(":", 1)
                if len(parts) > 1:
                    meta = parts[1].strip().split("@")
                    raw_name = meta[0].strip()
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


def funcs_to_dict(funcs: List[Tuple[str, str]]) -> Dict[str, str]:
    """Convert list of (name, code) tuples to a dict, keeping last occurrence."""
    return {name: code for name, code in funcs}


def run_ghidra_decompile(binary_path: Path, output_path: Path,
                         ghidra_home: Optional[str] = None,
                         timeout: int = 2400) -> Optional[Path]:
    """Run Ghidra headless decompilation on a binary.

    Args:
        binary_path: path to the .sys / .exe file
        output_path: desired path for the decompiled .c output
        ghidra_home: GHIDRA_HOME directory (default: env or /opt/ghidra)
        timeout: seconds before killing Ghidra

    Returns:
        Path to the decompiled .c file, or None on failure.
    """
    if ghidra_home is None:
        ghidra_home = os.environ.get("GHIDRA_HOME", "/opt/ghidra")

    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    if not os.path.isfile(headless):
        logger.error(f"analyzeHeadless not found at {headless}")
        return None

    if not EXPORT_SCRIPT.exists():
        logger.error(f"ExportDecompiled.py not found at {EXPORT_SCRIPT}")
        return None

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="autopiff_ghidra_") as tmp:
        project_dir = os.path.join(tmp, "project")
        os.makedirs(project_dir)
        output_dir = os.path.join(tmp, "output")
        os.makedirs(output_dir)

        cmd = [
            headless, project_dir, "temp_project",
            "-import", str(binary_path),
            "-scriptPath", str(EXPORT_SCRIPT.parent),
            "-postScript", "ExportDecompiled.py", output_dir,
            "-deleteProject",
        ]

        logger.info(f"Decompiling {binary_path.name}...")
        try:
            proc = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=timeout,
            )
            if proc.returncode != 0:
                logger.warning(
                    f"Ghidra exited {proc.returncode} for {binary_path.name}"
                )
                stderr_tail = proc.stderr.decode(errors="replace")[:2000]
                logger.debug(f"Ghidra stderr: {stderr_tail}")
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra timed out ({timeout}s) for {binary_path.name}")
            return None
        except FileNotFoundError:
            logger.error(f"Ghidra binary not found: {headless}")
            return None

        # Find the .c output
        expected = os.path.join(output_dir, binary_path.name + ".c")
        if os.path.exists(expected):
            src = expected
        else:
            c_files = [f for f in os.listdir(output_dir) if f.endswith(".c")]
            if not c_files:
                logger.error(f"No decompiled output for {binary_path.name}")
                return None
            src = os.path.join(output_dir, c_files[0])

        # Copy to cache location
        import shutil
        shutil.copy2(src, str(output_path))
        logger.info(f"Decompiled output cached: {output_path}")
        return output_path


def decompile_cve(cve_entry: dict, corpus_dir: Path = CORPUS_DIR,
                  force: bool = False,
                  ghidra_home: Optional[str] = None,
                  timeout: int = 2400) -> Tuple[Optional[Path], Optional[Path]]:
    """Decompile both vuln and fix binaries for a CVE, with caching.

    Returns (vuln_c_path, fix_c_path) — either may be None on failure.
    """
    cve_id = cve_entry["cve_id"]
    driver = cve_entry["driver"]
    cve_dir = corpus_dir / cve_id
    cache_dir = cve_dir / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for variant in ("vuln", "fix"):
        cache_path = cache_dir / f"{variant}.c"
        binary_path = cve_dir / variant / driver

        if cache_path.exists() and not force:
            logger.info(f"Using cached decompilation: {cache_path}")
            results.append(cache_path)
            continue

        if not binary_path.exists():
            logger.error(f"Binary not found: {binary_path}")
            results.append(None)
            continue

        result = run_ghidra_decompile(
            binary_path, cache_path,
            ghidra_home=ghidra_home, timeout=timeout,
        )
        results.append(result)

    return results[0], results[1]


def decompile_all(manifest: dict, corpus_dir: Path = CORPUS_DIR,
                  force: bool = False,
                  cve_filter: Optional[str] = None,
                  ghidra_home: Optional[str] = None,
                  timeout: int = 2400) -> Dict[str, Tuple[Optional[Path], Optional[Path]]]:
    """Decompile binaries for all CVEs in the manifest.

    Returns dict mapping CVE ID to (vuln_c_path, fix_c_path).
    """
    results = {}
    for entry in manifest["cves"]:
        cve_id = entry["cve_id"]
        if cve_filter and cve_id != cve_filter:
            continue

        logger.info(f"--- Decompiling {cve_id} ({entry['driver']}) ---")
        vuln_c, fix_c = decompile_cve(
            entry, corpus_dir, force=force,
            ghidra_home=ghidra_home, timeout=timeout,
        )
        results[cve_id] = (vuln_c, fix_c)

        if vuln_c:
            logger.info(f"  vuln.c: {vuln_c}")
        else:
            logger.warning(f"  vuln.c: FAILED")
        if fix_c:
            logger.info(f"  fix.c:  {fix_c}")
        else:
            logger.warning(f"  fix.c:  FAILED")

    return results
