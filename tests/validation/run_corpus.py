#!/usr/bin/env python3
"""
AutoPiff CVE Validation Corpus — main CLI entry point.

Usage:
    python3 tests/validation/run_corpus.py                     # Full pipeline
    python3 tests/validation/run_corpus.py --skip-decompile    # Use cached .c
    python3 tests/validation/run_corpus.py --download-only     # Just fetch binaries
    python3 tests/validation/run_corpus.py --evaluate-only     # Requires cached .c
    python3 tests/validation/run_corpus.py --cve CVE-2024-30085
    python3 tests/validation/run_corpus.py --json              # Machine-readable
    python3 tests/validation/run_corpus.py --corpus-dir /path  # Custom corpus location

Exit code 0 if recall >= 0.60, else 1.
"""

import argparse
import importlib
import json
import logging
import sys
from pathlib import Path

# Ensure repo root and this directory are importable
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_THIS_DIR = Path(__file__).resolve().parent
for _p in (str(_REPO_ROOT), str(_THIS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Import sibling modules directly (not via tests.validation.*) to avoid
# double-execution when this script is run as __main__.
import download_corpus as _dl  # noqa: E402
import decompile as _dec  # noqa: E402
import evaluate as _eval  # noqa: E402
import metrics as _met  # noqa: E402

download_all = _dl.download_all
update_manifest_hashes = _dl.update_manifest_hashes
decompile_all = _dec.decompile_all
evaluate_all = _eval.evaluate_all
CORPUS_DIR = _eval.CORPUS_DIR
compute_overall = _met.compute_overall
format_json_report = _met.format_json_report
format_text_report = _met.format_text_report

MANIFEST_PATH = Path(__file__).resolve().parent / "corpus_manifest.json"
RECALL_THRESHOLD = 0.60


def load_manifest(path: Path = MANIFEST_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(
        description="AutoPiff CVE Validation Corpus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--download-only", action="store_true",
        help="Only download binaries, skip decompile and evaluate",
    )
    parser.add_argument(
        "--skip-decompile", action="store_true",
        help="Skip Ghidra decompilation, use cached .c files",
    )
    parser.add_argument(
        "--evaluate-only", action="store_true",
        help="Only run evaluation (requires cached .c files)",
    )
    parser.add_argument(
        "--cve", type=str, default=None,
        help="Evaluate a single CVE (e.g. CVE-2024-30085)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output machine-readable JSON instead of text table",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Force re-download / re-decompile even if cached",
    )
    parser.add_argument(
        "--corpus-dir", type=str, default=None,
        help="Custom corpus directory (default: <repo>/corpus/)",
    )
    parser.add_argument(
        "--manifest", type=str, default=None,
        help="Custom manifest file path",
    )
    parser.add_argument(
        "--ghidra-home", type=str, default=None,
        help="Ghidra installation directory",
    )
    parser.add_argument(
        "--ghidra-timeout", type=int, default=2400,
        help="Ghidra decompilation timeout in seconds (default: 2400)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    manifest_path = Path(args.manifest) if args.manifest else MANIFEST_PATH
    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else CORPUS_DIR

    manifest = load_manifest(manifest_path)
    logger = logging.getLogger("run_corpus")
    logger.info(
        f"Loaded manifest: {len(manifest['cves'])} CVEs"
        + (f" (filtering to {args.cve})" if args.cve else "")
    )

    # Step 1: Download
    if not args.evaluate_only:
        logger.info("=== Step 1: Download binaries ===")
        dl_results = download_all(
            manifest, corpus_dir, force=args.force, cve_filter=args.cve,
        )
        # Update manifest hashes in memory
        update_manifest_hashes(manifest, corpus_dir)

        success = sum(1 for v, f in dl_results.values() if v and f)
        total = len(dl_results)
        logger.info(f"Downloaded {success}/{total} CVE pairs successfully")

        if args.download_only:
            # Save updated manifest with hashes
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)
                f.write("\n")
            logger.info(f"Manifest updated with SHA256 hashes")
            sys.exit(0 if success > 0 else 1)

    # Step 2: Decompile
    if not args.evaluate_only and not args.skip_decompile:
        logger.info("=== Step 2: Ghidra decompilation ===")
        dec_results = decompile_all(
            manifest, corpus_dir, force=args.force, cve_filter=args.cve,
            ghidra_home=args.ghidra_home, timeout=args.ghidra_timeout,
        )
        success = sum(1 for v, f in dec_results.values() if v and f)
        total = len(dec_results)
        logger.info(f"Decompiled {success}/{total} CVE pairs successfully")

    # Step 3: Evaluate
    logger.info("=== Step 3: Rule engine evaluation ===")
    results = evaluate_all(
        manifest, corpus_dir, cve_filter=args.cve,
    )

    # Step 4: Report
    if args.json:
        print(format_json_report(results))
    else:
        print(format_text_report(results))

    # Exit code based on recall threshold
    overall = compute_overall(results)
    recall = overall["recall"]
    if recall >= RECALL_THRESHOLD:
        logger.info(f"PASS: recall {recall:.2%} >= {RECALL_THRESHOLD:.0%} threshold")
        sys.exit(0)
    else:
        logger.warning(
            f"FAIL: recall {recall:.2%} < {RECALL_THRESHOLD:.0%} threshold"
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
