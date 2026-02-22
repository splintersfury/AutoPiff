#!/usr/bin/env python3
"""
Build the function embedding index for KernelSense variant search.

Reads all decompiled C files from the driver corpus and indexes
each function into ChromaDB for similarity search.

Usage:
    python scripts/build_embedding_index.py                    # Index all drivers
    python scripts/build_embedding_index.py --driver clfs.sys  # Index one driver
    python scripts/build_embedding_index.py --stats            # Show index stats
    python scripts/build_embedding_index.py --rebuild          # Full rebuild
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

# Add the services directory to path for imports
sys.path.insert(
    0, str(Path(__file__).parent.parent / "services" / "karton-kernelsense")
)

from embeddings import FunctionEmbeddingIndex

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("build_index")

# Default paths for decompiled code
DECOMPILED_DIRS = [
    os.path.expanduser("~/Documents/driver_analyzer/decompiled_code"),
    os.path.expanduser("~/Documents/AutoPiff/corpus"),
]

PERSIST_DIR = os.path.expanduser("~/Documents/AutoPiff/data/embeddings")


def find_decompiled_files(dirs: list[str], driver_filter: str | None = None) -> list[tuple[str, str]]:
    """Find all decompiled .c files and extract driver names.

    Returns list of (driver_name, file_path) tuples.
    """
    files = []
    for dir_path in dirs:
        d = Path(dir_path)
        if not d.exists():
            logger.info(f"Directory not found, skipping: {dir_path}")
            continue

        for c_file in d.rglob("*.c"):
            # Extract driver name from filename or parent directory
            driver_name = c_file.stem
            if driver_name.startswith("decompiled_"):
                driver_name = driver_name[len("decompiled_"):]

            # Apply filter if specified
            if driver_filter and driver_filter.lower() not in driver_name.lower():
                continue

            files.append((driver_name, str(c_file)))

    return files


def build_index(
    driver_filter: str | None = None,
    rebuild: bool = False,
) -> None:
    """Build or update the embedding index."""
    if rebuild:
        import shutil

        if os.path.exists(PERSIST_DIR):
            logger.warning(f"Rebuilding: removing {PERSIST_DIR}")
            shutil.rmtree(PERSIST_DIR)

    index = FunctionEmbeddingIndex(persist_dir=PERSIST_DIR)

    files = find_decompiled_files(DECOMPILED_DIRS, driver_filter)
    if not files:
        logger.error("No decompiled files found")
        logger.info(f"Searched: {DECOMPILED_DIRS}")
        return

    logger.info(f"Found {len(files)} decompiled files to index")

    total_functions = 0
    start_time = time.time()

    for i, (driver_name, file_path) in enumerate(files, 1):
        logger.info(f"[{i}/{len(files)}] Indexing {driver_name}...")
        count = index.add_driver(driver_name, file_path)
        total_functions += count

    elapsed = time.time() - start_time
    stats = index.get_stats()

    logger.info(
        f"Indexing complete in {elapsed:.1f}s: "
        f"{total_functions} new functions added, "
        f"{stats['total_functions']} total in index"
    )


def show_stats() -> None:
    """Display current index statistics."""
    if not os.path.exists(PERSIST_DIR):
        print("No embedding index found. Run without --stats to build one.")
        return

    index = FunctionEmbeddingIndex(persist_dir=PERSIST_DIR)
    stats = index.get_stats()

    print(f"Embedding Index Statistics")
    print(f"  Location:     {stats['persist_dir']}")
    print(f"  Total funcs:  {stats['total_functions']}")
    print(f"  Drivers:      {stats['drivers_sampled']}+")


def main():
    parser = argparse.ArgumentParser(
        description="Build KernelSense function embedding index"
    )
    parser.add_argument(
        "--driver",
        type=str,
        help="Only index files matching this driver name",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show index statistics and exit",
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help="Delete and rebuild the entire index",
    )

    args = parser.parse_args()

    if args.stats:
        show_stats()
    else:
        build_index(driver_filter=args.driver, rebuild=args.rebuild)


if __name__ == "__main__":
    main()
