"""
WinBIndex source — polls winbindex.m417z.com for new builds of system drivers.

For each driver in the watchlist, fetches the compressed index JSON and
compares SHA256 hashes against known versions in Redis.
"""

import gzip
import json
import logging
import time
from io import BytesIO
from typing import Dict, List

import requests

logger = logging.getLogger(__name__)

WINBINDEX_BASE = "https://winbindex.m417z.com/data/by_filename_compressed"


def poll(driver_names: List[str], redis_client, known_key: str, versions_prefix: str) -> List[Dict]:
    """
    Poll WinBIndex for new builds of the given driver filenames.

    Returns a list of dicts: {name, sha256, url, version, source}.
    Only returns entries whose SHA256 is NOT already in the known set.
    """
    new_drivers = []

    for name in driver_names:
        name = name.strip().lower()
        url = f"{WINBINDEX_BASE}/{name}.json.gz"

        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 404:
                logger.debug(f"WinBIndex: no data for {name}")
                continue
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"WinBIndex: failed to fetch {name}: {e}")
            continue

        try:
            raw = gzip.decompress(resp.content)
            index = json.loads(raw)
        except (gzip.BadGzipFile, json.JSONDecodeError) as e:
            logger.warning(f"WinBIndex: failed to parse {name}: {e}")
            continue

        # index is {build_hash: {file_info...}} or {build: {arch: {file_info}}}
        # WinBIndex format: each top-level key is a Windows build hash,
        # value contains nested arch -> file info with SHA256
        for build_key, build_data in index.items():
            sha256_values = _extract_sha256s(build_data)

            for sha256, meta in sha256_values:
                if not sha256:
                    continue

                sha256 = sha256.lower()

                # Check if we already know this hash
                if redis_client.sismember(known_key, sha256):
                    continue

                version = meta.get("version", build_key)

                new_drivers.append({
                    "name": name,
                    "sha256": sha256,
                    "version": str(version),
                    "source": "winbindex",
                    "build_key": build_key,
                    "download_url": meta.get("url", ""),
                })

                # Mark as known immediately to avoid re-processing within same poll
                redis_client.sadd(known_key, sha256)

                # Track version history
                version_key = f"{versions_prefix}:{name}"
                redis_client.zadd(version_key, {sha256: time.time()})

        logger.info(f"WinBIndex: processed {name}, found {len(index)} builds")

    logger.info(f"WinBIndex poll complete: {len(new_drivers)} new driver(s)")
    return new_drivers


def _extract_sha256s(data, depth=0):
    """Recursively extract SHA256 values from nested WinBIndex JSON structures."""
    results = []
    if depth > 5:
        return results

    if isinstance(data, dict):
        # If this dict has a sha256 key, it's a file entry
        if "sha256" in data:
            results.append((data["sha256"], data))
        elif "SHA256" in data:
            results.append((data["SHA256"], data))
        else:
            # Recurse into nested structures
            for v in data.values():
                results.extend(_extract_sha256s(v, depth + 1))

    return results
