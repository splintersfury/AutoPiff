"""
Download driver binaries from WinBIndex (Microsoft Symbol Server) for the
CVE validation corpus.

Fetches the compressed WinBIndex index for each driver, matches entries by
version prefix and amd64 architecture, then downloads from the MS symbol
server.
"""

import gzip
import hashlib
import json
import logging
import os
import struct
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

WINBINDEX_BASE = "https://winbindex.m417z.com/data/by_filename_compressed"
SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus"

# Cache WinBIndex index per driver name to avoid re-fetching
_index_cache: Dict[str, dict] = {}


def _fetch_winbindex_index(driver_name: str) -> Optional[dict]:
    """Fetch and decompress the WinBIndex index for a driver filename."""
    if driver_name in _index_cache:
        return _index_cache[driver_name]

    url = f"{WINBINDEX_BASE}/{driver_name.lower()}.json.gz"
    logger.info(f"Fetching WinBIndex index: {url}")

    try:
        resp = requests.get(url, timeout=60)
        if resp.status_code == 404:
            logger.error(f"WinBIndex has no data for {driver_name}")
            return None
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch WinBIndex index for {driver_name}: {e}")
        return None

    try:
        raw = gzip.decompress(resp.content)
        index = json.loads(raw)
    except (gzip.BadGzipFile, json.JSONDecodeError) as e:
        logger.error(f"Failed to parse WinBIndex data for {driver_name}: {e}")
        return None

    _index_cache[driver_name] = index
    logger.info(f"WinBIndex index for {driver_name}: {len(index)} build entries")
    return index


def _find_entry_by_version(index: dict, version_prefix: str,
                           arch: str = "amd64") -> Optional[dict]:
    """Find a WinBIndex entry matching the given version prefix and arch.

    WinBIndex JSON structure varies — entries may be nested under
    architecture keys or flat.  We search recursively for a file info dict
    containing a ``version`` field starting with *version_prefix*.
    """
    candidates = []

    def _recurse(data, depth=0):
        if depth > 6 or not isinstance(data, dict):
            return
        # Check if this dict looks like a file-info entry
        ver = data.get("version", "")
        if isinstance(ver, str) and ver.startswith(version_prefix):
            # Check architecture — may be in a parent key or in a field
            file_arch = data.get("machineType")
            # machineType 34404 == 0x8664 == AMD64
            if file_arch in (34404, "34404", "amd64", 332) or arch == "any":
                candidates.append(data)
                return
        for v in data.values():
            if isinstance(v, dict):
                _recurse(v, depth + 1)

    # WinBIndex top-level: {build_hash: {arch: {file_info}}} or flat
    for build_key, build_data in index.items():
        if isinstance(build_data, dict):
            # Prefer explicit arch sub-key if present
            if arch in build_data and isinstance(build_data[arch], dict):
                entry = build_data[arch]
                ver = entry.get("version", "")
                if isinstance(ver, str) and ver.startswith(version_prefix):
                    candidates.append(entry)
                    continue
            _recurse(build_data)

    if not candidates:
        return None

    # Prefer exact match, otherwise first
    for c in candidates:
        if c.get("version", "") == version_prefix:
            return c
    return candidates[0]


def _build_download_url(entry: dict, driver_name: str) -> Optional[str]:
    """Construct the MS Symbol Server download URL from a WinBIndex entry.

    URL format: https://msdl.microsoft.com/download/symbols/{name}/{TIMESTAMP:08X}{virtualSize:x}/{name}

    WinBIndex entries may carry the URL directly, or provide timestamp +
    virtualSize fields.
    """
    # Some entries already have a direct URL
    if "url" in entry and entry["url"]:
        return entry["url"]

    timestamp = entry.get("timestamp")
    virtual_size = entry.get("virtualSize")

    if timestamp is None or virtual_size is None:
        # Try PE header fields
        timestamp = entry.get("Timestamp") or entry.get("timeDateStamp")
        virtual_size = entry.get("VirtualSize") or entry.get("sizeOfImage")

    if timestamp is None or virtual_size is None:
        logger.warning(f"Cannot build download URL: missing timestamp/virtualSize")
        return None

    ts = int(timestamp)
    vs = int(virtual_size)
    name = driver_name.lower()
    return f"{SYMBOL_SERVER}/{name}/{ts:08X}{vs:x}/{name}"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def download_version(driver_name: str, version_info: dict,
                     output_dir: Path, force: bool = False) -> Optional[Path]:
    """Download a specific driver version to output_dir.

    Args:
        driver_name: e.g. "cldflt.sys"
        version_info: dict from manifest with build, winbindex_version_prefix, etc.
        output_dir: directory to save the binary
        force: re-download even if file exists

    Returns:
        Path to downloaded file, or None on failure.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / driver_name

    if output_path.exists() and not force:
        logger.info(f"Already downloaded: {output_path}")
        return output_path

    winbindex_name = version_info.get("winbindex_filename", driver_name)
    version_prefix = version_info["winbindex_version_prefix"]

    index = _fetch_winbindex_index(winbindex_name)
    if not index:
        return None

    entry = _find_entry_by_version(index, version_prefix)
    if not entry:
        logger.error(
            f"No WinBIndex entry for {winbindex_name} version {version_prefix}"
        )
        return None

    url = _build_download_url(entry, winbindex_name)
    if not url:
        return None

    logger.info(f"Downloading {winbindex_name} {version_prefix} from {url}")
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.error(f"Download failed: {e}")
        return None

    # Write to temp then rename for atomicity
    tmp_path = output_path.with_suffix(".tmp")
    with open(tmp_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=65536):
            f.write(chunk)
    tmp_path.rename(output_path)

    # Verify SHA256 if known
    expected_sha = version_info.get("sha256")
    actual_sha = _sha256_file(output_path)
    if expected_sha and actual_sha != expected_sha.lower():
        logger.warning(
            f"SHA256 mismatch for {output_path}: "
            f"expected {expected_sha}, got {actual_sha}"
        )

    logger.info(f"Downloaded {output_path} ({output_path.stat().st_size} bytes, sha256={actual_sha})")
    return output_path


def download_cve(cve_entry: dict, corpus_dir: Path = CORPUS_DIR,
                 force: bool = False) -> Tuple[Optional[Path], Optional[Path]]:
    """Download both vuln and fix binaries for a CVE entry.

    Returns (vuln_path, fix_path) — either may be None on failure.
    """
    cve_id = cve_entry["cve_id"]
    driver = cve_entry["driver"]
    cve_dir = corpus_dir / cve_id

    vuln_path = download_version(
        driver, cve_entry["vuln_version"],
        cve_dir / "vuln", force=force,
    )
    fix_path = download_version(
        driver, cve_entry["fix_version"],
        cve_dir / "fix", force=force,
    )

    return vuln_path, fix_path


def download_all(manifest: dict, corpus_dir: Path = CORPUS_DIR,
                 force: bool = False,
                 cve_filter: Optional[str] = None) -> Dict[str, Tuple[Optional[Path], Optional[Path]]]:
    """Download binaries for all CVEs in the manifest.

    Args:
        manifest: parsed corpus_manifest.json
        corpus_dir: root directory for corpus storage
        force: re-download existing files
        cve_filter: if set, only download this CVE ID

    Returns:
        Dict mapping CVE ID to (vuln_path, fix_path).
    """
    results = {}
    for entry in manifest["cves"]:
        cve_id = entry["cve_id"]
        if cve_filter and cve_id != cve_filter:
            continue

        logger.info(f"--- Downloading {cve_id} ({entry['driver']}) ---")
        vuln, fix = download_cve(entry, corpus_dir, force)
        results[cve_id] = (vuln, fix)

        if vuln:
            logger.info(f"  vuln: {vuln}")
        else:
            logger.warning(f"  vuln: FAILED")
        if fix:
            logger.info(f"  fix:  {fix}")
        else:
            logger.warning(f"  fix:  FAILED")

    return results


def update_manifest_hashes(manifest: dict, corpus_dir: Path = CORPUS_DIR) -> int:
    """Fill in sha256 fields in the manifest from downloaded files.

    Returns the number of hashes updated.
    """
    updated = 0
    for entry in manifest["cves"]:
        cve_id = entry["cve_id"]
        driver = entry["driver"]

        for variant in ("vuln", "fix"):
            ver_key = f"{variant}_version"
            ver = entry[ver_key]
            path = corpus_dir / cve_id / variant / driver
            if path.exists() and not ver.get("sha256"):
                ver["sha256"] = _sha256_file(path)
                updated += 1
                logger.info(f"Updated {cve_id} {variant} sha256: {ver['sha256']}")

    return updated
