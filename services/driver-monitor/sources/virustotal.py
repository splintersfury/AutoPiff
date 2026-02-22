"""
VirusTotal source — searches VT Intelligence for new driver uploads
matching watched families, then downloads new ones.

Two modes:
  - poll(): vendor-specific queries (CrowdStrike, SentinelOne, etc.), runs every 4h
  - sweep(): broad daily sweep for ANY new signed .sys on VT, runs every 24h

Reuses search-and-download pattern from find_vt_drivers.py.
"""

import logging
import os
import time
import tempfile
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def _exists_in_mwdb(mwdb_client, sha256: str) -> bool:
    """Check if a file already exists in MWDB by SHA256."""
    if mwdb_client is None:
        return False
    try:
        return mwdb_client.query_file(sha256) is not None
    except Exception:
        return False


def poll(
    vt_queries: List[Dict],
    dynamic_families: Dict[str, str],
    redis_client,
    known_key: str,
    versions_prefix: str,
    limit_per_query: int = 20,
    mwdb_client=None,
) -> List[Dict]:
    """
    Search VT Intelligence for new drivers matching watchlist queries.

    Returns list of dicts: {name, sha256, source, content_path}.
    Only returns entries whose SHA256 is NOT already in the known set
    or in MWDB.
    """
    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        logger.warning("VT_API_KEY not set, skipping VirusTotal poll")
        return []

    try:
        import vt
    except ImportError:
        logger.error("vt-py not installed, skipping VirusTotal poll")
        return []

    new_drivers = []
    client = vt.Client(vt_key)

    try:
        # Process static queries from watchlist.yaml
        all_queries = list(vt_queries)

        # Add dynamic queries from Telegram /watchdriver
        for family_name, meta_json in dynamic_families.items():
            all_queries.append({
                "name": family_name,
                "query": f'type:peexe tag:signed tag:contains-drv signature:"{family_name}" ls:7d+',
            })

        for entry in all_queries:
            query_name = entry.get("name", "unknown")
            query = entry.get("query", "")
            if not query:
                continue

            logger.info(f"VT: searching for '{query_name}': {query}")

            try:
                search_iter = client.iterator(
                    "/intelligence/search",
                    params={"query": query, "descriptors_only": "true"},
                    limit=limit_per_query,
                )

                for file_obj in search_iter:
                    sha256 = file_obj.id.lower()

                    if redis_client.sismember(known_key, sha256):
                        continue

                    if _exists_in_mwdb(mwdb_client, sha256):
                        logger.debug(f"VT: {sha256[:12]} already in MWDB, skipping download")
                        redis_client.sadd(known_key, sha256)
                        continue

                    # Download to temp file
                    try:
                        tmp = tempfile.NamedTemporaryFile(
                            delete=False, suffix=".bin", prefix=f"vt_{sha256[:8]}_"
                        )
                        client.download_file(sha256, tmp)
                        tmp.close()
                        content_path = tmp.name
                    except Exception as e:
                        logger.warning(f"VT: failed to download {sha256[:12]}: {e}")
                        continue

                    new_drivers.append({
                        "name": query_name,
                        "sha256": sha256,
                        "source": "virustotal",
                        "content_path": content_path,
                    })

                    # Mark as known
                    redis_client.sadd(known_key, sha256)

                    # Track version history
                    version_key = f"{versions_prefix}:{query_name.lower()}"
                    redis_client.zadd(version_key, {sha256: time.time()})

            except Exception as e:
                logger.error(f"VT: search failed for '{query_name}': {e}")
                continue

    finally:
        client.close()

    logger.info(f"VT poll complete: {len(new_drivers)} new driver(s)")
    return new_drivers


def sweep(
    sweep_config: Dict,
    redis_client,
    known_key: str,
    versions_prefix: str,
    mwdb_client=None,
) -> List[Dict]:
    """
    Broad daily sweep for new signed kernel drivers on VirusTotal.

    Unlike poll(), this searches for ANY new signed .sys file — not
    limited to specific vendors. Designed to run once per day.

    sweep_config is the vt_daily_sweep section from watchlist.yaml:
      {enabled: true, limit_per_query: 50, queries: [{name, query}, ...]}

    Checks MWDB before downloading to avoid wasting VT API quota.

    Returns list of dicts: {name, sha256, source, content_path, file_name, signer}.
    """
    if not sweep_config.get("enabled", False):
        logger.info("VT sweep: disabled in watchlist config")
        return []

    vt_key = os.environ.get("VT_API_KEY")
    if not vt_key:
        logger.warning("VT_API_KEY not set, skipping VT daily sweep")
        return []

    try:
        import vt
    except ImportError:
        logger.error("vt-py not installed, skipping VT daily sweep")
        return []

    queries = sweep_config.get("queries", [])
    if not queries:
        logger.info("VT sweep: no queries configured")
        return []

    limit = sweep_config.get("limit_per_query", 50)
    new_drivers = []
    client = vt.Client(vt_key)

    try:
        for entry in queries:
            query_name = entry.get("name", "unknown")
            query = entry.get("query", "")
            if not query:
                continue

            logger.info(f"VT sweep [{query_name}]: {query} (limit={limit})")

            try:
                search_iter = client.iterator(
                    "/intelligence/search",
                    params={"query": query},
                    limit=limit,
                )

                for file_obj in search_iter:
                    sha256 = file_obj.id.lower()

                    if redis_client.sismember(known_key, sha256):
                        continue

                    if _exists_in_mwdb(mwdb_client, sha256):
                        logger.debug(f"VT sweep: {sha256[:12]} already in MWDB, skipping download")
                        redis_client.sadd(known_key, sha256)
                        continue

                    # Extract metadata before downloading
                    file_name = ""
                    signer = ""
                    try:
                        file_name = getattr(file_obj, "meaningful_name", "") or ""
                        sig_info = getattr(file_obj, "signature_info", None)
                        if sig_info and isinstance(sig_info, dict):
                            signer = sig_info.get("subject", "")
                    except Exception:
                        pass

                    # Download the binary
                    try:
                        tmp = tempfile.NamedTemporaryFile(
                            delete=False, suffix=".sys",
                            prefix=f"vtsweep_{sha256[:8]}_",
                        )
                        client.download_file(sha256, tmp)
                        tmp.close()
                        content_path = tmp.name
                    except Exception as e:
                        logger.warning(
                            f"VT sweep: failed to download {sha256[:12]}: {e}"
                        )
                        continue

                    new_drivers.append({
                        "name": file_name or query_name,
                        "sha256": sha256,
                        "source": "vt_sweep",
                        "content_path": content_path,
                        "file_name": file_name,
                        "signer": signer,
                    })

                    # Mark as known
                    redis_client.sadd(known_key, sha256)

                    # Track in version history
                    version_key = f"{versions_prefix}:vt_sweep"
                    redis_client.zadd(version_key, {sha256: time.time()})

                    logger.info(
                        f"VT sweep: new driver {file_name or sha256[:12]} "
                        f"(signer: {signer or 'unknown'})"
                    )

            except Exception as e:
                logger.error(f"VT sweep: search failed for '{query_name}': {e}")
                continue

    finally:
        client.close()

    logger.info(f"VT daily sweep complete: {len(new_drivers)} new driver(s)")
    return new_drivers
