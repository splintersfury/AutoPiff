"""
VirusTotal source — searches VT Intelligence for new driver uploads
matching watched families, then downloads new ones.

Reuses search-and-download pattern from find_vt_drivers.py.
"""

import logging
import os
import time
import tempfile
from typing import Dict, List

logger = logging.getLogger(__name__)


def poll(
    vt_queries: List[Dict],
    dynamic_families: Dict[str, str],
    redis_client,
    known_key: str,
    versions_prefix: str,
    limit_per_query: int = 20,
) -> List[Dict]:
    """
    Search VT Intelligence for new drivers matching watchlist queries.

    Returns list of dicts: {name, sha256, source, content_path}.
    Only returns entries whose SHA256 is NOT already in the known set.
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
                "query": f'type:peexe tag:signed-driver signer:"{family_name}" ls:7d+',
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
