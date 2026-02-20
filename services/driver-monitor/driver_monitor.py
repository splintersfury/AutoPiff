#!/usr/bin/env python3
"""
AutoPiff Driver Monitor — standalone producer that detects new driver versions
and uploads them to MWDB (which triggers the Karton classifier pipeline).

Sources:
  - WinBIndex: polls every 6h for system drivers
  - VirusTotal: polls every 4h for watched 3rd-party families

Watchlist is the union of:
  - Static entries from watchlist.yaml
  - Dynamic entries from Telegram /watchdriver (stored in Redis)
"""

import os
import logging
import time
from pathlib import Path

import redis
import yaml
from apscheduler.schedulers.blocking import BlockingScheduler
from mwdblib import MWDB

from sources import winbindex, virustotal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
REDIS_HOST = os.environ.get("KARTON_REDIS_HOST", "karton-redis")
MWDB_API_URL = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
MWDB_API_KEY = os.environ.get("MWDB_API_KEY")
WATCHLIST_PATH = os.environ.get(
    "WATCHLIST_PATH",
    str(Path(__file__).parent / "watchlist.yaml"),
)
WINBINDEX_INTERVAL_HOURS = int(os.environ.get("WINBINDEX_INTERVAL_HOURS", "6"))
VT_INTERVAL_HOURS = int(os.environ.get("VT_INTERVAL_HOURS", "4"))

# Redis keys
KNOWN_KEY = "autopiff:monitor:known_sha256"
VERSIONS_PREFIX = "autopiff:monitor:versions"
LAST_POLL_PREFIX = "autopiff:monitor:last_poll"
WATCHLIST_KEY = "autopiff:watchlist:families"


class DriverMonitor:
    """Monitors driver sources and uploads new versions to MWDB."""

    def __init__(self):
        self.rdb = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
        api_key = MWDB_API_KEY.strip() if MWDB_API_KEY else None
        self.mwdb = MWDB(api_url=MWDB_API_URL, api_key=api_key)
        self.watchlist = self._load_watchlist()

    def _load_watchlist(self) -> dict:
        try:
            with open(WATCHLIST_PATH) as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.warning(f"Watchlist not found at {WATCHLIST_PATH}, using defaults")
            return {"system_drivers": [], "vt_queries": []}

    def _get_dynamic_families(self) -> dict:
        """Get dynamic watchlist families from Redis (added via Telegram /watchdriver)."""
        return self.rdb.hgetall(WATCHLIST_KEY)

    def _upload_to_mwdb(self, name: str, sha256: str, content: bytes, source: str):
        """Upload a driver binary to MWDB. Skips if already present."""
        try:
            existing = self.mwdb.query_file(sha256)
            if existing:
                logger.info(f"MWDB: {sha256[:12]} already exists, skipping upload")
                return
        except Exception:
            pass

        try:
            self.mwdb.upload_file(
                name=name,
                content=content,
                tags=["autopiff_monitor", f"source:{source}"],
            )
            logger.info(f"MWDB: uploaded {name} ({sha256[:12]})")
        except Exception as e:
            logger.error(f"MWDB: failed to upload {name}: {e}")

    def poll_winbindex(self):
        """Poll WinBIndex for new system driver builds."""
        logger.info("Starting WinBIndex poll...")

        driver_names = self.watchlist.get("system_drivers", [])

        # Also add dynamic families that look like .sys filenames
        dynamic = self._get_dynamic_families()
        for family in dynamic:
            if family.endswith(".sys") and family not in driver_names:
                driver_names.append(family)

        if not driver_names:
            logger.info("WinBIndex: no drivers to monitor")
            return

        new_drivers = winbindex.poll(
            driver_names, self.rdb, KNOWN_KEY, VERSIONS_PREFIX
        )

        for entry in new_drivers:
            # WinBIndex provides URLs — download and upload to MWDB
            url = entry.get("download_url")
            if not url:
                logger.debug(f"No download URL for {entry['sha256'][:12]}, skipping")
                continue

            try:
                import requests
                resp = requests.get(url, timeout=60)
                resp.raise_for_status()
                self._upload_to_mwdb(
                    entry["name"], entry["sha256"], resp.content, "winbindex"
                )
            except Exception as e:
                logger.error(f"Failed to download/upload {entry['sha256'][:12]}: {e}")

        self.rdb.set(
            f"{LAST_POLL_PREFIX}:winbindex",
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        )
        logger.info(f"WinBIndex poll complete: {len(new_drivers)} new driver(s)")

    def poll_virustotal(self):
        """Poll VirusTotal for new 3rd-party driver uploads."""
        logger.info("Starting VirusTotal poll...")

        vt_queries = self.watchlist.get("vt_queries", [])
        dynamic = self._get_dynamic_families()

        new_drivers = virustotal.poll(
            vt_queries, dynamic, self.rdb, KNOWN_KEY, VERSIONS_PREFIX
        )

        for entry in new_drivers:
            content_path = entry.get("content_path")
            if not content_path:
                continue

            try:
                with open(content_path, "rb") as f:
                    content = f.read()
                self._upload_to_mwdb(
                    entry["name"], entry["sha256"], content, "virustotal"
                )
            except Exception as e:
                logger.error(f"Failed to upload {entry['sha256'][:12]}: {e}")
            finally:
                # Clean up temp file
                try:
                    os.unlink(content_path)
                except OSError:
                    pass

        self.rdb.set(
            f"{LAST_POLL_PREFIX}:virustotal",
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        )
        logger.info(f"VT poll complete: {len(new_drivers)} new driver(s)")

    def run(self):
        """Start the scheduler with WinBIndex (6h) and VirusTotal (4h) jobs."""
        logger.info("AutoPiff Driver Monitor starting...")
        logger.info(f"WinBIndex interval: {WINBINDEX_INTERVAL_HOURS}h")
        logger.info(f"VirusTotal interval: {VT_INTERVAL_HOURS}h")
        logger.info(
            f"Monitoring {len(self.watchlist.get('system_drivers', []))} system drivers, "
            f"{len(self.watchlist.get('vt_queries', []))} VT queries"
        )

        scheduler = BlockingScheduler()

        # Run immediately on startup, then on interval
        scheduler.add_job(
            self.poll_winbindex,
            "interval",
            hours=WINBINDEX_INTERVAL_HOURS,
            next_run_time=None,  # Will be set by misfire_grace
            id="winbindex",
        )
        scheduler.add_job(
            self.poll_virustotal,
            "interval",
            hours=VT_INTERVAL_HOURS,
            next_run_time=None,
            id="virustotal",
        )

        # Run both once immediately
        self.poll_winbindex()
        self.poll_virustotal()

        try:
            scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            logger.info("Driver Monitor shutting down")


if __name__ == "__main__":
    monitor = DriverMonitor()
    monitor.run()
