#!/usr/bin/env python3
"""
Karton stale task cleanup — removes orphaned, crashed, and stale tasks.

Designed to run as a periodic cron job or manual maintenance tool.
Connects to the Karton Redis instance and:
  1. Deletes tasks stuck in 'Crashed' status
  2. Deletes tasks waiting for consumers that no longer exist
  3. Cleans up old crash logs
  4. Reports summary of what was cleaned

Usage:
  python3 scripts/cleanup_karton.py                    # Dry run
  python3 scripts/cleanup_karton.py --execute          # Actually delete
  python3 scripts/cleanup_karton.py --redis-host HOST  # Custom Redis host

Environment:
  KARTON_REDIS_HOST  (default: localhost for local, karton-redis for Docker)
"""

import argparse
import json
import os
import sys
import time

import redis


# Known active consumers — tasks for unlisted consumers are orphaned
ACTIVE_CONSUMERS = {
    "karton.classifier",
    "karton.driver-classifier",
    "AutoPiff.PatchDiffer",
    "AutoPiff.Stage5",
    "AutoPiff.Stage6",
    "AutoPiff.Stage7",
    "karton.autopiff.alerter",
    "karton.driver.ioctlance",
    "karton.driver.signature",
    "karton.driver.reporter",
}

# Max age for tasks before they're considered stale (48 hours)
STALE_THRESHOLD_SECONDS = 48 * 3600


def cleanup(redis_host, redis_port, dry_run=True):
    """Scan and clean up stale/orphaned Karton tasks."""
    rdb = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)

    try:
        rdb.ping()
    except redis.ConnectionError:
        print(f"ERROR: Cannot connect to Redis at {redis_host}:{redis_port}")
        sys.exit(1)

    task_keys = rdb.keys("karton.task:*")
    crash_keys = rdb.keys("karton.crash:*")

    print(f"Found {len(task_keys)} task(s), {len(crash_keys)} crash log(s)")
    print()

    to_delete = []
    stats = {"crashed": 0, "orphaned": 0, "stale": 0, "active": 0}

    for key in task_keys:
        key_type = rdb.type(key)
        if key_type == "string":
            raw = rdb.get(key)
        else:
            # Skip non-string keys
            continue

        if not raw:
            continue

        try:
            task = json.loads(raw)
        except json.JSONDecodeError:
            to_delete.append((key, "corrupt JSON"))
            continue

        status = task.get("status", "unknown")
        receiver = task.get("headers", {}).get("receiver", "unknown")
        uid = task.get("uid", key)
        last_update = task.get("last_update", 0)

        # 1. Crashed tasks
        if status == "Crashed":
            to_delete.append((key, f"crashed (receiver={receiver})"))
            stats["crashed"] += 1
            continue

        # 2. Orphaned tasks — consumer no longer exists
        if status == "Spawned" and receiver not in ACTIVE_CONSUMERS:
            to_delete.append((key, f"orphaned (receiver={receiver} not active)"))
            stats["orphaned"] += 1
            continue

        # 3. Stale tasks — spawned/started but stuck too long
        if status in ("Spawned", "Started") and last_update:
            age = time.time() - last_update
            if age > STALE_THRESHOLD_SECONDS:
                hours = age / 3600
                to_delete.append((key, f"stale {hours:.0f}h (status={status}, receiver={receiver})"))
                stats["stale"] += 1
                continue

        stats["active"] += 1

    # Report
    if to_delete:
        action = "Would delete" if dry_run else "Deleting"
        print(f"{action} {len(to_delete)} task(s):")
        for key, reason in to_delete:
            print(f"  {reason}")
            if not dry_run:
                rdb.delete(key)
        print()

    # Clean crash logs
    if crash_keys and not dry_run:
        for key in crash_keys:
            rdb.delete(key)
        print(f"Deleted {len(crash_keys)} crash log(s)")
    elif crash_keys:
        print(f"Would delete {len(crash_keys)} crash log(s)")

    print()
    print(f"Summary: {stats['crashed']} crashed, {stats['orphaned']} orphaned, "
          f"{stats['stale']} stale, {stats['active']} active")

    if dry_run and to_delete:
        print()
        print("Run with --execute to actually delete these tasks")


def main():
    parser = argparse.ArgumentParser(description="Clean up stale Karton tasks")
    parser.add_argument("--execute", action="store_true", help="Actually delete (default is dry run)")
    parser.add_argument("--redis-host", default=os.environ.get("KARTON_REDIS_HOST", "localhost"))
    parser.add_argument("--redis-port", type=int, default=6379)
    args = parser.parse_args()

    cleanup(args.redis_host, args.redis_port, dry_run=not args.execute)


if __name__ == "__main__":
    main()
