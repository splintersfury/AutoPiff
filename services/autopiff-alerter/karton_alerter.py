#!/usr/bin/env python3
"""
AutoPiff Alerter — Karton consumer that sends Telegram alerts for high-scoring findings.

Consumes: {type: autopiff, kind: semantic_deltas}
Filters:  final_score >= 8.0 AND surface_area in [ioctl, irp, filesystem]
Sends:    Telegram alerts via HTTP API
Stores:   Recent alerts in Redis sorted set (30-day TTL)
"""

import os
import json
import time
import logging

import redis
import requests
from karton.core import Karton, Task

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
REDIS_HOST = os.environ.get("KARTON_REDIS_HOST", "karton-redis")
SCORE_THRESHOLD = float(os.environ.get("AUTOPIFF_SCORE_THRESHOLD", "8.0"))
ALERTABLE_SURFACES = {"ioctl", "irp", "filesystem"}

# Redis keys
ALERTS_KEY = "autopiff:alerts:recent"
ALERTS_FAILED_KEY = "autopiff:alerts:failed"
ALERTS_TTL_SECONDS = 30 * 24 * 3600  # 30 days


class AutoPiffAlerter(Karton):
    """Karton consumer that filters high-scoring AutoPiff findings and sends Telegram alerts."""

    identity = "karton.autopiff.alerter"
    filters = [{"type": "autopiff", "kind": "semantic_deltas"}]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rdb = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)

    def process(self, task: Task) -> None:
        semantic_deltas = task.get_payload("semantic_deltas")
        if not semantic_deltas:
            logger.warning("No semantic_deltas payload in task")
            return

        deltas = semantic_deltas.get("deltas", [])
        driver_new = semantic_deltas.get("driver_new", {})
        driver_old = semantic_deltas.get("driver_old", {})
        summary = semantic_deltas.get("summary", {})

        driver_new_sha = driver_new.get("sha256", "unknown")
        driver_new_ver = driver_new.get("version", "unknown")
        driver_old_ver = driver_old.get("version", "unknown")

        logger.info(
            f"Processing {len(deltas)} deltas for {driver_new_sha[:12]} "
            f"(v{driver_old_ver} -> v{driver_new_ver})"
        )

        alertable = []
        for delta in deltas:
            score = delta.get("final_score", delta.get("confidence", 0))
            surface = delta.get("surface_area", "unknown")

            # surface_area can be a string or a list of strings
            if isinstance(surface, list):
                surface_match = any(s in ALERTABLE_SURFACES for s in surface)
            else:
                surface_match = surface in ALERTABLE_SURFACES

            if score >= SCORE_THRESHOLD and surface_match:
                alertable.append(delta)

        if not alertable:
            logger.info(
                f"No alertable findings (threshold={SCORE_THRESHOLD}, "
                f"surfaces={ALERTABLE_SURFACES})"
            )
            return

        logger.info(f"Found {len(alertable)} alertable findings")

        # Build and send alert
        msg = self._build_alert_message(
            alertable, driver_new_sha, driver_new_ver, driver_old_ver, summary
        )
        self._send_telegram_alert(msg)

        # Store in Redis for /findings command
        self._store_alerts(alertable, driver_new_sha)

    def _build_alert_message(
        self, findings, driver_sha, new_ver, old_ver, summary
    ) -> str:
        top = findings[0]
        top_score = top.get("final_score", top.get("confidence", 0))
        count = len(findings)

        # Check if any findings are new attack surface
        has_new_features = any(
            f.get("change_type") == "new_feature" for f in findings
        )

        if has_new_features:
            new_count = sum(1 for f in findings if f.get("change_type") == "new_feature")
            msg = f"*AutoPiff Alert — New Attack Surface* — {count} finding{'s' if count > 1 else ''} ({new_count} new)\n\n"
        else:
            msg = f"*AutoPiff Alert* — {count} high-scoring finding{'s' if count > 1 else ''}\n\n"

        msg += f"Driver: `{driver_sha[:16]}...`\n"
        msg += f"Versions: {old_ver} -> {new_ver}\n"
        msg += f"Top score: *{top_score:.1f}*\n\n"

        for i, finding in enumerate(findings[:5]):
            score = finding.get("final_score", finding.get("confidence", 0))
            func = finding.get("function", "unknown")
            rule = finding.get("rule_id", "unknown")
            category = finding.get("category", "unknown")
            surface = finding.get("surface_area", "unknown")
            change_type = finding.get("change_type", "patch")
            tag = "[NEW]" if change_type == "new_feature" else "[PATCH]"

            msg += f"*{i+1}.* {tag} `{func}` — *{score:.1f}*\n"
            msg += f"   {category} | {rule} | {surface}\n"

            why = finding.get("why_matters", "")
            if why:
                msg += f"   _{why[:100]}_\n"
            msg += "\n"

        if count > 5:
            msg += f"_...and {count - 5} more findings_\n"

        return msg

    def _send_telegram_alert(self, msg: str):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            logger.warning("Telegram credentials not configured, skipping alert")
            self._store_failed_alert(msg, "no_credentials")
            return

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={
                        "chat_id": TELEGRAM_CHAT_ID,
                        "text": msg,
                        "parse_mode": "Markdown",
                    },
                    timeout=15,
                )
                if resp.status_code == 200:
                    logger.info("Telegram alert sent successfully")
                    return
                elif resp.status_code == 429:
                    # Rate limited — retry with backoff
                    retry_after = int(resp.headers.get("Retry-After", 2 ** attempt))
                    logger.warning(f"Telegram rate limited, retrying in {retry_after}s (attempt {attempt}/{max_retries})")
                    import time
                    time.sleep(retry_after)
                    continue
                else:
                    logger.error(f"Telegram API error: {resp.status_code} {resp.text}")
                    self._store_failed_alert(msg, f"http_{resp.status_code}")
                    return
            except requests.RequestException as e:
                logger.error(f"Telegram request failed (attempt {attempt}/{max_retries}): {e}")
                if attempt < max_retries:
                    import time
                    time.sleep(2 ** attempt)
                    continue
                self._store_failed_alert(msg, str(e))
                return

    def _store_alerts(self, findings, driver_sha):
        now = time.time()
        pipe = self.rdb.pipeline()
        for finding in findings:
            alert_entry = {
                "score": finding.get("final_score", finding.get("confidence", 0)),
                "function": finding.get("function", "unknown"),
                "rule_id": finding.get("rule_id", "unknown"),
                "category": finding.get("category", "unknown"),
                "surface_area": finding.get("surface_area", "unknown"),
                "driver_new": driver_sha,
                "why_matters": finding.get("why_matters", ""),
            }
            pipe.zadd(ALERTS_KEY, {json.dumps(alert_entry): now})

        # Trim old entries (keep 30 days)
        cutoff = now - ALERTS_TTL_SECONDS
        pipe.zremrangebyscore(ALERTS_KEY, "-inf", cutoff)
        pipe.execute()

    def _store_failed_alert(self, msg: str, reason: str):
        now = time.time()
        entry = json.dumps({"msg": msg[:500], "reason": reason, "ts": now})
        self.rdb.zadd(ALERTS_FAILED_KEY, {entry: now})


if __name__ == "__main__":
    AutoPiffAlerter().loop()
