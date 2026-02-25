#!/usr/bin/env python3
"""
DriverAtlas Triage — Karton consumer that scores every driver's attack surface.

Consumes: {type: "driver", kind: "driver:windows"}
Actions:
  - Scans driver with DriverAtlas structural fingerprinting
  - Scores attack surface using attack_surface.yaml rules
  - Tags MWDB sample with score, framework, risk level
  - Sends Telegram alert if score >= threshold
  - Emits derived task {type: driveratlas, kind: triage} for downstream
"""

import os
import json
import logging
import tempfile

import requests
from karton.core import Karton, Task, Resource
from mwdblib import MWDB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Configuration
MWDB_API_URL = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
MWDB_API_KEY = os.environ.get("MWDB_API_KEY", "")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
SCORE_THRESHOLD = float(os.environ.get("DRIVERATLAS_SCORE_THRESHOLD", "8.0"))

# DriverAtlas paths (inside container)
SIGNATURES_DIR = os.environ.get("DRIVERATLAS_SIGNATURES_DIR", "/app/driveratlas-signatures")
FRAMEWORKS_PATH = os.path.join(SIGNATURES_DIR, "frameworks.yaml")
CATEGORIES_PATH = os.path.join(SIGNATURES_DIR, "api_categories.yaml")
ATTACK_SURFACE_PATH = os.path.join(SIGNATURES_DIR, "attack_surface.yaml")


def _escape_md(text: str) -> str:
    """Escape Telegram Markdown special characters in dynamic strings."""
    for ch in ("_", "*", "`", "[", "]"):
        text = text.replace(ch, f"\\{ch}")
    return text


class DriverTriageKarton(Karton):
    """Karton consumer that triages every Windows driver via DriverAtlas scoring."""

    identity = "karton.driveratlas.triage"
    filters = [{"type": "driver", "kind": "driver:windows"}]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mwdb = None
        self._classifier = None
        self._scorer = None

    @property
    def mwdb(self):
        if self._mwdb is None:
            self._mwdb = MWDB(api_url=MWDB_API_URL, api_key=MWDB_API_KEY)
        return self._mwdb

    @property
    def classifier(self):
        if self._classifier is None:
            from driveratlas.framework_detect import FrameworkClassifier
            if os.path.exists(FRAMEWORKS_PATH):
                self._classifier = FrameworkClassifier(FRAMEWORKS_PATH)
        return self._classifier

    @property
    def scorer(self):
        if self._scorer is None:
            from driveratlas.scoring import AttackSurfaceScorer
            self._scorer = AttackSurfaceScorer(ATTACK_SURFACE_PATH)
        return self._scorer

    def process(self, task: Task) -> None:
        sample = task.get_resource("sample")
        if not sample:
            logger.warning("No sample resource in task")
            return

        sha256 = task.headers.get("sha256", "unknown")
        logger.info(f"Triaging driver {sha256[:16]}...")

        # Write sample to temp file for scanning
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sys") as tmp:
            tmp.write(sample.content)
            tmp_path = tmp.name

        try:
            from driveratlas.scanner import scan_driver

            cats_path = CATEGORIES_PATH if os.path.exists(CATEGORIES_PATH) else None
            profile = scan_driver(tmp_path, classifier=self.classifier, categories_path=cats_path)
            score = self.scorer.score(profile)

            logger.info(
                f"Triage complete: {profile.name} — "
                f"score={score.total:.1f} ({score.risk_level}), "
                f"framework={profile.framework}"
            )

            # Tag MWDB sample
            self._tag_mwdb(sha256, profile, score)

            # Telegram alert for high scorers
            if score.total >= SCORE_THRESHOLD:
                self._send_telegram_alert(profile, score, sha256)

            # Emit derived task for downstream consumers
            triage_data = {
                "driver_name": profile.name,
                "sha256": profile.sha256,
                "score": score.total,
                "risk_level": score.risk_level,
                "framework": profile.framework,
                "framework_confidence": profile.framework_confidence,
                "import_count": profile.import_count,
                "device_names": profile.device_names,
                "flags": score.flags,
                "contributions": score.to_dict()["contributions"],
            }

            derived = task.derive_task({
                "type": "driveratlas",
                "kind": "triage",
            })
            derived.add_payload("triage", triage_data)
            derived.add_resource("sample", sample)
            self.send_task(derived)

        except Exception as e:
            logger.error(f"Triage failed for {sha256[:16]}: {e}", exc_info=True)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.debug(f"Failed to clean up temp file {tmp_path}: {e}")

    def _tag_mwdb(self, sha256: str, profile, score):
        """Tag the MWDB sample with triage results."""
        if not MWDB_API_KEY:
            logger.debug("No MWDB_API_KEY, skipping tagging")
            return

        try:
            mwdb_file = self.mwdb.query_file(sha256)
            if not mwdb_file:
                logger.warning(f"Sample {sha256[:16]} not found in MWDB")
                return

            mwdb_file.add_tag(f"attack_surface_score:{score.total:.1f}")
            mwdb_file.add_tag(f"risk:{score.risk_level}")
            mwdb_file.add_tag(f"framework:{profile.framework}")
            mwdb_file.add_tag("driveratlas_triaged")

            logger.info(f"Tagged MWDB sample {sha256[:16]} with score={score.total:.1f}")
        except Exception as e:
            logger.warning(f"MWDB tagging failed: {e}")

    def _send_telegram_alert(self, profile, score, sha256: str):
        """Send Telegram alert for high-scoring triage result."""
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            logger.debug("Telegram not configured, skipping alert")
            return

        msg = f"*DriverAtlas Triage Alert*\n\n"
        msg += f"Driver: `{_escape_md(profile.name)}`\n"
        msg += f"SHA256: `{_escape_md(sha256[:16])}...`\n"
        msg += f"Score: *{score.total:.1f}* ({_escape_md(score.risk_level.upper())})\n"
        msg += f"Framework: {_escape_md(profile.framework)}\n"
        msg += f"Imports: {profile.import_count}\n"

        if profile.device_names:
            msg += f"Devices: {', '.join(_escape_md(d) for d in profile.device_names[:3])}\n"

        if score.flags:
            msg += f"\nRisk factors:\n"
            for flag in score.flags[:5]:
                msg += f"  - {_escape_md(flag)}\n"

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
                logger.info(f"Telegram triage alert sent for {profile.name}")
            else:
                logger.error(f"Telegram API error: {resp.status_code}")
        except Exception as e:
            logger.error(f"Telegram request failed: {e}")


if __name__ == "__main__":
    DriverTriageKarton().loop()
