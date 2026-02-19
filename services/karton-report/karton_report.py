"""
AutoPiff Stage 7: Report Generation

Consumes ranked findings from Stage 6, generates human-readable (report.md)
and machine-readable (report.json) reports, uploads both to MWDB as children
of the driver sample, and tags the sample autopiff_reported.
"""

import os
import json
import logging
from datetime import datetime, timezone

from karton.core import Karton, Task, Resource
from jsonschema import validate
from mwdblib import MWDB

from . import report_templates as tpl

logger = logging.getLogger("autopiff.report")

AUTOPIFF_VERSION = "0.6.0"


class ReportKarton(Karton):
    """
    AutoPiff Stage 7: Report Generation.

    Consumes ranked findings from Stage 6, generates human-readable
    (Markdown) and machine-readable (JSON) reports, validates against
    the report schema, and uploads both to MWDB.

    Consumes: type=autopiff, kind=ranking
    Produces: report.md + report.json uploaded to MWDB
    """

    identity = "AutoPiff.Stage7"
    filters = [
        {"type": "autopiff", "kind": "ranking"}
    ]

    def __init__(self, config=None, backend=None):
        super().__init__(config=config, backend=backend)

        # Load report output schema
        schema_path = os.environ.get(
            "AUTOPIFF_REPORT_SCHEMA",
            os.path.join(os.path.dirname(__file__), "report.schema.json")
        )
        with open(schema_path, "r") as f:
            self.schema = json.load(f)

        # MWDB connection
        self.mwdb_url = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
        self.mwdb_key = os.environ.get("MWDB_API_KEY", "")

    def process(self, task: Task) -> None:
        ranking_raw = task.headers.get("ranking")
        if isinstance(ranking_raw, str):
            ranking = json.loads(ranking_raw)
        else:
            ranking = ranking_raw

        if not ranking:
            self.log.error("No ranking data in task")
            return

        semantic_deltas = task.get_payload("semantic_deltas")

        # Gather all context
        driver_new = ranking.get("driver_new", {})
        driver_old = ranking.get("driver_old", {})
        findings = ranking.get("findings", [])
        skipped = ranking.get("skipped_findings", [])
        summary = ranking.get("summary", {})

        # Get pairing info from task payload or defaults
        pairing_info = self._get_pairing_info(task)

        # Derive driver name from semantic_deltas or sha
        driver_name = self._get_driver_name(semantic_deltas, driver_new)
        arch = self._get_arch(semantic_deltas)

        # Count reachable findings
        reachable_count = sum(
            1 for f in findings if f.get("reachability_class", "unknown") != "unknown"
        )

        # Generate human report
        report_md = self._generate_markdown_report(
            driver_name, arch, driver_old, driver_new,
            pairing_info, findings, skipped, reachable_count
        )

        # Generate machine report
        report_json = self._generate_json_report(
            driver_name, arch, driver_old, driver_new,
            pairing_info, findings, skipped, reachable_count
        )

        # Validate JSON report
        validate(instance=report_json, schema=self.schema)

        self.log.info(
            f"Generated reports for {driver_name}: "
            f"{len(findings)} findings, {reachable_count} reachable"
        )

        # Upload to MWDB
        self._upload_to_mwdb(
            task, driver_new, report_md, report_json
        )

    def _get_pairing_info(self, task: Task) -> dict:
        """Extract pairing info from task payload."""
        pairing = {
            "decision": "accept",
            "noise_risk": "low",
            "confidence": 0.80,
        }
        pairing_data = task.get_payload("pairing")
        if pairing_data:
            pairing["decision"] = pairing_data.get("decision", "accept")
            pairing["noise_risk"] = pairing_data.get("noise_risk", "low")
            pairing["confidence"] = pairing_data.get("confidence", 0.80)
        return pairing

    def _get_driver_name(self, semantic_deltas, driver_new):
        """Get human-readable driver name."""
        if semantic_deltas:
            name = semantic_deltas.get("driver_name")
            if name:
                return name
        sha = driver_new.get("sha256", "unknown")
        return sha[:16] if sha != "unknown" else "unknown_driver"

    def _get_arch(self, semantic_deltas):
        """Get driver architecture."""
        if semantic_deltas:
            return semantic_deltas.get("arch", "x64")
        return "x64"

    def _generate_markdown_report(
        self, driver_name, arch, driver_old, driver_new,
        pairing_info, findings, skipped, reachable_count
    ):
        """Generate the human-readable markdown report."""
        sections = []

        # Header
        sections.append(tpl.render_header(
            driver_name, arch, driver_old, driver_new, pairing_info
        ))

        # Executive Summary
        sections.append(tpl.render_executive_summary(findings, reachable_count))

        # Top Findings
        sections.append(tpl.render_top_findings(findings))

        # Skipped / Deprioritized
        sections.append(tpl.render_skipped(skipped))

        return "\n---\n\n".join(sections)

    def _generate_json_report(
        self, driver_name, arch, driver_old, driver_new,
        pairing_info, findings, skipped, reachable_count
    ):
        """Generate the machine-readable JSON report."""
        # Collect top categories
        categories = [f.get("category", "") for f in findings]
        unique_cats = list(dict.fromkeys(categories))

        # Transform findings for report schema
        report_findings = []
        for f in findings:
            report_findings.append({
                "rank": f.get("rank", 0),
                "function": f.get("function", ""),
                "score": f.get("final_score", 0.0),
                "confidence": f.get("semantic_confidence", 0.0),
                "rule_ids": f.get("rule_ids", []),
                "category": f.get("category", ""),
                "reachability": {
                    "class": f.get("reachability_class", "unknown"),
                    "path": f.get("reachability_path", []),
                },
                "sinks": f.get("sinks", []),
                "added_checks": f.get("indicators", []),
                "why": f.get("why_matters", ""),
            })

        # Transform skipped
        report_skipped = []
        for s in skipped:
            report_skipped.append({
                "function": s.get("function", ""),
                "reason": s.get("reason", ""),
            })

        return {
            "autopiff_stage": "report",
            "driver": {
                "name": driver_name,
                "arch": arch,
                "old": {
                    "sha256": driver_old.get("sha256", ""),
                    "version": driver_old.get("version"),
                },
                "new": {
                    "sha256": driver_new.get("sha256", ""),
                    "version": driver_new.get("version"),
                },
            },
            "pairing": pairing_info,
            "summary": {
                "total_findings": len(findings),
                "reachable_findings": reachable_count,
                "top_categories": unique_cats[:5],
            },
            "findings": report_findings,
            "skipped": report_skipped,
            "metadata": {
                "autopiff_version": AUTOPIFF_VERSION,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }

    def _upload_to_mwdb(self, task, driver_new, report_md, report_json):
        """Upload reports to MWDB as children of the driver sample."""
        if not self.mwdb_key:
            self.log.warning("No MWDB_API_KEY set, skipping MWDB upload")
            return

        try:
            mwdb = MWDB(api_url=self.mwdb_url, api_key=self.mwdb_key)
        except Exception as e:
            self.log.error(f"Failed to connect to MWDB: {e}")
            return

        sha256 = driver_new.get("sha256", "")
        if not sha256:
            self.log.error("No driver sha256, cannot upload to MWDB")
            return

        try:
            parent = mwdb.query_file(sha256)
        except Exception as e:
            self.log.warning(f"Could not find parent sample {sha256}: {e}")
            parent = None

        # Upload report.md
        try:
            md_content = report_md.encode("utf-8")
            md_file = mwdb.upload_file(
                f"autopiff_report_{sha256[:12]}.md",
                md_content,
                parent=parent,
            )
            self.log.info(f"Uploaded report.md: {md_file.sha256}")
        except Exception as e:
            self.log.error(f"Failed to upload report.md: {e}")

        # Upload report.json
        try:
            json_content = json.dumps(report_json, indent=2).encode("utf-8")
            json_file = mwdb.upload_file(
                f"autopiff_report_{sha256[:12]}.json",
                json_content,
                parent=parent,
            )
            self.log.info(f"Uploaded report.json: {json_file.sha256}")
        except Exception as e:
            self.log.error(f"Failed to upload report.json: {e}")

        # Tag the sample
        if parent:
            try:
                parent.add_tag("autopiff_reported")
                self.log.info(f"Tagged {sha256[:12]} with autopiff_reported")
            except Exception as e:
                self.log.error(f"Failed to tag sample: {e}")


if __name__ == "__main__":
    ReportKarton().loop()
