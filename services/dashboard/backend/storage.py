"""Analysis storage backend for AutoPiff Dashboard.

Supports two modes:
- File-based: reads analysis artifacts from a local directory
- MWDB: queries MWDB API for analysis results
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx

from .models import (
    Analysis,
    AnalysisListItem,
    Arch,
    DeltaSummary,
    DispatchInfo,
    DriverInfo,
    Finding,
    IOCTLInfo,
    MatchingQuality,
    MatchingResult,
    NoiseRisk,
    PairingDecision,
    PairingResult,
    ReachabilityClass,
    ReachabilityResult,
    ReachabilityTag,
    ScoreBreakdown,
    SymbolsResult,
)

logger = logging.getLogger(__name__)


def _parse_reachability_class(val: str) -> ReachabilityClass:
    try:
        return ReachabilityClass(val)
    except ValueError:
        return ReachabilityClass.unknown


def _parse_analysis_from_artifacts(analysis_id: str, artifacts: dict) -> Analysis:
    """Parse pipeline output artifacts into an Analysis model."""
    pairing_data = artifacts.get("pairing", {})
    symbols_data = artifacts.get("symbols", {})
    matching_data = artifacts.get("matching", {})
    deltas_data = artifacts.get("semantic_deltas", {})
    reach_data = artifacts.get("reachability", {})

    # Driver info
    driver_new_raw = pairing_data.get("driver_new", {}) or deltas_data.get("driver_new", {})
    driver_old_raw = pairing_data.get("driver_old", {}) or deltas_data.get("driver_old", {})

    driver_new = DriverInfo(
        sha256=driver_new_raw.get("sha256", "unknown"),
        product=driver_new_raw.get("product"),
        version=driver_new_raw.get("version"),
        arch=driver_new_raw.get("arch", "Unknown"),
    )
    driver_old = None
    if driver_old_raw:
        driver_old = DriverInfo(
            sha256=driver_old_raw.get("sha256", "unknown"),
            product=driver_old_raw.get("product"),
            version=driver_old_raw.get("version"),
            arch=driver_old_raw.get("arch", "Unknown"),
        )

    # Pairing
    pairing = None
    if pairing_data.get("decision"):
        pairing = PairingResult(
            decision=PairingDecision(pairing_data["decision"]),
            confidence=pairing_data.get("confidence", 0.0),
            noise_risk=NoiseRisk(pairing_data.get("noise_risk", "high")),
            rationale=pairing_data.get("rationale", []),
            arch_mismatch=pairing_data.get("arch_mismatch", False),
        )

    # Symbols
    symbols = None
    sym_inner = symbols_data.get("symbolization", symbols_data)
    if sym_inner.get("method"):
        symbols = SymbolsResult(
            method=sym_inner["method"],
            coverage=sym_inner.get("coverage", 0.0),
        )

    # Matching
    matching = None
    match_inner = matching_data.get("matching", matching_data)
    if match_inner.get("method"):
        matching = MatchingResult(
            method=match_inner["method"],
            confidence=match_inner.get("confidence", 0.0),
            matched_count=match_inner.get("matched_count", 0),
            added_count=match_inner.get("added_count", 0),
            removed_count=match_inner.get("removed_count", 0),
            changed_count=match_inner.get("changed_count", 0),
            total_new=match_inner.get("total_new", 0),
            total_old=match_inner.get("total_old", 0),
            quality=MatchingQuality(match_inner.get("quality", "low")),
        )

    # Build reachability lookup for enrichment
    reach_tags: dict[str, ReachabilityTag] = {}
    if reach_data:
        for tag in reach_data.get("tags", []):
            rt = ReachabilityTag(
                function=tag["function"],
                reachability_class=_parse_reachability_class(tag.get("reachability_class", "unknown")),
                confidence=tag.get("confidence", 0.0),
                paths=tag.get("paths", []),
                evidence=tag.get("evidence", []),
            )
            reach_tags[tag["function"]] = rt

    # Findings
    findings = []
    for delta in deltas_data.get("deltas", []):
        reach_tag = reach_tags.get(delta.get("function", ""))
        reach_cls = _parse_reachability_class(delta.get("reachability_class", "unknown"))
        reach_path: list[str] = []
        if reach_tag:
            reach_cls = reach_tag.reachability_class
            if reach_tag.paths:
                reach_path = reach_tag.paths[0]

        sb_raw = delta.get("score_breakdown", {})
        score_breakdown = None
        if sb_raw:
            score_breakdown = ScoreBreakdown(
                semantic=sb_raw.get("semantic", 0.0),
                reachability=sb_raw.get("reachability", 0.0),
                sinks=sb_raw.get("sinks", 0.0),
                penalties=sb_raw.get("penalties", 0.0),
                gates=sb_raw.get("gates", []),
            )

        findings.append(Finding(
            function=delta.get("function", "unknown"),
            rule_id=delta.get("rule_id", ""),
            category=delta.get("category", "bounds_check"),
            confidence=delta.get("confidence", 0.0),
            sinks=delta.get("sinks", []),
            indicators=delta.get("indicators", []),
            diff_snippet=delta.get("diff_snippet", ""),
            why_matters=delta.get("why_matters", ""),
            surface_area=delta.get("surface_area", []),
            final_score=delta.get("final_score", 0.0),
            score_breakdown=score_breakdown,
            reachability_class=reach_cls,
            reachability_path=reach_path,
        ))

    # Sort by score descending
    findings.sort(key=lambda f: f.final_score, reverse=True)

    # Summary
    summary_raw = deltas_data.get("summary", {})
    summary = DeltaSummary(
        total_deltas=summary_raw.get("total_deltas", len(findings)),
        by_category=summary_raw.get("by_category", {}),
        by_rule=summary_raw.get("by_rule", {}),
        top_functions=summary_raw.get("top_functions", []),
        top_score=summary_raw.get("top_score", findings[0].final_score if findings else 0.0),
        match_rate=summary_raw.get("match_rate", 0.0),
    )

    # Reachability
    reachability = None
    if reach_data:
        dispatch_raw = reach_data.get("dispatch", {})
        dispatch = DispatchInfo(
            driver_entry=dispatch_raw.get("driver_entry"),
            major_functions=dispatch_raw.get("major_functions", {}),
        ) if dispatch_raw else None

        ioctls = [
            IOCTLInfo(
                ioctl=i.get("ioctl", "unknown"),
                handler=i.get("handler", ""),
                confidence=i.get("confidence", 0.0),
                evidence=i.get("evidence", []),
            )
            for i in reach_data.get("ioctls", [])
        ]

        reachability = ReachabilityResult(
            dispatch=dispatch,
            ioctls=ioctls,
            tags=list(reach_tags.values()),
        )

    created_raw = artifacts.get("_created_at")
    created_at = datetime.fromisoformat(created_raw) if created_raw else datetime.utcnow()

    return Analysis(
        id=analysis_id,
        created_at=created_at,
        driver_new=driver_new,
        driver_old=driver_old,
        pairing=pairing,
        symbols=symbols,
        matching=matching,
        findings=findings,
        summary=summary,
        reachability=reachability,
        notes=deltas_data.get("notes", []) + pairing_data.get("notes", []),
    )


class FileStorage:
    """Read analysis artifacts from a local directory.

    Directory structure:
      analyses_dir/
        <analysis_id>/
          combined.json   (all stages in one file)
        OR
          <analysis_id>.json
    """

    def __init__(self, analyses_dir: str):
        self.analyses_dir = Path(analyses_dir)
        self.analyses_dir.mkdir(parents=True, exist_ok=True)

    def list_analyses(self) -> list[AnalysisListItem]:
        items = []
        for path in sorted(self.analyses_dir.iterdir(), reverse=True):
            try:
                analysis = self._load(path)
                if analysis is None:
                    continue
                reachable = sum(
                    1 for f in analysis.findings
                    if f.reachability_class in (ReachabilityClass.ioctl, ReachabilityClass.irp)
                )
                items.append(AnalysisListItem(
                    id=analysis.id,
                    created_at=analysis.created_at,
                    driver_name=analysis.driver_new.product,
                    arch=analysis.driver_new.arch,
                    decision=analysis.pairing.decision if analysis.pairing else None,
                    noise_risk=analysis.pairing.noise_risk if analysis.pairing else None,
                    total_findings=len(analysis.findings),
                    top_score=analysis.findings[0].final_score if analysis.findings else 0.0,
                    reachable_findings=reachable,
                ))
            except Exception as e:
                logger.warning("Failed to load analysis from %s: %s", path, e)
        return items

    def get_analysis(self, analysis_id: str) -> Optional[Analysis]:
        # Try directory-based first
        dir_path = self.analyses_dir / analysis_id
        if dir_path.is_dir():
            return self._load(dir_path)
        # Try single file
        file_path = self.analyses_dir / f"{analysis_id}.json"
        if file_path.is_file():
            return self._load(file_path)
        return None

    def save_analysis(self, analysis_id: str, artifacts: dict) -> Analysis:
        dir_path = self.analyses_dir / analysis_id
        dir_path.mkdir(parents=True, exist_ok=True)
        combined_path = dir_path / "combined.json"
        artifacts["_created_at"] = datetime.utcnow().isoformat()
        with open(combined_path, "w") as f:
            json.dump(artifacts, f, indent=2)
        return _parse_analysis_from_artifacts(analysis_id, artifacts)

    def _load(self, path: Path) -> Optional[Analysis]:
        if path.is_dir():
            combined = path / "combined.json"
            if not combined.exists():
                return None
            with open(combined) as f:
                data = json.load(f)
            return _parse_analysis_from_artifacts(path.name, data)
        elif path.is_file() and path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
            return _parse_analysis_from_artifacts(path.stem, data)
        return None


class MWDBStorage:
    """Read analysis results from MWDB API."""

    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self._headers = {}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    async def list_analyses(self) -> list[AnalysisListItem]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_url}/file",
                headers=self._headers,
                params={"query": "tag:autopiff:*"},
            )
            if resp.status_code != 200:
                logger.warning("MWDB list failed: %s", resp.status_code)
                return []
            files = resp.json().get("files", [])

        items = []
        for f in files:
            sha = f.get("sha256", "")
            items.append(AnalysisListItem(
                id=sha[:12],
                created_at=datetime.fromisoformat(f["upload_time"]) if "upload_time" in f else datetime.utcnow(),
                driver_name=f.get("file_name"),
                total_findings=0,
            ))
        return items

    async def get_analysis(self, analysis_id: str) -> Optional[Analysis]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.api_url}/file/{analysis_id}",
                headers=self._headers,
            )
            if resp.status_code != 200:
                return None
            file_data = resp.json()

            # Look for autopiff attributes
            attrs = file_data.get("attributes", {})
            artifacts = {}
            for key in ("pairing", "symbols", "matching", "semantic_deltas", "reachability"):
                if key in attrs:
                    artifacts[key] = attrs[key]

        if not artifacts:
            return None
        return _parse_analysis_from_artifacts(analysis_id, artifacts)
