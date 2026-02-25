"""Triage state store — file-backed JSON persistence.

Stores finding triage states (untriaged / investigating / confirmed /
false_positive / resolved) keyed by ``{analysis_id}::{function}``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import TriageEntry, TriageState, TriageSummary

logger = logging.getLogger(__name__)


class TriageStore:
    """Manages finding triage states in a JSON file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text())
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load triage store: %s", e)
                self._data = {}

    def _save(self) -> None:
        try:
            self.path.write_text(json.dumps(self._data, indent=2, default=str))
        except OSError as e:
            logger.error("Failed to save triage store: %s", e)

    @staticmethod
    def _key(analysis_id: str, function: str) -> str:
        return f"{analysis_id}::{function}"

    def get(self, analysis_id: str, function: str) -> TriageEntry:
        key = self._key(analysis_id, function)
        if key in self._data:
            return TriageEntry(**self._data[key])
        return TriageEntry(
            analysis_id=analysis_id,
            function=function,
            state=TriageState.untriaged,
        )

    def get_for_analysis(self, analysis_id: str) -> dict[str, TriageEntry]:
        """Return all triage entries for an analysis, keyed by function name."""
        result = {}
        prefix = f"{analysis_id}::"
        for key, data in self._data.items():
            if key.startswith(prefix):
                entry = TriageEntry(**data)
                result[entry.function] = entry
        return result

    def set(
        self,
        analysis_id: str,
        function: str,
        state: TriageState,
        note: str = "",
    ) -> TriageEntry:
        key = self._key(analysis_id, function)
        entry = TriageEntry(
            analysis_id=analysis_id,
            function=function,
            state=state,
            updated_at=datetime.now(),
            note=note,
        )
        self._data[key] = entry.model_dump()
        self._save()
        return entry

    def summary(self) -> TriageSummary:
        counts = {s.value: 0 for s in TriageState}
        for data in self._data.values():
            state = data.get("state", "untriaged")
            if state in counts:
                counts[state] += 1
        return TriageSummary(
            untriaged=counts["untriaged"],
            investigating=counts["investigating"],
            confirmed=counts["confirmed"],
            false_positive=counts["false_positive"],
            resolved=counts["resolved"],
            total=sum(counts.values()),
        )

    def recent_updates(self, limit: int = 20) -> list[TriageEntry]:
        """Return the most recent triage updates (non-untriaged)."""
        entries = []
        for data in self._data.values():
            if data.get("state", "untriaged") != "untriaged":
                entries.append(TriageEntry(**data))
        entries.sort(key=lambda e: e.updated_at, reverse=True)
        return entries[:limit]
