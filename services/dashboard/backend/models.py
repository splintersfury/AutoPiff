"""Pydantic models for AutoPiff Dashboard API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# --- Enums ---


class Arch(str, Enum):
    x64 = "x64"
    x86 = "x86"
    ARM64 = "ARM64"
    Unknown = "Unknown"


class PairingDecision(str, Enum):
    accept = "accept"
    quarantine = "quarantine"
    reject = "reject"


class NoiseRisk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class MatchingQuality(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"


class RuleCategory(str, Enum):
    bounds_check = "bounds_check"
    lifetime_fix = "lifetime_fix"
    user_boundary_check = "user_boundary_check"
    int_overflow = "int_overflow"
    state_hardening = "state_hardening"


class ReachabilityClass(str, Enum):
    ioctl = "ioctl"
    irp = "irp"
    pnp = "pnp"
    internal = "internal"
    unknown = "unknown"


# --- Driver Info ---


class DriverInfo(BaseModel):
    sha256: str
    product: Optional[str] = None
    version: Optional[str] = None
    arch: Arch = Arch.Unknown


# --- Stage Models ---


class PairingResult(BaseModel):
    decision: PairingDecision
    confidence: float = Field(ge=0.0, le=1.0)
    noise_risk: NoiseRisk
    rationale: list[str] = []
    arch_mismatch: bool = False


class SymbolAnchor(BaseModel):
    name: str
    addr_new: str
    addr_old: str
    confidence: float = Field(ge=0.0, le=1.0)


class SymbolsResult(BaseModel):
    method: str = "ghidra_decompile"
    coverage: float = Field(ge=0.0, le=1.0)
    anchors: list[SymbolAnchor] = []


class MatchingResult(BaseModel):
    method: str = "hash_lcs"
    confidence: float = Field(ge=0.0, le=1.0)
    matched_count: int = 0
    added_count: int = 0
    removed_count: int = 0
    changed_count: int = 0
    total_new: int = 0
    total_old: int = 0
    quality: MatchingQuality = MatchingQuality.low


class ScoreBreakdown(BaseModel):
    semantic: float = 0.0
    reachability: float = 0.0
    sinks: float = 0.0
    penalties: float = 0.0
    gates: list[str] = []


class Finding(BaseModel):
    function: str
    rule_id: str
    category: RuleCategory
    confidence: float = Field(ge=0.0, le=1.0)
    sinks: list[str] = []
    indicators: list[str] = []
    diff_snippet: str = ""
    why_matters: str = ""
    surface_area: list[str] = []
    final_score: float = 0.0
    score_breakdown: Optional[ScoreBreakdown] = None
    reachability_class: ReachabilityClass = ReachabilityClass.unknown
    reachability_path: list[str] = []


class DeltaSummary(BaseModel):
    total_deltas: int = 0
    by_category: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    top_functions: list[str] = []
    top_score: float = 0.0
    match_rate: float = 0.0


class ReachabilityTag(BaseModel):
    function: str
    reachability_class: ReachabilityClass
    confidence: float = Field(ge=0.0, le=1.0)
    paths: list[list[str]] = []
    evidence: list[str] = []


class IOCTLInfo(BaseModel):
    ioctl: str
    handler: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = []


class DispatchInfo(BaseModel):
    driver_entry: Optional[str] = None
    major_functions: dict[str, Optional[str]] = {}


class ReachabilityResult(BaseModel):
    dispatch: Optional[DispatchInfo] = None
    ioctls: list[IOCTLInfo] = []
    tags: list[ReachabilityTag] = []


# --- Full Analysis ---


class Analysis(BaseModel):
    id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    driver_new: DriverInfo
    driver_old: Optional[DriverInfo] = None
    pairing: Optional[PairingResult] = None
    symbols: Optional[SymbolsResult] = None
    matching: Optional[MatchingResult] = None
    findings: list[Finding] = []
    summary: Optional[DeltaSummary] = None
    reachability: Optional[ReachabilityResult] = None
    notes: list[str] = []


class AnalysisListItem(BaseModel):
    id: str
    created_at: datetime
    driver_name: Optional[str] = None
    arch: Arch = Arch.Unknown
    decision: Optional[PairingDecision] = None
    noise_risk: Optional[NoiseRisk] = None
    total_findings: int = 0
    top_score: float = 0.0
    reachable_findings: int = 0


# --- API Responses ---


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"


class AnalysisListResponse(BaseModel):
    analyses: list[AnalysisListItem]
    total: int
