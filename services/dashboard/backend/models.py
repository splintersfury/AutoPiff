"""Pydantic models for AutoPiff Dashboard API."""

from __future__ import annotations

from datetime import datetime, timezone
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


class ChangeType(str, Enum):
    patch = "patch"
    new_feature = "new_feature"


class RuleCategory(str, Enum):
    bounds_check = "bounds_check"
    lifetime_fix = "lifetime_fix"
    user_boundary_check = "user_boundary_check"
    int_overflow = "int_overflow"
    state_hardening = "state_hardening"
    authorization = "authorization"
    race_condition = "race_condition"
    info_disclosure = "info_disclosure"
    ioctl_hardening = "ioctl_hardening"
    mdl_handling = "mdl_handling"
    object_management = "object_management"
    string_handling = "string_handling"
    pool_hardening = "pool_hardening"
    crypto_hardening = "crypto_hardening"
    error_path_hardening = "error_path_hardening"
    dos_hardening = "dos_hardening"
    ndis_hardening = "ndis_hardening"
    filesystem_filter = "filesystem_filter"
    pnp_power = "pnp_power"
    dma_mmio = "dma_mmio"
    wdf_hardening = "wdf_hardening"
    new_attack_surface = "new_attack_surface"


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
    change_type: ChangeType = ChangeType.patch
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
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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
    version: str = "0.2.0"


class AnalysisListResponse(BaseModel):
    analyses: list[AnalysisListItem]
    total: int


# --- Triage Workflow ---


class TriageState(str, Enum):
    untriaged = "untriaged"
    investigating = "investigating"
    confirmed = "confirmed"
    false_positive = "false_positive"
    resolved = "resolved"


class TriageEntry(BaseModel):
    """Triage state for a single finding (keyed by analysis_id + function)."""
    analysis_id: str
    function: str
    state: TriageState = TriageState.untriaged
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = ""


class TriageUpdate(BaseModel):
    """Request body for updating triage state."""
    state: TriageState
    note: str = ""


class TriageSummary(BaseModel):
    """Aggregate triage counts."""
    untriaged: int = 0
    investigating: int = 0
    confirmed: int = 0
    false_positive: int = 0
    resolved: int = 0
    total: int = 0


# --- Activity Feed ---


class ActivityType(str, Enum):
    new_analysis = "new_analysis"
    high_score_finding = "high_score_finding"
    triage_update = "triage_update"


class ActivityItem(BaseModel):
    """A single activity feed entry."""
    type: ActivityType
    timestamp: str
    title: str
    detail: str = ""
    link: str = ""
    score: Optional[float] = None


# --- Corpus Validation ---


# --- Driver Grouping ---


class DriverSummary(BaseModel):
    driver_name: str
    analysis_count: int = 0
    latest_analysis: Optional[str] = None
    latest_date: Optional[datetime] = None
    highest_score: float = 0.0
    total_findings: int = 0
    reachable_findings: int = 0
    arch: Arch = Arch.Unknown


# --- Alert History ---


class AlertEntry(BaseModel):
    score: float = 0.0
    function: str = ""
    rule_id: str = ""
    category: str = ""
    surface_area: str = ""
    driver_new: str = ""
    why_matters: str = ""
    timestamp: float = 0.0


class VariantAlertEntry(BaseModel):
    source_driver: str = ""
    source_function: str = ""
    bug_class: str = ""
    variant_driver: str = ""
    variant_function: str = ""
    similarity: float = 0.0
    confidence: float = 0.0
    reasoning: str = ""
    timestamp: float = 0.0


class AlertsResponse(BaseModel):
    alerts: list[AlertEntry] = []
    variants: list[VariantAlertEntry] = []


# --- Search ---


class SearchResult(BaseModel):
    type: str  # "analysis", "finding", "driver"
    id: str
    title: str
    detail: str = ""
    score: Optional[float] = None
    link: str = ""


class SearchResponse(BaseModel):
    query: str
    results: list[SearchResult] = []
    total: int = 0


# --- Pipeline Health ---


class PipelineStage(BaseModel):
    name: str
    identity: str
    status: str = "unknown"
    last_seen: Optional[str] = None


class PipelineHealth(BaseModel):
    stages: list[PipelineStage] = []
    active_consumers: int = 0
    redis_connected: bool = False


# --- Stats / Trends ---


class TrendPoint(BaseModel):
    date: str
    analyses: int = 0
    findings: int = 0
    reachable: int = 0
    avg_score: float = 0.0


class ScoreBucket(BaseModel):
    bucket: str
    count: int = 0


class CategoryCount(BaseModel):
    category: str
    count: int = 0


class StatsResponse(BaseModel):
    trends: list[TrendPoint] = []
    score_distribution: list[ScoreBucket] = []
    by_category: list[CategoryCount] = []
    total_analyses: int = 0
    total_findings: int = 0
    total_reachable: int = 0


# --- Corpus Validation ---


class CorpusStatus(str, Enum):
    pending = "pending"
    downloaded = "downloaded"
    decompiled = "decompiled"
    evaluated = "evaluated"


class DetectionDetail(BaseModel):
    function_pattern: str = ""
    matched_function: Optional[str] = None
    expected_category: str = ""
    expected_rules: list[str] = []
    min_confidence: float = 0.0
    actual_category: Optional[str] = None
    actual_rule: Optional[str] = None
    actual_confidence: Optional[float] = None
    is_tp: bool = False


class UnexpectedHit(BaseModel):
    """A false positive: rule fired on a function with no expected detection."""
    function: str
    rule_id: str
    category: str
    confidence: float = 0.0


class CVECorpusEntry(BaseModel):
    cve_id: str
    driver: str
    description: str = ""
    expected_category_primary: str = ""
    vuln_build: str = ""
    fix_build: str = ""
    vuln_kb: str = ""
    fix_kb: str = ""
    expected_detections_count: int = 0
    detection_details: list[DetectionDetail] = []
    unexpected_hits: list[UnexpectedHit] = []
    status: CorpusStatus = CorpusStatus.pending
    tp: int = 0
    fn: int = 0
    fp: int = 0
    total_changed: int = 0
    total_hits: int = 0
    error: Optional[str] = None


class CategoryMetrics(BaseModel):
    category: str
    cve_count: int = 0
    tp: int = 0
    fn: int = 0
    fp: int = 0
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1: Optional[float] = None


class DetectionRates(BaseModel):
    """High-level detection rates across the evaluated corpus."""
    vuln_function_flagged: float = 0.0
    correct_category: float = 0.0
    exact_rule: float = 0.0


class ConfidenceStats(BaseModel):
    """Confidence distribution for true positive detections."""
    mean: Optional[float] = None
    min: Optional[float] = None
    max: Optional[float] = None
    count: int = 0


class CorpusOverview(BaseModel):
    total_cves: int = 0
    downloaded: int = 0
    decompiled: int = 0
    evaluated: int = 0
    overall_precision: Optional[float] = None
    overall_recall: Optional[float] = None
    overall_f1: Optional[float] = None
    per_category: list[CategoryMetrics] = []
    detection_rates: DetectionRates = DetectionRates()
    confidence_stats: ConfidenceStats = ConfidenceStats()
    cves: list[CVECorpusEntry] = []
