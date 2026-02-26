export type Arch = "x64" | "x86" | "ARM64" | "Unknown";
export type PairingDecision = "accept" | "quarantine" | "reject";
export type NoiseRisk = "low" | "medium" | "high";
export type MatchingQuality = "high" | "medium" | "low";
export type RuleCategory =
  | "bounds_check"
  | "lifetime_fix"
  | "user_boundary_check"
  | "int_overflow"
  | "state_hardening";
export type ReachabilityClass =
  | "ioctl"
  | "irp"
  | "pnp"
  | "internal"
  | "unknown";

export interface DriverInfo {
  sha256: string;
  product?: string | null;
  version?: string | null;
  arch: Arch;
}

export interface PairingResult {
  decision: PairingDecision;
  confidence: number;
  noise_risk: NoiseRisk;
  rationale: string[];
  arch_mismatch: boolean;
}

export interface MatchingResult {
  method: string;
  confidence: number;
  matched_count: number;
  added_count: number;
  removed_count: number;
  changed_count: number;
  total_new: number;
  total_old: number;
  quality: MatchingQuality;
}

export interface ScoreBreakdown {
  semantic: number;
  reachability: number;
  sinks: number;
  penalties: number;
  gates: string[];
}

export interface Finding {
  function: string;
  rule_id: string;
  category: RuleCategory;
  confidence: number;
  sinks: string[];
  indicators: string[];
  diff_snippet: string;
  why_matters: string;
  surface_area: string[];
  final_score: number;
  score_breakdown?: ScoreBreakdown | null;
  reachability_class: ReachabilityClass;
  reachability_path: string[];
}

export interface DeltaSummary {
  total_deltas: number;
  by_category: Record<string, number>;
  by_rule: Record<string, number>;
  top_functions: string[];
  top_score: number;
  match_rate: number;
}

export interface IOCTLInfo {
  ioctl: string;
  handler: string;
  confidence: number;
  evidence: string[];
}

export interface DispatchInfo {
  driver_entry?: string | null;
  major_functions: Record<string, string | null>;
}

export interface ReachabilityTag {
  function: string;
  reachability_class: ReachabilityClass;
  confidence: number;
  paths: string[][];
  evidence: string[];
}

export interface ReachabilityResult {
  dispatch?: DispatchInfo | null;
  ioctls: IOCTLInfo[];
  tags: ReachabilityTag[];
}

export interface Analysis {
  id: string;
  created_at: string;
  driver_new: DriverInfo;
  driver_old?: DriverInfo | null;
  pairing?: PairingResult | null;
  matching?: MatchingResult | null;
  findings: Finding[];
  summary?: DeltaSummary | null;
  reachability?: ReachabilityResult | null;
  notes: string[];
}

export interface AnalysisListItem {
  id: string;
  created_at: string;
  driver_name?: string | null;
  arch: Arch;
  decision?: PairingDecision | null;
  noise_risk?: NoiseRisk | null;
  total_findings: number;
  top_score: number;
  reachable_findings: number;
}

export interface AnalysisListResponse {
  analyses: AnalysisListItem[];
  total: number;
}

// --- Corpus Validation ---

export type CorpusStatus = "pending" | "downloaded" | "decompiled" | "evaluated";

export interface DetectionDetail {
  function_pattern: string;
  matched_function?: string | null;
  expected_category: string;
  expected_rules: string[];
  min_confidence: number;
  actual_category?: string | null;
  actual_rule?: string | null;
  actual_confidence?: number | null;
  is_tp: boolean;
}

export interface UnexpectedHit {
  function: string;
  rule_id: string;
  category: string;
  confidence: number;
}

export interface CVECorpusEntry {
  cve_id: string;
  driver: string;
  description: string;
  expected_category_primary: string;
  vuln_build: string;
  fix_build: string;
  vuln_kb: string;
  fix_kb: string;
  expected_detections_count: number;
  detection_details: DetectionDetail[];
  unexpected_hits: UnexpectedHit[];
  status: CorpusStatus;
  tp: number;
  fn: number;
  fp: number;
  total_changed: number;
  total_hits: number;
  error?: string | null;
}

export interface CategoryMetrics {
  category: string;
  cve_count: number;
  tp: number;
  fn: number;
  fp: number;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
}

export interface DetectionRates {
  vuln_function_flagged: number;
  correct_category: number;
  exact_rule: number;
}

export interface ConfidenceStats {
  mean?: number | null;
  min?: number | null;
  max?: number | null;
  count: number;
}

export interface CorpusOverview {
  total_cves: number;
  downloaded: number;
  decompiled: number;
  evaluated: number;
  overall_precision?: number | null;
  overall_recall?: number | null;
  overall_f1?: number | null;
  per_category: CategoryMetrics[];
  detection_rates: DetectionRates;
  confidence_stats: ConfidenceStats;
  cves: CVECorpusEntry[];
}

export interface CorpusSource {
  cve_id: string;
  vuln_source?: string | null;
  fix_source?: string | null;
}

// --- Triage Workflow ---

export type TriageState =
  | "untriaged"
  | "investigating"
  | "confirmed"
  | "false_positive"
  | "resolved";

export type ExploitStage =
  | "not_started"
  | "recon"
  | "poc"
  | "tested"
  | "working";

export interface TriageEntry {
  analysis_id: string;
  function: string;
  state: TriageState;
  exploit_stage: ExploitStage;
  updated_at: string;
  note: string;
}

export interface VariantMatch {
  analysis_id: string;
  driver_name: string;
  function: string;
  rule_id: string;
  category: string;
  final_score: number;
  confidence: number;
  reachability_class: string;
  created_at: string;
}

export interface TriageSummary {
  untriaged: number;
  investigating: number;
  confirmed: number;
  false_positive: number;
  resolved: number;
  total: number;
}

// --- Activity Feed ---

export type ActivityType =
  | "new_analysis"
  | "high_score_finding"
  | "triage_update";

export interface ActivityItem {
  type: ActivityType;
  timestamp: string;
  title: string;
  detail: string;
  link: string;
  score?: number | null;
}

// --- Driver Grouping ---

export interface DriverSummary {
  driver_name: string;
  analysis_count: number;
  latest_analysis?: string | null;
  latest_date?: string | null;
  highest_score: number;
  total_findings: number;
  reachable_findings: number;
  arch: Arch;
}

// --- Alert History ---

export interface AlertEntry {
  score: number;
  function: string;
  rule_id: string;
  category: string;
  surface_area: string;
  driver_new: string;
  why_matters: string;
  timestamp: number;
}

export interface VariantAlertEntry {
  source_driver: string;
  source_function: string;
  bug_class: string;
  variant_driver: string;
  variant_function: string;
  similarity: number;
  confidence: number;
  reasoning: string;
  timestamp: number;
}

export interface AlertsResponse {
  alerts: AlertEntry[];
  variants: VariantAlertEntry[];
}

// --- Search ---

export interface SearchResult {
  type: string;
  id: string;
  title: string;
  detail: string;
  score?: number | null;
  link: string;
}

export interface SearchResponse {
  query: string;
  results: SearchResult[];
  total: number;
}

// --- Pipeline Health ---

export interface PipelineStage {
  name: string;
  identity: string;
  status: string;
  last_seen?: string | null;
}

export interface PipelineHealth {
  stages: PipelineStage[];
  active_consumers: number;
  redis_connected: boolean;
}

// --- Stats / Trends ---

export interface TrendPoint {
  date: string;
  analyses: number;
  findings: number;
  reachable: number;
  avg_score: number;
}

export interface ScoreBucket {
  bucket: string;
  count: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface StatsResponse {
  trends: TrendPoint[];
  score_distribution: ScoreBucket[];
  by_category: CategoryCount[];
  total_analyses: number;
  total_findings: number;
  total_reachable: number;
}
