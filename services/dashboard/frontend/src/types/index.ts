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
