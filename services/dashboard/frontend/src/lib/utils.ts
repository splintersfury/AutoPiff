import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function scoreColor(score: number): string {
  if (score >= 10) return "text-score-critical";
  if (score >= 7) return "text-score-high";
  if (score >= 4) return "text-score-medium";
  return "text-score-low";
}

export function scoreBg(score: number): string {
  if (score >= 10) return "bg-red-500/10 border-red-500/30";
  if (score >= 7) return "bg-orange-500/10 border-orange-500/30";
  if (score >= 4) return "bg-yellow-500/10 border-yellow-500/30";
  return "bg-green-500/10 border-green-500/30";
}

export function confidenceBadge(confidence: number): string {
  if (confidence >= 0.9) return "bg-green-100 text-green-800";
  if (confidence >= 0.75) return "bg-yellow-100 text-yellow-800";
  return "bg-red-100 text-red-800";
}

export function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    bounds_check: "Bounds Check",
    lifetime_fix: "Lifetime Fix",
    user_boundary_check: "User Boundary",
    int_overflow: "Integer Overflow",
    state_hardening: "State Hardening",
    authorization: "Authorization",
    race_condition: "Race Condition",
    info_disclosure: "Info Disclosure",
    ioctl_hardening: "IOCTL Hardening",
    mdl_handling: "MDL Handling",
    object_management: "Object Mgmt",
    string_handling: "String Handling",
    pool_hardening: "Pool Hardening",
    crypto_hardening: "Crypto Hardening",
    error_path_hardening: "Error Path",
    dos_hardening: "DoS Hardening",
    ndis_hardening: "NDIS Hardening",
    filesystem_filter: "FS Filter",
    pnp_power: "PnP/Power",
    dma_mmio: "DMA/MMIO",
    wdf_hardening: "WDF Hardening",
    new_attack_surface: "New Surface",
  };
  return labels[category] || category;
}

export function reachabilityLabel(cls: string): string {
  const labels: Record<string, string> = {
    ioctl: "IOCTL",
    irp: "IRP",
    pnp: "PnP",
    internal: "Internal",
    unknown: "Unknown",
  };
  return labels[cls] || cls;
}

export function reachabilityBadge(cls: string): string {
  const colors: Record<string, string> = {
    ioctl: "bg-red-100 text-red-800",
    irp: "bg-orange-100 text-orange-800",
    pnp: "bg-yellow-100 text-yellow-800",
    internal: "bg-gray-100 text-gray-700",
    unknown: "bg-gray-100 text-gray-500",
  };
  return colors[cls] || "bg-gray-100 text-gray-500";
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function truncateSha(sha: string, len = 12): string {
  return sha.slice(0, len);
}

export function triageLabel(state: string): string {
  const labels: Record<string, string> = {
    untriaged: "Untriaged",
    investigating: "Investigating",
    confirmed: "Confirmed",
    false_positive: "False Positive",
    resolved: "Resolved",
  };
  return labels[state] || state;
}

export function triageBadge(state: string): string {
  const colors: Record<string, string> = {
    untriaged: "bg-gray-100 text-gray-600",
    investigating: "bg-blue-100 text-blue-700",
    confirmed: "bg-red-100 text-red-700",
    false_positive: "bg-yellow-100 text-yellow-700",
    resolved: "bg-green-100 text-green-700",
  };
  return colors[state] || "bg-gray-100 text-gray-500";
}

export function activityIcon(type: string): string {
  const icons: Record<string, string> = {
    new_analysis: "M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2",
    high_score_finding: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z",
    triage_update: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z",
  };
  return icons[type] || "";
}

export function activityColor(type: string): string {
  const colors: Record<string, string> = {
    new_analysis: "text-blue-500",
    high_score_finding: "text-red-500",
    triage_update: "text-green-500",
  };
  return colors[type] || "text-gray-500";
}

export function timeAgo(iso: string): string {
  const now = Date.now();
  const then = new Date(iso).getTime();
  const diff = now - then;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(iso);
}
