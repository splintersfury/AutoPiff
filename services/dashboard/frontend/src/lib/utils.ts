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
