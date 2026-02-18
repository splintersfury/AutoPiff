import type { Analysis, AnalysisListResponse, Finding } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export async function getAnalyses(): Promise<AnalysisListResponse> {
  return fetchJson("/api/analyses");
}

export async function getAnalysis(id: string): Promise<Analysis> {
  return fetchJson(`/api/analyses/${id}`);
}

export async function getFindings(
  id: string,
  category?: string,
  minScore?: number
): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (category) params.set("category", category);
  if (minScore) params.set("min_score", String(minScore));
  const qs = params.toString();
  return fetchJson(`/api/analyses/${id}/findings${qs ? `?${qs}` : ""}`);
}
