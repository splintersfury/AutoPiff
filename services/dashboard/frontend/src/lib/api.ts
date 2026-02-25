import type {
  ActivityItem,
  Analysis,
  AnalysisListResponse,
  CorpusOverview,
  CorpusSource,
  CVECorpusEntry,
  Finding,
  TriageEntry,
  TriageSummary,
  TriageState,
} from "@/types";

// Server-side (SSR) fetch needs a full URL; client-side uses relative paths
// which the Next.js rewrite proxies to the backend.
const API_BASE =
  typeof window === "undefined"
    ? process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
    : "";

async function fetchJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

async function postJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
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

export async function getCorpus(): Promise<CorpusOverview> {
  return fetchJson("/api/corpus");
}

export async function getCorpusCVE(cveId: string): Promise<CVECorpusEntry> {
  return fetchJson(`/api/corpus/${cveId}`);
}

export async function triggerCorpusDownload(): Promise<{ status: string }> {
  return postJson("/api/corpus/download");
}

export async function triggerCorpusEvaluate(): Promise<{ status: string }> {
  return postJson("/api/corpus/evaluate");
}

export async function getCorpusSource(cveId: string): Promise<CorpusSource> {
  return fetchJson(`/api/corpus/${cveId}/source`);
}

// --- Activity Feed ---

export async function getActivity(limit = 30): Promise<ActivityItem[]> {
  return fetchJson(`/api/activity?limit=${limit}`);
}

// --- Triage ---

export async function getTriageSummary(): Promise<TriageSummary> {
  return fetchJson("/api/triage/summary");
}

export async function getTriageStates(
  analysisId: string
): Promise<Record<string, TriageEntry>> {
  return fetchJson(`/api/triage/${analysisId}`);
}

export async function setTriageState(
  analysisId: string,
  func: string,
  state: TriageState,
  note = ""
): Promise<TriageEntry> {
  const res = await fetch(
    `${API_BASE}/api/triage/${analysisId}/${encodeURIComponent(func)}`,
    {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ state, note }),
    }
  );
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}
