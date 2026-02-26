"use client";

import { useEffect, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import type { Analysis, Finding, TriageEntry } from "@/types";
import { OverviewCards, TrustIndicators } from "@/components/overview-cards";
import { FindingsTable } from "@/components/findings-table";
import { FindingDetail } from "@/components/finding-detail";
import { formatDate, truncateSha, cn, triageBadge, triageLabel } from "@/lib/utils";

export default function AnalysisPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const id = params.id as string;
  const fnParam = searchParams.get("fn");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [triageStates, setTriageStates] = useState<Record<string, TriageEntry>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch(`/api/analyses/${id}`).then((res) => {
        if (!res.ok) throw new Error(`${res.status}`);
        return res.json();
      }),
      fetch(`/api/triage/${id}`).then((res) => {
        if (!res.ok) return {};
        return res.json();
      }),
    ])
      .then(([data, triage]: [Analysis, Record<string, TriageEntry>]) => {
        setAnalysis(data);
        setTriageStates(triage || {});
        // Deep-link to specific finding if ?fn= is present
        const target = fnParam
          ? data.findings.find((f: Finding) => f.function === fnParam)
          : null;
        setSelectedFinding(target || data.findings[0] || null);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, [id, fnParam]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-muted-foreground">
          Loading analysis...
        </div>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="rounded-lg border border-red-300 bg-red-50 p-6">
        <h2 className="font-medium text-red-800">Analysis not found</h2>
        <p className="mt-1 text-sm text-red-700">
          {error || "Could not load analysis data."}
        </p>
      </div>
    );
  }

  // Triage stats for this analysis
  const triageCount = Object.values(triageStates).filter(
    (t) => t.state !== "untriaged"
  ).length;
  const untriagedCount = analysis.findings.length - triageCount;

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-semibold">
              {analysis.driver_new.product || analysis.id}
            </h1>
            <div className="mt-1 flex items-center gap-3 text-sm text-muted-foreground">
              <span>{analysis.driver_new.arch}</span>
              <span>&middot;</span>
              <span>{formatDate(analysis.created_at)}</span>
            </div>
          </div>
          {/* Triage progress badge */}
          <div className="text-right">
            {untriagedCount > 0 ? (
              <span className="rounded-full bg-gray-100 px-3 py-1 text-xs font-medium text-gray-600">
                {untriagedCount} untriaged
              </span>
            ) : (
              <span className="rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-700">
                All triaged
              </span>
            )}
          </div>
        </div>

        {/* Version comparison */}
        <div className="mt-4 flex items-center gap-3 text-sm">
          <div className="rounded-lg border bg-muted/50 px-3 py-2">
            <span className="text-xs text-muted-foreground">Old: </span>
            <span className="font-mono">
              {analysis.driver_old?.version ||
                truncateSha(analysis.driver_old?.sha256 || "N/A")}
            </span>
          </div>
          <svg
            className="h-4 w-4 text-muted-foreground"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M13 7l5 5m0 0l-5 5m5-5H6"
            />
          </svg>
          <div className="rounded-lg border bg-muted/50 px-3 py-2">
            <span className="text-xs text-muted-foreground">New: </span>
            <span className="font-mono">
              {analysis.driver_new.version ||
                truncateSha(analysis.driver_new.sha256)}
            </span>
          </div>
        </div>

        {/* Trust indicators */}
        <div className="mt-4">
          <TrustIndicators analysis={analysis} />
        </div>
      </div>

      {/* Overview cards */}
      <OverviewCards analysis={analysis} />

      {/* Dispatch / IOCTLs */}
      {analysis.reachability &&
        analysis.reachability.ioctls.length > 0 && (
          <div>
            <h2 className="text-lg font-semibold">IOCTLs Identified</h2>
            <div className="mt-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
              {analysis.reachability.ioctls.map((ioctl) => (
                <div
                  key={ioctl.ioctl}
                  className="rounded-lg border bg-card p-3"
                >
                  <p className="font-mono text-sm font-semibold text-red-600">
                    {ioctl.ioctl}
                  </p>
                  <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                    {ioctl.handler}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Confidence: {(ioctl.confidence * 100).toFixed(0)}%
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

      {/* Findings */}
      <div>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">
            Ranked Findings ({analysis.findings.length})
          </h2>
          {/* Triage filter chips */}
          <div className="flex gap-1">
            {Object.entries(
              Object.values(triageStates).reduce(
                (acc, t) => {
                  acc[t.state] = (acc[t.state] || 0) + 1;
                  return acc;
                },
                {} as Record<string, number>
              )
            ).map(([state, count]) =>
              state !== "untriaged" ? (
                <span
                  key={state}
                  className={cn(
                    "rounded-full px-2 py-0.5 text-xs font-medium",
                    triageBadge(state)
                  )}
                >
                  {triageLabel(state)}: {count}
                </span>
              ) : null
            )}
          </div>
        </div>
        <div className="mt-4">
          <FindingsTable
            findings={analysis.findings}
            onSelect={setSelectedFinding}
            selectedFunction={selectedFinding?.function}
            triageStates={triageStates}
            analysisId={id}
            onTriageUpdate={() => {
              // Refresh triage states after bulk update
              fetch(`/api/triage/${id}`)
                .then((res) => (res.ok ? res.json() : {}))
                .then((data) => setTriageStates(data || {}));
            }}
          />
        </div>
      </div>

      {/* Finding detail */}
      {selectedFinding && (
        <div className="rounded-xl border bg-card p-6">
          <FindingDetail
            finding={selectedFinding}
            analysis={analysis}
            analysisId={id}
            triage={triageStates[selectedFinding.function] || null}
          />
        </div>
      )}

      {/* Notes */}
      {analysis.notes.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold">Notes</h2>
          <ul className="mt-2 space-y-1 text-sm text-muted-foreground">
            {analysis.notes.map((note, i) => (
              <li key={i}>&bull; {note}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
