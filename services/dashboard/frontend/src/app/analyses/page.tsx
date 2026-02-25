"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getAnalyses } from "@/lib/api";
import { cn, scoreColor, formatDate } from "@/lib/utils";
import type { AnalysisListItem } from "@/types";

const SCORE_RANGES = [
  { label: "All", min: 0 },
  { label: "10+", min: 10 },
  { label: "8+", min: 8 },
  { label: "6+", min: 6 },
  { label: "4+", min: 4 },
];

const DECISIONS = ["accept", "quarantine", "reject"];
const NOISE_RISKS = ["low", "medium", "high"];
const ARCHES = ["x64", "x86", "ARM64"];

export default function AnalysesPage() {
  const [analyses, setAnalyses] = useState<AnalysisListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [minScore, setMinScore] = useState(0);
  const [decision, setDecision] = useState("");
  const [noiseRisk, setNoiseRisk] = useState("");
  const [arch, setArch] = useState("");

  useEffect(() => {
    setLoading(true);
    getAnalyses({
      min_score: minScore || undefined,
      decision: decision || undefined,
      noise_risk: noiseRisk || undefined,
      arch: arch || undefined,
    })
      .then((data) => {
        setAnalyses(data.analyses);
        setTotal(data.total);
        setLoading(false);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, [minScore, decision, noiseRisk, arch]);

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Analyses</h1>
        <p className="mt-4 text-muted-foreground">
          Could not load analyses. Is the backend running?
        </p>
      </div>
    );
  }

  const hasFilters = minScore > 0 || decision || noiseRisk || arch;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Analyses</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {total} analysis result{total !== 1 ? "s" : ""}
            {hasFilters && " (filtered)"}
          </p>
        </div>
        {hasFilters && (
          <button
            onClick={() => { setMinScore(0); setDecision(""); setNoiseRisk(""); setArch(""); }}
            className="text-xs text-blue-600 hover:underline dark:text-blue-400"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-card p-3">
        <span className="text-xs font-medium text-muted-foreground">Filters:</span>

        {/* Score range */}
        <div className="flex gap-1">
          {SCORE_RANGES.map((r) => (
            <button
              key={r.label}
              onClick={() => setMinScore(r.min)}
              className={cn(
                "rounded-md px-2.5 py-1 text-xs transition-colors",
                minScore === r.min
                  ? "bg-foreground text-background"
                  : "bg-muted text-muted-foreground hover:bg-accent"
              )}
            >
              {r.label}
            </button>
          ))}
        </div>

        <span className="text-border">|</span>

        {/* Decision */}
        <select
          value={decision}
          onChange={(e) => setDecision(e.target.value)}
          className="rounded-md border bg-background px-2 py-1 text-xs"
        >
          <option value="">Any decision</option>
          {DECISIONS.map((d) => (
            <option key={d} value={d}>{d}</option>
          ))}
        </select>

        {/* Noise risk */}
        <select
          value={noiseRisk}
          onChange={(e) => setNoiseRisk(e.target.value)}
          className="rounded-md border bg-background px-2 py-1 text-xs"
        >
          <option value="">Any noise</option>
          {NOISE_RISKS.map((n) => (
            <option key={n} value={n}>{n}</option>
          ))}
        </select>

        {/* Arch */}
        <select
          value={arch}
          onChange={(e) => setArch(e.target.value)}
          className="rounded-md border bg-background px-2 py-1 text-xs"
        >
          <option value="">Any arch</option>
          {ARCHES.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
      </div>

      {loading ? (
        <div className="py-8 text-center">
          <div className="animate-pulse text-muted-foreground">Loading...</div>
        </div>
      ) : analyses.length === 0 ? (
        <div className="rounded-lg border bg-muted/50 p-8 text-center">
          <p className="text-muted-foreground">
            {hasFilters ? "No analyses match the current filters." : "No analyses found."}
          </p>
        </div>
      ) : (
        <div className="grid gap-4">
          {analyses.map((a) => (
            <Link
              key={a.id}
              href={`/analysis/${a.id}`}
              className="group rounded-xl border bg-card p-5 transition-colors hover:border-foreground/20"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-medium group-hover:text-blue-600 dark:group-hover:text-blue-400">
                    {a.driver_name || a.id}
                  </h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    {a.arch} &middot; {formatDate(a.created_at)}
                  </p>
                </div>
                <div className="text-right">
                  <p
                    className={cn(
                      "text-xl font-bold font-mono",
                      scoreColor(a.top_score)
                    )}
                  >
                    {a.top_score.toFixed(2)}
                  </p>
                  <p className="text-xs text-muted-foreground">top score</p>
                </div>
              </div>
              <div className="mt-3 flex items-center gap-4 text-sm">
                <span>
                  <strong>{a.total_findings}</strong>{" "}
                  <span className="text-muted-foreground">findings</span>
                </span>
                {a.reachable_findings > 0 && (
                  <span className="text-orange-600 dark:text-orange-400">
                    <strong>{a.reachable_findings}</strong> reachable
                  </span>
                )}
                <span
                  className={cn(
                    "rounded-full px-2 py-0.5 text-xs font-medium",
                    a.decision === "accept"
                      ? "bg-green-100 text-green-700"
                      : a.decision === "quarantine"
                        ? "bg-yellow-100 text-yellow-700"
                        : "bg-gray-100 text-gray-600"
                  )}
                >
                  {a.decision || "N/A"}
                </span>
                {a.noise_risk && (
                  <span
                    className={cn(
                      "rounded-full px-2 py-0.5 text-xs font-medium",
                      a.noise_risk === "low"
                        ? "bg-green-100 text-green-700"
                        : a.noise_risk === "medium"
                          ? "bg-yellow-100 text-yellow-700"
                          : "bg-red-100 text-red-700"
                    )}
                  >
                    noise: {a.noise_risk}
                  </span>
                )}
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
