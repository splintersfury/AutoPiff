"use client";

import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import {
  getCorpus,
  getCorpusSource,
  triggerCorpusDownload,
  triggerCorpusEvaluate,
} from "@/lib/api";
import { cn, categoryLabel } from "@/lib/utils";
import type {
  CategoryMetrics,
  ConfidenceStats,
  CorpusOverview,
  CorpusSource,
  CorpusStatus,
  CVECorpusEntry,
  DetectionRates,
} from "@/types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusColor(status: CorpusStatus): string {
  switch (status) {
    case "pending":
      return "bg-gray-100 text-gray-600";
    case "downloaded":
      return "bg-blue-100 text-blue-700";
    case "decompiled":
      return "bg-yellow-100 text-yellow-700";
    case "evaluated":
      return "bg-green-100 text-green-700";
  }
}

type ResultLabel = "PASS" | "PARTIAL" | "FAIL" | "ERROR" | "--";

function resultBadge(entry: CVECorpusEntry): {
  label: ResultLabel;
  color: string;
} {
  if (entry.status !== "evaluated") {
    return { label: "--", color: "text-muted-foreground" };
  }
  if (entry.error) {
    return { label: "ERROR", color: "text-red-600" };
  }
  if (entry.tp > 0 && entry.fn === 0) {
    return { label: "PASS", color: "text-green-600" };
  }
  if (entry.tp > 0) {
    return { label: "PARTIAL", color: "text-yellow-600" };
  }
  return { label: "FAIL", color: "text-red-600" };
}

function pct(value: number | null | undefined): string {
  return value != null ? `${(value * 100).toFixed(1)}%` : "N/A";
}

// ---------------------------------------------------------------------------
// Small reusable components
// ---------------------------------------------------------------------------

function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={cn("animate-spin h-4 w-4", className)}
      viewBox="0 0 24 24"
      fill="none"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
      />
    </svg>
  );
}

function MetricBar({
  value,
  label,
}: {
  value: number | null | undefined;
  label: string;
}) {
  const p = value != null ? Math.round(value * 100) : 0;
  const color =
    p >= 80 ? "bg-green-500" : p >= 50 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono font-semibold">{pct(value)}</span>
      </div>
      <div className="mt-1 h-2 w-full rounded-full bg-muted">
        <div
          className={cn("h-2 rounded-full transition-all", color)}
          style={{ width: `${p}%` }}
        />
      </div>
    </div>
  );
}

function SmallMetricBar({
  value,
  label,
}: {
  value: number | null | undefined;
  label: string;
}) {
  const p = value != null ? Math.round(value * 100) : 0;
  const color =
    p >= 80 ? "bg-green-500" : p >= 50 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-6 text-muted-foreground">{label}</span>
      <div className="h-1.5 flex-1 rounded-full bg-muted">
        <div
          className={cn("h-1.5 rounded-full", color)}
          style={{ width: `${p}%` }}
        />
      </div>
      <span className="w-10 text-right font-mono">
        {value != null ? `${(value * 100).toFixed(0)}%` : "--"}
      </span>
    </div>
  );
}

function RateCard({
  value,
  label,
  description,
}: {
  value: number;
  label: string;
  description: string;
}) {
  const p = Math.round(value * 100);
  return (
    <div className="rounded-xl border bg-card p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p
        className={cn(
          "mt-1 text-2xl font-semibold font-mono",
          p >= 80
            ? "text-green-600"
            : p >= 50
              ? "text-yellow-600"
              : "text-red-600"
        )}
      >
        {p}%
      </p>
      <p className="mt-1 text-[11px] text-muted-foreground">{description}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter controls
// ---------------------------------------------------------------------------

type StatusFilter = CorpusStatus | "all";
type ResultFilter = ResultLabel | "all";

function FilterBar({
  statusFilter,
  setStatusFilter,
  resultFilter,
  setResultFilter,
  categoryFilter,
  setCategoryFilter,
  categories,
  searchQuery,
  setSearchQuery,
}: {
  statusFilter: StatusFilter;
  setStatusFilter: (v: StatusFilter) => void;
  resultFilter: ResultFilter;
  setResultFilter: (v: ResultFilter) => void;
  categoryFilter: string;
  setCategoryFilter: (v: string) => void;
  categories: string[];
  searchQuery: string;
  setSearchQuery: (v: string) => void;
}) {
  const statusOptions: { value: StatusFilter; label: string }[] = [
    { value: "all", label: "All statuses" },
    { value: "pending", label: "Pending" },
    { value: "downloaded", label: "Downloaded" },
    { value: "decompiled", label: "Decompiled" },
    { value: "evaluated", label: "Evaluated" },
  ];
  const resultOptions: { value: ResultFilter; label: string }[] = [
    { value: "all", label: "All results" },
    { value: "PASS", label: "Pass" },
    { value: "PARTIAL", label: "Partial" },
    { value: "FAIL", label: "Fail" },
    { value: "ERROR", label: "Error" },
  ];

  return (
    <div className="flex flex-wrap gap-3">
      <input
        type="text"
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="Search CVE, driver..."
        className="rounded-lg border bg-card px-3 py-1.5 text-sm w-48 focus:outline-none focus:ring-2 focus:ring-blue-500/40"
      />
      <select
        value={statusFilter}
        onChange={(e) => setStatusFilter(e.target.value as StatusFilter)}
        className="rounded-lg border bg-card px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
      >
        {statusOptions.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select
        value={resultFilter}
        onChange={(e) => setResultFilter(e.target.value as ResultFilter)}
        className="rounded-lg border bg-card px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
      >
        {resultOptions.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <select
        value={categoryFilter}
        onChange={(e) => setCategoryFilter(e.target.value)}
        className="rounded-lg border bg-card px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/40"
      >
        <option value="all">All categories</option>
        {categories.map((c) => (
          <option key={c} value={c}>
            {categoryLabel(c)}
          </option>
        ))}
      </select>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Source Diff Viewer (lazy-loaded per CVE)
// ---------------------------------------------------------------------------

function SourceDiffViewer({ cveId }: { cveId: string }) {
  const [source, setSource] = useState<CorpusSource | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"vuln" | "fix">("vuln");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    getCorpusSource(cveId)
      .then((s) => {
        if (!cancelled) setSource(s);
      })
      .catch((e) => {
        if (!cancelled)
          setError(e instanceof Error ? e.message : "Failed to load source");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [cveId]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
        <Spinner /> Loading decompiled source...
      </div>
    );
  }
  if (error) {
    return (
      <p className="text-sm text-muted-foreground py-2">
        No decompiled source available
      </p>
    );
  }
  if (!source || (!source.vuln_source && !source.fix_source)) {
    return (
      <p className="text-sm text-muted-foreground py-2">
        Source files not yet decompiled
      </p>
    );
  }

  const currentSource =
    activeTab === "vuln" ? source.vuln_source : source.fix_source;
  const lineCount = currentSource ? currentSource.split("\n").length : 0;

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <button
          onClick={() => setActiveTab("vuln")}
          className={cn(
            "rounded px-3 py-1 text-xs font-medium transition-colors",
            activeTab === "vuln"
              ? "bg-orange-100 text-orange-700"
              : "bg-muted text-muted-foreground hover:bg-muted/80"
          )}
        >
          vuln.c
        </button>
        <button
          onClick={() => setActiveTab("fix")}
          className={cn(
            "rounded px-3 py-1 text-xs font-medium transition-colors",
            activeTab === "fix"
              ? "bg-green-100 text-green-700"
              : "bg-muted text-muted-foreground hover:bg-muted/80"
          )}
        >
          fix.c
        </button>
        <span className="text-[11px] text-muted-foreground ml-auto">
          {lineCount.toLocaleString()} lines
        </span>
      </div>
      {currentSource ? (
        <div className="overflow-auto rounded border bg-[#1e1e2e] max-h-[400px]">
          <pre className="text-xs leading-relaxed p-3 text-gray-300">
            <code>{currentSource}</code>
          </pre>
        </div>
      ) : (
        <p className="text-sm text-muted-foreground py-2">
          {activeTab === "vuln" ? "vuln.c" : "fix.c"} not available
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CVE Detail Panel (expanded below a CVE row)
// ---------------------------------------------------------------------------

function CVEDetailPanel({ cve }: { cve: CVECorpusEntry }) {
  const hasEvalResults = cve.status === "evaluated";
  const [showSource, setShowSource] = useState(false);

  return (
    <div className="bg-muted/30 px-6 py-4 space-y-5 border-t border-dashed">
      {/* Version info + stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Version Info
          </h4>
          <div className="space-y-1 text-sm">
            <div>
              <span className="text-muted-foreground">Vulnerable: </span>
              <span className="font-mono">{cve.vuln_build}</span>
              {cve.vuln_kb && (
                <span className="ml-1.5 text-xs rounded bg-orange-100 text-orange-700 px-1.5 py-0.5">
                  {cve.vuln_kb}
                </span>
              )}
            </div>
            <div>
              <span className="text-muted-foreground">Fix: </span>
              <span className="font-mono">{cve.fix_build}</span>
              {cve.fix_kb && (
                <span className="ml-1.5 text-xs rounded bg-green-100 text-green-700 px-1.5 py-0.5">
                  {cve.fix_kb}
                </span>
              )}
            </div>
          </div>
        </div>
        {hasEvalResults && (
          <div>
            <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
              Analysis Stats
            </h4>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted-foreground">Functions changed: </span>
                <span className="font-mono font-semibold">
                  {cve.total_changed}
                </span>
              </div>
              <div>
                <span className="text-muted-foreground">Rule hits: </span>
                <span className="font-mono font-semibold">
                  {cve.total_hits}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Expected detections table */}
      {cve.detection_details.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            Expected Detections
          </h4>
          <div className="overflow-x-auto rounded border bg-card">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Function Pattern
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Expected Category
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Expected Rules
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Min Confidence
                  </th>
                  {hasEvalResults && (
                    <>
                      <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                        Matched Function
                      </th>
                      <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                        Actual
                      </th>
                      <th className="px-3 py-2 text-center font-medium text-muted-foreground">
                        Result
                      </th>
                    </>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y">
                {cve.detection_details.map((d, i) => (
                  <tr key={i}>
                    <td className="px-3 py-2 font-mono max-w-[200px] truncate">
                      {d.function_pattern}
                    </td>
                    <td className="px-3 py-2">
                      <span className="rounded-full bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-700">
                        {categoryLabel(d.expected_category)}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {d.expected_rules.map((r) => (
                          <span
                            key={r}
                            className={cn(
                              "rounded px-1.5 py-0.5 text-xs",
                              hasEvalResults &&
                                d.actual_rule === r
                                ? "bg-green-100 text-green-700 font-medium"
                                : "bg-gray-100 text-gray-600"
                            )}
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono">
                      {(d.min_confidence * 100).toFixed(0)}%
                    </td>
                    {hasEvalResults && (
                      <>
                        <td className="px-3 py-2 font-mono max-w-[160px] truncate">
                          {d.matched_function || (
                            <span className="text-red-400 italic">
                              no match
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          {d.actual_rule ? (
                            <span className="text-xs">
                              {d.actual_rule}{" "}
                              <span className="font-mono text-muted-foreground">
                                (
                                {((d.actual_confidence ?? 0) * 100).toFixed(0)}
                                %)
                              </span>
                            </span>
                          ) : (
                            <span className="text-red-400 italic text-xs">
                              not detected
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-center">
                          <span
                            className={cn(
                              "rounded-full px-2 py-0.5 text-xs font-semibold",
                              d.is_tp
                                ? "bg-green-100 text-green-700"
                                : "bg-red-100 text-red-700"
                            )}
                          >
                            {d.is_tp ? "TP" : "FN"}
                          </span>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Unexpected hits (actual false positives) */}
      {hasEvalResults && cve.unexpected_hits.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
            False Positives ({cve.unexpected_hits.length} unexpected hit
            {cve.unexpected_hits.length !== 1 ? "s" : ""})
          </h4>
          <div className="overflow-x-auto rounded border bg-card">
            <table className="w-full text-xs">
              <thead className="bg-muted/50 border-b">
                <tr>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Function
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Rule
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Category
                  </th>
                  <th className="px-3 py-2 text-left font-medium text-muted-foreground">
                    Confidence
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {cve.unexpected_hits.map((h, i) => (
                  <tr key={i}>
                    <td className="px-3 py-2 font-mono">{h.function}</td>
                    <td className="px-3 py-2">{h.rule_id}</td>
                    <td className="px-3 py-2">
                      <span className="rounded-full bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-700">
                        {categoryLabel(h.category)}
                      </span>
                    </td>
                    <td className="px-3 py-2 font-mono">
                      {(h.confidence * 100).toFixed(0)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Source viewer toggle */}
      {cve.status !== "pending" && (
        <div>
          <button
            onClick={() => setShowSource(!showSource)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-600 hover:text-blue-700"
          >
            <svg
              className={cn(
                "h-3.5 w-3.5 transition-transform",
                showSource && "rotate-90"
              )}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 5l7 7-7 7"
              />
            </svg>
            {showSource ? "Hide" : "View"} Decompiled Source
          </button>
          {showSource && (
            <div className="mt-3">
              <SourceDiffViewer cveId={cve.cve_id} />
            </div>
          )}
        </div>
      )}

      {/* Error display */}
      {cve.error && (
        <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-700">
          <span className="font-semibold">Error:</span> {cve.error}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-Category Metrics Section
// ---------------------------------------------------------------------------

function CategoryBreakdown({ categories }: { categories: CategoryMetrics[] }) {
  if (categories.length === 0) return null;
  return (
    <div>
      <h2 className="text-lg font-semibold">Per-Category Metrics</h2>
      <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {categories.map((cat) => (
          <div key={cat.category} className="rounded-xl border bg-card p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="rounded-full bg-purple-100 px-2.5 py-0.5 text-xs font-medium text-purple-700">
                {categoryLabel(cat.category)}
              </span>
              <span className="text-xs text-muted-foreground">
                {cat.cve_count} CVE{cat.cve_count !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-1.5">
              <SmallMetricBar value={cat.precision} label="P" />
              <SmallMetricBar value={cat.recall} label="R" />
              <SmallMetricBar value={cat.f1} label="F1" />
            </div>
            <div className="mt-2 flex gap-3 text-xs text-muted-foreground">
              <span>
                TP:{" "}
                <span className="font-mono text-foreground">{cat.tp}</span>
              </span>
              <span>
                FN:{" "}
                <span className="font-mono text-foreground">{cat.fn}</span>
              </span>
              <span>
                FP:{" "}
                <span className="font-mono text-foreground">{cat.fp}</span>
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detection Rates + Confidence Stats
// ---------------------------------------------------------------------------

function DetectionInsights({
  rates,
  confidence,
}: {
  rates: DetectionRates;
  confidence: ConfidenceStats;
}) {
  return (
    <div>
      <h2 className="text-lg font-semibold">Detection Insights</h2>
      <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <RateCard
          value={rates.vuln_function_flagged}
          label="Function Flagged"
          description="CVEs where the vulnerable function received any hit"
        />
        <RateCard
          value={rates.correct_category}
          label="Category Match"
          description="CVEs where the correct vulnerability category was detected"
        />
        <RateCard
          value={rates.exact_rule}
          label="Exact Rule Match"
          description="CVEs where the exact expected rule fired"
        />
        {/* Confidence stats card */}
        <div className="rounded-xl border bg-card p-4">
          <p className="text-xs text-muted-foreground">TP Confidence</p>
          {confidence.count > 0 ? (
            <>
              <p className="mt-1 text-2xl font-semibold font-mono">
                {((confidence.mean ?? 0) * 100).toFixed(0)}%
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">
                mean across {confidence.count} true positive
                {confidence.count !== 1 ? "s" : ""}
              </p>
              <div className="mt-2 flex gap-3 text-xs text-muted-foreground">
                <span>
                  Min:{" "}
                  <span className="font-mono text-foreground">
                    {((confidence.min ?? 0) * 100).toFixed(0)}%
                  </span>
                </span>
                <span>
                  Max:{" "}
                  <span className="font-mono text-foreground">
                    {((confidence.max ?? 0) * 100).toFixed(0)}%
                  </span>
                </span>
              </div>
            </>
          ) : (
            <>
              <p className="mt-1 text-2xl font-semibold text-muted-foreground">
                N/A
              </p>
              <p className="mt-1 text-[11px] text-muted-foreground">
                No true positives yet
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

export default function CorpusPage() {
  const [data, setData] = useState<CorpusOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const fetchData = useCallback(async () => {
    try {
      const result = await getCorpus();
      setData(result);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load corpus data");
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Poll while action in progress
  useEffect(() => {
    if (actionInProgress) {
      pollRef.current = setInterval(fetchData, 10_000);
    } else if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [actionInProgress, fetchData]);

  const handleDownload = async () => {
    try {
      setActionInProgress("download");
      await triggerCorpusDownload();
      setTimeout(() => {
        fetchData();
        setActionInProgress(null);
      }, 3000);
    } catch {
      setActionInProgress(null);
    }
  };

  const handleEvaluate = async () => {
    try {
      setActionInProgress("evaluate");
      await triggerCorpusEvaluate();
      setTimeout(() => {
        fetchData();
        setActionInProgress(null);
      }, 5000);
    } catch {
      setActionInProgress(null);
    }
  };

  const handleExport = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `corpus-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (error && !data) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">CVE Validation Corpus</h1>
        <div className="mt-8 rounded-lg border border-yellow-300 bg-yellow-50 p-6">
          <h2 className="font-medium text-yellow-800">Backend not available</h2>
          <p className="mt-1 text-sm text-yellow-700">
            Could not connect to the API. Make sure the backend is running on
            port 8000.
          </p>
        </div>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center py-20">
        <Spinner className="h-6 w-6 text-muted-foreground" />
      </div>
    );
  }

  const hasEvaluated = data.evaluated > 0;

  // Unique categories from CVEs
  const allCategories = [
    ...new Set(data.cves.map((c) => c.expected_category_primary).filter(Boolean)),
  ].sort();

  // Apply filters
  const filteredCves = data.cves.filter((cve) => {
    if (statusFilter !== "all" && cve.status !== statusFilter) return false;
    if (resultFilter !== "all" && resultBadge(cve).label !== resultFilter)
      return false;
    if (
      categoryFilter !== "all" &&
      cve.expected_category_primary !== categoryFilter
    )
      return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (
        !cve.cve_id.toLowerCase().includes(q) &&
        !cve.driver.toLowerCase().includes(q) &&
        !cve.description.toLowerCase().includes(q)
      )
        return false;
    }
    return true;
  });

  return (
    <div className="space-y-8">
      {/* Header with actions */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold">CVE Validation Corpus</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Ground truth for rule engine precision &amp; recall measurement
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleExport}
            className="inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-muted transition-colors"
          >
            <svg
              className="h-4 w-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={1.5}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"
              />
            </svg>
            Export JSON
          </button>
          <button
            onClick={handleDownload}
            disabled={actionInProgress !== null}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors",
              actionInProgress === "download"
                ? "bg-blue-100 text-blue-700 cursor-wait"
                : "bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
            )}
          >
            {actionInProgress === "download" && <Spinner />}
            Download All
          </button>
          <button
            onClick={handleEvaluate}
            disabled={actionInProgress !== null}
            className={cn(
              "inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors",
              actionInProgress === "evaluate"
                ? "bg-green-100 text-green-700 cursor-wait"
                : "bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
            )}
          >
            {actionInProgress === "evaluate" && <Spinner />}
            Run Evaluation
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total CVEs</p>
          <p className="mt-1 text-2xl font-semibold">{data.total_cves}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Downloaded</p>
          <p className="mt-1 text-2xl font-semibold text-blue-600">
            {data.downloaded}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Decompiled</p>
          <p className="mt-1 text-2xl font-semibold text-yellow-600">
            {data.decompiled}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Evaluated</p>
          <p className="mt-1 text-2xl font-semibold text-green-600">
            {data.evaluated}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Overall Recall</p>
          <p className="mt-1 text-2xl font-semibold">
            {pct(data.overall_recall)}
          </p>
        </div>
      </div>

      {/* Overall P/R/F1 */}
      {hasEvaluated && (
        <div className="rounded-xl border bg-card p-6">
          <h2 className="text-lg font-semibold">Overall Metrics</h2>
          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            <MetricBar value={data.overall_precision} label="Precision" />
            <MetricBar value={data.overall_recall} label="Recall" />
            <MetricBar value={data.overall_f1} label="F1 Score" />
          </div>
        </div>
      )}

      {/* Detection insights (rates + confidence) */}
      {hasEvaluated && (
        <DetectionInsights
          rates={data.detection_rates}
          confidence={data.confidence_stats}
        />
      )}

      {/* Per-category breakdown */}
      {data.per_category.length > 0 && (
        <CategoryBreakdown categories={data.per_category} />
      )}

      {/* CVE table */}
      <div>
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-lg font-semibold">
            CVE Entries
            {filteredCves.length !== data.cves.length && (
              <span className="ml-2 text-sm font-normal text-muted-foreground">
                ({filteredCves.length} of {data.cves.length})
              </span>
            )}
          </h2>
        </div>

        <div className="mt-3">
          <FilterBar
            statusFilter={statusFilter}
            setStatusFilter={setStatusFilter}
            resultFilter={resultFilter}
            setResultFilter={setResultFilter}
            categoryFilter={categoryFilter}
            setCategoryFilter={setCategoryFilter}
            categories={allCategories}
            searchQuery={searchQuery}
            setSearchQuery={setSearchQuery}
          />
        </div>

        {filteredCves.length === 0 ? (
          <div className="mt-4 rounded-lg border bg-muted/50 p-8 text-center">
            <p className="text-muted-foreground">
              {data.cves.length === 0
                ? "No CVEs in corpus."
                : "No CVEs match filters."}
            </p>
          </div>
        ) : (
          <div className="mt-4 overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm">
              <thead className="border-b bg-muted/50">
                <tr>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    CVE ID
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Driver
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Version
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Category
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Status
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground text-center">
                    Funcs / Hits
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground text-center">
                    TP
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground text-center">
                    FN
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground text-center">
                    FP
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Result
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {filteredCves.map((cve) => {
                  const badge = resultBadge(cve);
                  const isExpanded = expandedCve === cve.cve_id;
                  return (
                    <Fragment key={cve.cve_id}>
                      <tr
                        onClick={() =>
                          setExpandedCve(isExpanded ? null : cve.cve_id)
                        }
                        className={cn(
                          "cursor-pointer transition-colors hover:bg-muted/50",
                          isExpanded && "bg-muted/50"
                        )}
                      >
                        <td className="px-4 py-3">
                          <span className="font-medium font-mono text-sm">
                            {cve.cve_id}
                          </span>
                          {cve.description && (
                            <p className="mt-0.5 text-xs text-muted-foreground truncate max-w-[240px]">
                              {cve.description}
                            </p>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono text-sm">
                          {cve.driver}
                        </td>
                        <td className="px-4 py-3">
                          <div className="text-xs font-mono">
                            <span className="text-muted-foreground">
                              {cve.vuln_build}
                            </span>
                            <span className="mx-1 text-muted-foreground">
                              &rarr;
                            </span>
                            <span>{cve.fix_build}</span>
                          </div>
                          {(cve.vuln_kb || cve.fix_kb) && (
                            <div className="mt-0.5 flex gap-1">
                              {cve.vuln_kb && (
                                <span className="text-[10px] rounded bg-orange-100 text-orange-700 px-1">
                                  {cve.vuln_kb}
                                </span>
                              )}
                              {cve.fix_kb && (
                                <span className="text-[10px] rounded bg-green-100 text-green-700 px-1">
                                  {cve.fix_kb}
                                </span>
                              )}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className="rounded-full bg-purple-100 px-2 py-0.5 text-xs font-medium text-purple-700">
                            {categoryLabel(cve.expected_category_primary)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={cn(
                              "rounded-full px-2 py-0.5 text-xs font-medium",
                              statusColor(cve.status)
                            )}
                          >
                            {cve.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-center">
                          {cve.status === "evaluated" ? (
                            <span className="text-xs font-mono">
                              {cve.total_changed}
                              <span className="text-muted-foreground">
                                {" / "}
                              </span>
                              {cve.total_hits}
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              {cve.expected_detections_count} expected
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-center font-mono">
                          {cve.status === "evaluated" ? cve.tp : "--"}
                        </td>
                        <td className="px-4 py-3 text-center font-mono">
                          {cve.status === "evaluated" ? cve.fn : "--"}
                        </td>
                        <td className="px-4 py-3 text-center font-mono">
                          {cve.status === "evaluated" ? cve.fp : "--"}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span
                              className={cn(
                                "font-semibold text-sm",
                                badge.color
                              )}
                            >
                              {badge.label}
                            </span>
                            <svg
                              className={cn(
                                "h-4 w-4 text-muted-foreground transition-transform",
                                isExpanded && "rotate-180"
                              )}
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                              strokeWidth={2}
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                d="M19 9l-7 7-7-7"
                              />
                            </svg>
                          </div>
                          {cve.error && (
                            <p className="mt-0.5 text-xs text-red-500 truncate max-w-[160px]">
                              {cve.error}
                            </p>
                          )}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={10} className="p-0">
                            <CVEDetailPanel cve={cve} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
