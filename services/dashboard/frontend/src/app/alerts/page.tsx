"use client";

import { useEffect, useState } from "react";
import { getAlerts } from "@/lib/api";
import { cn, scoreColor, categoryLabel } from "@/lib/utils";
import type { AlertsResponse } from "@/types";

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AlertsPage() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"findings" | "variants">("findings");

  useEffect(() => {
    getAlerts(100)
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Alerts</h1>
        <p className="mt-4 text-muted-foreground">Could not load alerts: {error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-muted-foreground">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Alert History</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {data.alerts.length} finding alert{data.alerts.length !== 1 ? "s" : ""},{" "}
          {data.variants.length} variant alert{data.variants.length !== 1 ? "s" : ""}
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        <button
          onClick={() => setTab("findings")}
          className={cn(
            "px-4 py-2 text-sm font-medium transition-colors",
            tab === "findings"
              ? "border-b-2 border-foreground text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          Finding Alerts ({data.alerts.length})
        </button>
        <button
          onClick={() => setTab("variants")}
          className={cn(
            "px-4 py-2 text-sm font-medium transition-colors",
            tab === "variants"
              ? "border-b-2 border-foreground text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          Variant Alerts ({data.variants.length})
        </button>
      </div>

      {tab === "findings" && (
        <>
          {data.alerts.length === 0 ? (
            <div className="rounded-lg border bg-muted/50 p-8 text-center">
              <p className="text-muted-foreground">No finding alerts yet.</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Alerts appear when findings score above the threshold.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {data.alerts.map((alert, i) => (
                <div key={i} className="rounded-xl border bg-card p-4">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <svg className="h-5 w-5 text-red-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                      </svg>
                      <div>
                        <p className="text-sm font-medium font-mono">{alert.function}</p>
                        <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                          <span className="rounded bg-muted px-1.5 py-0.5">{categoryLabel(alert.category)}</span>
                          <span className="font-mono">{alert.rule_id}</span>
                          <span>{alert.surface_area}</span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className={cn("text-lg font-bold font-mono", scoreColor(alert.score))}>
                        {alert.score.toFixed(1)}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {formatTimestamp(alert.timestamp)}
                      </p>
                    </div>
                  </div>
                  {alert.why_matters && (
                    <p className="mt-2 text-xs text-muted-foreground">{alert.why_matters}</p>
                  )}
                  <p className="mt-1 text-xs font-mono text-muted-foreground">
                    Driver: {alert.driver_new.slice(0, 16)}...
                  </p>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {tab === "variants" && (
        <>
          {data.variants.length === 0 ? (
            <div className="rounded-lg border bg-muted/50 p-8 text-center">
              <p className="text-muted-foreground">No variant alerts yet.</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Variant alerts appear when KernelSense finds similar vulnerable patterns in other drivers.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {data.variants.map((v, i) => (
                <div key={i} className="rounded-xl border bg-card p-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <svg className="h-5 w-5 text-purple-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 21L3 16.5m0 0L7.5 12M3 16.5h13.5m0-13.5L21 7.5m0 0L16.5 12M21 7.5H7.5" />
                        </svg>
                        <p className="text-sm font-medium">
                          <span className="font-mono">{v.variant_function}</span>
                          <span className="text-muted-foreground"> in </span>
                          <span>{v.variant_driver}</span>
                        </p>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Variant of <span className="font-mono">{v.source_function}</span> in {v.source_driver}
                      </p>
                      <div className="mt-1 flex items-center gap-2 text-xs">
                        <span className="rounded bg-purple-100 px-1.5 py-0.5 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300">
                          {v.bug_class}
                        </span>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-semibold font-mono">
                        {(v.similarity * 100).toFixed(0)}% similar
                      </p>
                      <p className="text-xs text-muted-foreground">
                        conf: {(v.confidence * 100).toFixed(0)}%
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {formatTimestamp(v.timestamp)}
                      </p>
                    </div>
                  </div>
                  {v.reasoning && (
                    <p className="mt-2 text-xs text-muted-foreground italic">{v.reasoning}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
