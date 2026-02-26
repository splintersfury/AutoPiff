"use client";

import { useEffect, useState } from "react";
import { getPipelineHealth } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { PipelineHealth } from "@/types";

function StatusDot({ status }: { status: string }) {
  return (
    <span
      className={cn(
        "inline-block h-2.5 w-2.5 rounded-full",
        status === "online" && "bg-green-500",
        status === "offline" && "bg-red-500",
        status === "unknown" && "bg-gray-400 animate-pulse"
      )}
    />
  );
}

export default function PipelinePage() {
  const [health, setHealth] = useState<PipelineHealth | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPipelineHealth()
      .then(setHealth)
      .catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Pipeline Health</h1>
        <p className="mt-4 text-muted-foreground">Could not load pipeline status: {error}</p>
      </div>
    );
  }

  if (!health) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-pulse text-muted-foreground">Loading pipeline status...</div>
      </div>
    );
  }

  const onlineCount = health.stages.filter((s) => s.status === "online").length;
  const totalStages = health.stages.length;
  const allUnknown = health.stages.every((s) => s.status === "unknown");

  // Group stages by type
  const pipelineStages = health.stages.filter((s) =>
    ["karton.autopiff.patch-differ", "karton.autopiff.reachability", "karton.autopiff.ranking", "karton.autopiff.report"].includes(s.identity)
  );
  const enrichmentStages = health.stages.filter((s) =>
    ["karton.autopiff.kernelsense", "karton.driveratlas.triage"].includes(s.identity)
  );
  const supportStages = health.stages.filter((s) =>
    ["karton.autopiff.alerter", "karton.autopiff.driver-monitor"].includes(s.identity)
  );

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Pipeline Health</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          AutoPiff Karton pipeline status
        </p>
      </div>

      {/* No Redis banner */}
      {!health.redis_connected && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/5 p-4">
          <p className="text-sm font-medium text-yellow-700 dark:text-yellow-400">
            Redis not connected
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Pipeline monitoring requires a connection to Karton Redis. Set <code className="rounded bg-muted px-1">KARTON_REDIS_HOST</code> or run the full Docker stack to see live consumer status.
          </p>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Active Consumers</p>
          <p className={cn(
            "mt-1 text-2xl font-semibold",
            allUnknown ? "text-muted-foreground" : onlineCount === totalStages ? "text-green-600 dark:text-green-400" : onlineCount > 0 ? "text-yellow-600 dark:text-yellow-400" : "text-red-600 dark:text-red-400"
          )}>
            {allUnknown ? "—" : `${onlineCount} / ${totalStages}`}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Redis</p>
          <p className={cn(
            "mt-1 text-2xl font-semibold",
            health.redis_connected ? "text-green-600 dark:text-green-400" : "text-muted-foreground"
          )}>
            {health.redis_connected ? "Connected" : "Not configured"}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Pipeline Status</p>
          <p className={cn(
            "mt-1 text-2xl font-semibold",
            allUnknown ? "text-muted-foreground" : onlineCount === totalStages ? "text-green-600 dark:text-green-400" : "text-yellow-600 dark:text-yellow-400"
          )}>
            {allUnknown ? "No data" : onlineCount === totalStages ? "Healthy" : onlineCount > 0 ? "Degraded" : "Down"}
          </p>
        </div>
      </div>

      {/* Pipeline Flow */}
      <div>
        <h2 className="text-lg font-semibold">Core Pipeline</h2>
        <p className="mt-1 mb-4 text-sm text-muted-foreground">
          Driver update &rarr; Diff &rarr; Reachability &rarr; Ranking &rarr; Report
        </p>
        <div className="flex items-center gap-2">
          {pipelineStages.map((stage, i) => (
            <div key={stage.identity} className="flex items-center gap-2">
              <div className={cn(
                "rounded-lg border p-4 min-w-[160px]",
                stage.status === "online" ? "border-green-500/50 bg-green-500/5" :
                stage.status === "offline" ? "border-red-500/50 bg-red-500/5" :
                "border-border"
              )}>
                <div className="flex items-center gap-2">
                  <StatusDot status={stage.status} />
                  <span className="text-sm font-medium">{stage.name}</span>
                </div>
                <p className="mt-1 text-xs text-muted-foreground font-mono truncate">
                  {stage.identity}
                </p>
              </div>
              {i < pipelineStages.length - 1 && (
                <svg className="h-4 w-4 text-muted-foreground shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Enrichment */}
      <div>
        <h2 className="text-lg font-semibold">Enrichment</h2>
        <p className="mt-1 mb-4 text-sm text-muted-foreground">
          Parallel consumers that enhance findings
        </p>
        <div className="grid grid-cols-2 gap-4">
          {enrichmentStages.map((stage) => (
            <div key={stage.identity} className={cn(
              "rounded-lg border p-4",
              stage.status === "online" ? "border-green-500/50 bg-green-500/5" :
              stage.status === "offline" ? "border-red-500/50 bg-red-500/5" :
              "border-border"
            )}>
              <div className="flex items-center gap-2">
                <StatusDot status={stage.status} />
                <span className="text-sm font-medium">{stage.name}</span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground font-mono">
                {stage.identity}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Support */}
      <div>
        <h2 className="text-lg font-semibold">Support Services</h2>
        <p className="mt-1 mb-4 text-sm text-muted-foreground">
          Monitoring, alerting, and input generation
        </p>
        <div className="grid grid-cols-2 gap-4">
          {supportStages.map((stage) => (
            <div key={stage.identity} className={cn(
              "rounded-lg border p-4",
              stage.status === "online" ? "border-green-500/50 bg-green-500/5" :
              stage.status === "offline" ? "border-red-500/50 bg-red-500/5" :
              "border-border"
            )}>
              <div className="flex items-center gap-2">
                <StatusDot status={stage.status} />
                <span className="text-sm font-medium">{stage.name}</span>
              </div>
              <p className="mt-1 text-xs text-muted-foreground font-mono">
                {stage.identity}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
