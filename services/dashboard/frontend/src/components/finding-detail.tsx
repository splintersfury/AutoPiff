"use client";

import { useState, useEffect } from "react";
import type { Analysis, Finding, TriageEntry, VariantMatch } from "@/types";
import { categoryLabel, cn, scoreColor, reachabilityLabel, reachabilityBadge, truncateSha } from "@/lib/utils";
import { ScoreBreakdown } from "./score-breakdown";
import { DiffViewer } from "./diff-viewer";
import { ReachabilityPath } from "./reachability-path";
import { TriageSelector } from "./triage-selector";
import { ExploitTracker } from "./exploit-tracker";
import { getVariants } from "@/lib/api";

function BinaryLinks({ sha256 }: { sha256: string }) {
  return (
    <span className="inline-flex gap-1.5 ml-1">
      <a
        href={`https://www.virustotal.com/gui/file/${sha256}`}
        target="_blank"
        rel="noopener noreferrer"
        className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-blue-500/10 text-blue-600 hover:bg-blue-500/20 dark:text-blue-400 transition-colors"
        title="View on VirusTotal"
      >
        VT
      </a>
      <a
        href={`https://winbindex.m417z.com/?hash=${sha256}`}
        target="_blank"
        rel="noopener noreferrer"
        className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-purple-500/10 text-purple-600 hover:bg-purple-500/20 dark:text-purple-400 transition-colors"
        title="Look up on WinBIndex"
      >
        WBI
      </a>
    </span>
  );
}

interface FindingDetailProps {
  finding: Finding;
  analysis?: Analysis | null;
  analysisId?: string;
  triage?: TriageEntry | null;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <button
      onClick={handleCopy}
      title={`Copy ${label}`}
      className="ml-1 inline-flex items-center rounded px-1 py-0.5 text-[10px] text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground"
    >
      {copied ? (
        <svg className="h-3 w-3 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      ) : (
        <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

export function FindingDetail({ finding, analysis, analysisId, triage }: FindingDetailProps) {
  const [variants, setVariants] = useState<VariantMatch[]>([]);
  const [variantsLoading, setVariantsLoading] = useState(false);

  useEffect(() => {
    if (!analysisId) return;
    setVariantsLoading(true);
    getVariants(analysisId, finding.function)
      .then(setVariants)
      .catch(() => setVariants([]))
      .finally(() => setVariantsLoading(false));
  }, [analysisId, finding.function]);

  const driverNew = analysis?.driver_new;
  const driverOld = analysis?.driver_old;

  // Find matching IOCTLs for this finding's reachability
  const relatedIoctls = analysis?.reachability?.ioctls.filter((ioctl) => {
    if (!finding.reachability_path.length) return false;
    return finding.reachability_path.some((p) => p === ioctl.handler);
  }) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold font-mono">
              {finding.function}
            </h3>
            <CopyButton text={finding.function} label="function name" />
          </div>
          <div className="mt-1 flex items-center gap-2">
            <span className="rounded-md bg-muted px-2 py-0.5 text-xs">
              {categoryLabel(finding.category)}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              {finding.rule_id}
            </span>
            <span
              className={cn(
                "rounded-full px-2 py-0.5 text-xs font-medium",
                reachabilityBadge(finding.reachability_class)
              )}
            >
              {reachabilityLabel(finding.reachability_class)}
            </span>
          </div>
        </div>
        <div className="text-right">
          <p className={cn("text-2xl font-bold", scoreColor(finding.final_score))}>
            {finding.final_score.toFixed(2)}
          </p>
          <p className="text-xs text-muted-foreground">/ 15.00</p>
        </div>
      </div>

      {/* Triage + Exploit Stage */}
      {analysisId && (
        <div className="flex flex-wrap items-start gap-4">
          <TriageSelector
            analysisId={analysisId}
            functionName={finding.function}
            currentState={triage?.state || "untriaged"}
            currentNote={triage?.note || ""}
          />
          <ExploitTracker
            analysisId={analysisId}
            functionName={finding.function}
            currentStage={triage?.exploit_stage || "not_started"}
          />
        </div>
      )}

      {/* Driver Context — the key missing info */}
      {driverNew && (
        <div className="rounded-lg border bg-muted/30 p-4">
          <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Driver Context
          </h4>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            {/* New (patched) driver */}
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-muted-foreground">Patched Binary (new)</p>
              <p className="text-sm font-medium">
                {driverNew.product || "Unknown Driver"}
                {driverNew.version && (
                  <span className="ml-2 text-xs text-muted-foreground">v{driverNew.version}</span>
                )}
              </p>
              <div className="flex items-center gap-1">
                <span className="font-mono text-xs text-muted-foreground">
                  {truncateSha(driverNew.sha256, 16)}...
                </span>
                <CopyButton text={driverNew.sha256} label="SHA256" />
                <BinaryLinks sha256={driverNew.sha256} />
              </div>
              <p className="text-xs text-muted-foreground">{driverNew.arch}</p>
            </div>

            {/* Old (vulnerable) driver */}
            {driverOld && (
              <div className="space-y-1.5">
                <p className="text-xs font-medium text-muted-foreground">Vulnerable Binary (old)</p>
                <p className="text-sm font-medium">
                  {driverOld.product || "Unknown Driver"}
                  {driverOld.version && (
                    <span className="ml-2 text-xs text-muted-foreground">v{driverOld.version}</span>
                  )}
                </p>
                <div className="flex items-center gap-1">
                  <span className="font-mono text-xs text-muted-foreground">
                    {truncateSha(driverOld.sha256, 16)}...
                  </span>
                  <CopyButton text={driverOld.sha256} label="SHA256" />
                  <BinaryLinks sha256={driverOld.sha256} />
                </div>
                <p className="text-xs text-muted-foreground">{driverOld.arch}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Surface Area + Related IOCTLs */}
      {(finding.surface_area.length > 0 || relatedIoctls.length > 0) && (
        <div>
          <h4 className="text-sm font-medium text-muted-foreground">Attack Surface</h4>
          <div className="mt-2 flex flex-wrap gap-2">
            {finding.surface_area.map((s) => (
              <span
                key={s}
                className="rounded-md border border-orange-500/30 bg-orange-500/10 px-2 py-1 text-xs font-medium text-orange-700 dark:text-orange-300"
              >
                {s}
              </span>
            ))}
          </div>
          {relatedIoctls.length > 0 && (
            <div className="mt-2 space-y-1">
              {relatedIoctls.map((ioctl) => (
                <div key={ioctl.ioctl} className="flex items-center gap-2 text-xs">
                  <span className="font-mono font-semibold text-red-600 dark:text-red-400">
                    {ioctl.ioctl}
                  </span>
                  <CopyButton text={ioctl.ioctl} label="IOCTL code" />
                  <span className="text-muted-foreground">
                    via <span className="font-mono">{ioctl.handler}</span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Why it matters */}
      <div>
        <h4 className="text-sm font-medium text-muted-foreground">
          Why This Matters
        </h4>
        <p className="mt-1 text-sm leading-relaxed">{finding.why_matters}</p>
      </div>

      {/* Indicators */}
      <div className="flex gap-8">
        {finding.sinks.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-muted-foreground">Sinks</h4>
            <div className="mt-1 flex flex-wrap gap-1">
              {finding.sinks.map((sink) => (
                <span
                  key={sink}
                  className="rounded bg-red-100 px-1.5 py-0.5 text-xs font-mono text-red-700"
                >
                  {sink}
                </span>
              ))}
            </div>
          </div>
        )}
        {finding.indicators.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-muted-foreground">
              Indicators
            </h4>
            <div className="mt-1 flex flex-wrap gap-1">
              {finding.indicators.map((ind) => (
                <span
                  key={ind}
                  className="rounded bg-blue-100 px-1.5 py-0.5 text-xs font-mono text-blue-700"
                >
                  {ind}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Reachability */}
      <div>
        <h4 className="mb-2 text-sm font-medium text-muted-foreground">
          Reachability
        </h4>
        <ReachabilityPath
          path={finding.reachability_path}
          reachabilityClass={finding.reachability_class}
        />
      </div>

      {/* Score Breakdown */}
      {finding.score_breakdown && (
        <div>
          <h4 className="mb-2 text-sm font-medium text-muted-foreground">
            Score Breakdown
          </h4>
          <ScoreBreakdown
            breakdown={finding.score_breakdown}
            finalScore={finding.final_score}
          />
        </div>
      )}

      {/* Diff */}
      <div>
        <h4 className="mb-2 text-sm font-medium text-muted-foreground">
          Diff Snippet
        </h4>
        <DiffViewer
          snippet={finding.diff_snippet}
          shaNew={driverNew?.sha256}
          shaOld={driverOld?.sha256}
        />
      </div>

      {/* Cross-driver variants */}
      {analysisId && (
        <div>
          <h4 className="mb-2 text-sm font-medium text-muted-foreground">
            Similar Findings in Other Drivers
          </h4>
          {variantsLoading ? (
            <p className="text-xs text-muted-foreground">Searching...</p>
          ) : variants.length > 0 ? (
            <div className="space-y-1.5">
              {variants.map((v) => (
                <a
                  key={`${v.analysis_id}::${v.function}`}
                  href={`/analysis/${v.analysis_id}?fn=${encodeURIComponent(v.function)}`}
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-xs transition-colors hover:bg-muted/50"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{v.driver_name}</span>
                    <span className="font-mono text-muted-foreground">{v.function}</span>
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px]">{v.category}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={cn("font-mono font-semibold", scoreColor(v.final_score))}>
                      {v.final_score.toFixed(2)}
                    </span>
                    <span className={cn(
                      "rounded-full px-2 py-0.5 text-[10px]",
                      reachabilityBadge(v.reachability_class)
                    )}>
                      {reachabilityLabel(v.reachability_class)}
                    </span>
                  </div>
                </a>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              No similar findings in other analyses.
            </p>
          )}
        </div>
      )}

      {/* Quick-copy reference */}
      {driverNew && (
        <div className="rounded-lg border border-dashed p-3">
          <h4 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Quick Reference
          </h4>
          <div className="mt-2 grid gap-1 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-20 text-muted-foreground">Function:</span>
              <code className="font-mono">{finding.function}</code>
              <CopyButton text={finding.function} label="function" />
            </div>
            <div className="flex items-center gap-2">
              <span className="w-20 text-muted-foreground">New SHA256:</span>
              <code className="font-mono">{truncateSha(driverNew.sha256, 20)}...</code>
              <CopyButton text={driverNew.sha256} label="new SHA256" />
            </div>
            {driverOld && (
              <div className="flex items-center gap-2">
                <span className="w-20 text-muted-foreground">Old SHA256:</span>
                <code className="font-mono">{truncateSha(driverOld.sha256, 20)}...</code>
                <CopyButton text={driverOld.sha256} label="old SHA256" />
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="w-20 text-muted-foreground">Rule:</span>
              <code className="font-mono">{finding.rule_id}</code>
              <CopyButton text={finding.rule_id} label="rule ID" />
            </div>
            {relatedIoctls.length > 0 && (
              <div className="flex items-center gap-2">
                <span className="w-20 text-muted-foreground">IOCTL:</span>
                <code className="font-mono">{relatedIoctls[0].ioctl}</code>
                <CopyButton text={relatedIoctls[0].ioctl} label="IOCTL" />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
