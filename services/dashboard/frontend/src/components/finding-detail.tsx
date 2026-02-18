import type { Finding } from "@/types";
import { categoryLabel, cn, scoreColor } from "@/lib/utils";
import { ScoreBreakdown } from "./score-breakdown";
import { DiffViewer } from "./diff-viewer";
import { ReachabilityPath } from "./reachability-path";

interface FindingDetailProps {
  finding: Finding;
}

export function FindingDetail({ finding }: FindingDetailProps) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold font-mono">
            {finding.function}
          </h3>
          <div className="mt-1 flex items-center gap-2">
            <span className="rounded-md bg-muted px-2 py-0.5 text-xs">
              {categoryLabel(finding.category)}
            </span>
            <span className="font-mono text-xs text-muted-foreground">
              {finding.rule_id}
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

      {/* Why it matters */}
      <div>
        <h4 className="text-sm font-medium text-muted-foreground">
          Why This Matters
        </h4>
        <p className="mt-1 text-sm leading-relaxed">{finding.why_matters}</p>
      </div>

      {/* Indicators */}
      <div className="flex gap-8">
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
        <DiffViewer snippet={finding.diff_snippet} />
      </div>
    </div>
  );
}
