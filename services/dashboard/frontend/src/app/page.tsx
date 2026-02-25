import Link from "next/link";
import { getAnalyses, getActivity, getTriageSummary } from "@/lib/api";
import {
  cn,
  scoreColor,
  formatDate,
  timeAgo,
  activityIcon,
  activityColor,
  triageBadge,
  triageLabel,
} from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  let data;
  let activity;
  let triageSummary;
  try {
    [data, activity, triageSummary] = await Promise.all([
      getAnalyses(),
      getActivity(20),
      getTriageSummary(),
    ]);
  } catch {
    return (
      <div>
        <h1 className="text-2xl font-semibold">AutoPiff Dashboard</h1>
        <div className="mt-8 rounded-lg border border-yellow-300 bg-yellow-50 p-6">
          <h2 className="font-medium text-yellow-800">
            Backend not available
          </h2>
          <p className="mt-1 text-sm text-yellow-700">
            Could not connect to the API. Make sure the backend is running on
            port 8000.
          </p>
        </div>
      </div>
    );
  }

  const analyses = data.analyses;
  const totalFindings = analyses.reduce((sum, a) => sum + a.total_findings, 0);
  const reachableFindings = analyses.reduce(
    (sum, a) => sum + a.reachable_findings,
    0
  );
  const highestScore =
    analyses.length > 0 ? Math.max(...analyses.map((a) => a.top_score)) : 0;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          AutoPiff Patch Intelligence overview
        </p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total Analyses</p>
          <p className="mt-1 text-2xl font-semibold">{analyses.length}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total Findings</p>
          <p className="mt-1 text-2xl font-semibold">{totalFindings}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Reachable</p>
          <p className="mt-1 text-2xl font-semibold text-orange-600">
            {reachableFindings}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Highest Score</p>
          <p
            className={cn(
              "mt-1 text-2xl font-semibold",
              scoreColor(highestScore)
            )}
          >
            {analyses.length > 0 ? highestScore.toFixed(1) : "N/A"}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Needs Triage</p>
          <p className="mt-1 text-2xl font-semibold">
            {triageSummary
              ? totalFindings - triageSummary.total + triageSummary.untriaged
              : totalFindings}
          </p>
          {triageSummary && triageSummary.confirmed > 0 && (
            <p className="mt-0.5 text-xs text-red-600">
              {triageSummary.confirmed} confirmed
            </p>
          )}
        </div>
      </div>

      {/* Triage status bar */}
      {triageSummary && triageSummary.total > 0 && (
        <div className="rounded-xl border bg-card p-5">
          <p className="mb-3 text-sm font-medium text-muted-foreground">
            Triage Progress
          </p>
          <div className="flex gap-4 text-sm">
            {(
              [
                "investigating",
                "confirmed",
                "false_positive",
                "resolved",
              ] as const
            ).map((state) => (
              <span
                key={state}
                className={cn(
                  "rounded-full px-2.5 py-0.5 text-xs font-medium",
                  triageBadge(state)
                )}
              >
                {triageLabel(state)}: {triageSummary[state]}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="grid gap-8 lg:grid-cols-3">
        {/* Activity Feed — takes 2/3 width */}
        <div className="lg:col-span-2">
          <h2 className="text-lg font-semibold">Activity Feed</h2>
          <p className="mb-4 text-sm text-muted-foreground">
            Recent pipeline events
          </p>

          {activity && activity.length > 0 ? (
            <div className="space-y-1">
              {activity.map((item, i) => (
                <Link
                  key={`${item.timestamp}-${i}`}
                  href={item.link || "#"}
                  className="flex items-start gap-3 rounded-lg border bg-card p-4 transition-colors hover:bg-muted/50"
                >
                  <svg
                    className={cn(
                      "mt-0.5 h-5 w-5 shrink-0",
                      activityColor(item.type)
                    )}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={1.5}
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d={activityIcon(item.type)}
                    />
                  </svg>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-medium truncate">
                        {item.title}
                      </p>
                      <span className="shrink-0 text-xs text-muted-foreground">
                        {timeAgo(item.timestamp)}
                      </span>
                    </div>
                    {item.detail && (
                      <p className="mt-0.5 text-xs text-muted-foreground truncate">
                        {item.detail}
                      </p>
                    )}
                    {item.score != null && item.score >= 8 && (
                      <span
                        className={cn(
                          "mt-1 inline-block font-mono text-xs font-semibold",
                          scoreColor(item.score)
                        )}
                      >
                        {item.score.toFixed(1)}
                      </span>
                    )}
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border bg-muted/50 p-8 text-center">
              <p className="text-muted-foreground">No activity yet.</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Run the AutoPiff pipeline to see events here.
              </p>
            </div>
          )}
        </div>

        {/* Recent Analyses — sidebar 1/3 width */}
        <div>
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold">Recent Analyses</h2>
            <Link
              href="/analyses"
              className="text-xs text-blue-600 hover:underline"
            >
              View all
            </Link>
          </div>
          <p className="mb-4 text-sm text-muted-foreground">
            {analyses.length} total
          </p>

          {analyses.length === 0 ? (
            <div className="rounded-lg border bg-muted/50 p-6 text-center">
              <p className="text-sm text-muted-foreground">No analyses yet.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {analyses.slice(0, 8).map((a) => (
                <Link
                  key={a.id}
                  href={`/analysis/${a.id}`}
                  className="block rounded-lg border bg-card p-3 transition-colors hover:bg-muted/50"
                >
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium truncate">
                      {a.driver_name || a.id}
                    </p>
                    <span
                      className={cn(
                        "font-mono text-sm font-semibold",
                        scoreColor(a.top_score)
                      )}
                    >
                      {a.top_score.toFixed(1)}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                    <span>{a.total_findings} findings</span>
                    {a.reachable_findings > 0 && (
                      <span className="text-orange-600">
                        {a.reachable_findings} reachable
                      </span>
                    )}
                    <span className="ml-auto">{timeAgo(a.created_at)}</span>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
