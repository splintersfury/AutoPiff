import Link from "next/link";
import { getAnalyses, getActivity, getTriageSummary, getStats } from "@/lib/api";
import {
  cn,
  scoreColor,
  formatDate,
  timeAgo,
  activityIcon,
  activityColor,
  triageBadge,
  triageLabel,
  categoryLabel,
} from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  let data;
  let activity;
  let triageSummary;
  let stats;
  try {
    [data, activity, triageSummary, stats] = await Promise.all([
      getAnalyses(),
      getActivity(20),
      getTriageSummary(),
      getStats(),
    ]);
  } catch {
    return (
      <div>
        <h1 className="text-2xl font-semibold">AutoPiff Dashboard</h1>
        <div className="mt-8 rounded-lg border border-yellow-300 bg-yellow-50 p-6 dark:border-yellow-700 dark:bg-yellow-900/20">
          <h2 className="font-medium text-yellow-800 dark:text-yellow-300">
            Backend not available
          </h2>
          <p className="mt-1 text-sm text-yellow-700 dark:text-yellow-400">
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

  // Score distribution max for chart scaling
  const maxBucketCount = stats
    ? Math.max(...stats.score_distribution.map((b) => b.count), 1)
    : 1;

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
        <Link href="/analyses" className="rounded-xl border bg-card p-5 transition-colors hover:border-foreground/20">
          <p className="text-sm text-muted-foreground">Total Analyses</p>
          <p className="mt-1 text-2xl font-semibold">{analyses.length}</p>
        </Link>
        <Link href="/analyses?min_score=0" className="rounded-xl border bg-card p-5 transition-colors hover:border-foreground/20">
          <p className="text-sm text-muted-foreground">Total Findings</p>
          <p className="mt-1 text-2xl font-semibold">{totalFindings}</p>
        </Link>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Reachable</p>
          <p className="mt-1 text-2xl font-semibold text-orange-600 dark:text-orange-400">
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
            <p className="mt-0.5 text-xs text-red-600 dark:text-red-400">
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

      {/* Trend Charts */}
      {stats && (stats.score_distribution.some((b) => b.count > 0) || stats.by_category.length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Score Distribution */}
          <div className="rounded-xl border bg-card p-5">
            <p className="mb-4 text-sm font-medium text-muted-foreground">
              Score Distribution
            </p>
            <div className="flex items-end gap-2" style={{ height: "100px" }}>
              {stats.score_distribution.map((b) => {
                const pct = maxBucketCount > 0 ? (b.count / maxBucketCount) * 100 : 0;
                const colorClass =
                  b.bucket === "10+"
                    ? "bg-red-500"
                    : b.bucket === "8-10"
                      ? "bg-orange-500"
                      : b.bucket === "6-8"
                        ? "bg-yellow-500"
                        : b.bucket === "4-6"
                          ? "bg-yellow-400"
                          : b.bucket === "2-4"
                            ? "bg-green-400"
                            : "bg-green-500";
                return (
                  <div key={b.bucket} className="flex flex-1 flex-col items-center gap-1">
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {b.count}
                    </span>
                    <div
                      className={cn("w-full rounded-t", colorClass)}
                      style={{ height: `${Math.max(pct, 3)}%` }}
                    />
                    <span className="text-[10px] text-muted-foreground">{b.bucket}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Category Breakdown */}
          <div className="rounded-xl border bg-card p-5">
            <p className="mb-4 text-sm font-medium text-muted-foreground">
              Findings by Category
            </p>
            <div className="space-y-2">
              {stats.by_category.slice(0, 8).map((c) => {
                const maxCat = stats.by_category[0]?.count || 1;
                const pct = (c.count / maxCat) * 100;
                return (
                  <div key={c.category} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span>{categoryLabel(c.category)}</span>
                      <span className="font-mono text-muted-foreground">{c.count}</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-muted">
                      <div
                        className="h-1.5 rounded-full bg-blue-500"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Findings Over Time */}
      {stats && stats.trends.length > 1 && (
        <div className="rounded-xl border bg-card p-5">
          <p className="mb-4 text-sm font-medium text-muted-foreground">
            Findings Over Time
          </p>
          <div className="flex items-end gap-1" style={{ height: "80px" }}>
            {stats.trends.map((t) => {
              const maxFindings = Math.max(...stats.trends.map((p) => p.findings), 1);
              const pct = (t.findings / maxFindings) * 100;
              return (
                <div
                  key={t.date}
                  className="flex flex-1 flex-col items-center gap-1"
                  title={`${t.date}: ${t.findings} findings, ${t.analyses} analyses`}
                >
                  <div
                    className="w-full rounded-t bg-blue-500/70"
                    style={{ height: `${Math.max(pct, 3)}%` }}
                  />
                </div>
              );
            })}
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
            <span>{stats.trends[0]?.date}</span>
            <span>{stats.trends[stats.trends.length - 1]?.date}</span>
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
              className="text-xs text-blue-600 hover:underline dark:text-blue-400"
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
                      <span className="text-orange-600 dark:text-orange-400">
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
