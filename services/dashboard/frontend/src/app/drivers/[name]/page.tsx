import Link from "next/link";
import { getDriverAnalyses } from "@/lib/api";
import { cn, scoreColor, formatDate } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function DriverDetailPage({
  params,
}: {
  params: { name: string };
}) {
  const driverName = decodeURIComponent(params.name);
  let data;
  try {
    data = await getDriverAnalyses(driverName);
  } catch {
    return (
      <div>
        <h1 className="text-2xl font-semibold">{driverName}</h1>
        <p className="mt-4 text-muted-foreground">Driver not found or backend unavailable.</p>
      </div>
    );
  }

  const analyses = data.analyses;
  const scores = analyses.map((a) => a.top_score);
  const maxScore = Math.max(...scores, 0);
  const avgScore = scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : 0;
  const totalFindings = analyses.reduce((s, a) => s + a.total_findings, 0);
  const totalReachable = analyses.reduce((s, a) => s + a.reachable_findings, 0);

  return (
    <div className="space-y-6">
      <div>
        <Link href="/drivers" className="text-xs text-blue-600 hover:underline dark:text-blue-400">
          &larr; All Drivers
        </Link>
        <h1 className="mt-2 text-2xl font-semibold">{driverName}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {analyses.length} version{analyses.length !== 1 ? "s" : ""} analyzed
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Highest Score</p>
          <p className={cn("mt-1 text-2xl font-semibold", scoreColor(maxScore))}>
            {maxScore.toFixed(1)}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Avg Score</p>
          <p className="mt-1 text-2xl font-semibold">{avgScore.toFixed(1)}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total Findings</p>
          <p className="mt-1 text-2xl font-semibold">{totalFindings}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Reachable</p>
          <p className="mt-1 text-2xl font-semibold text-orange-600 dark:text-orange-400">
            {totalReachable}
          </p>
        </div>
      </div>

      {/* Score trend (mini bar chart) */}
      {analyses.length > 1 && (
        <div className="rounded-xl border bg-card p-5">
          <p className="mb-3 text-sm font-medium text-muted-foreground">Score Trend (by version)</p>
          <div className="flex items-end gap-1" style={{ height: "80px" }}>
            {[...analyses].reverse().map((a) => {
              const pct = maxScore > 0 ? (a.top_score / maxScore) * 100 : 0;
              return (
                <Link
                  key={a.id}
                  href={`/analysis/${a.id}`}
                  className="group relative flex-1"
                  title={`${formatDate(a.created_at)} — Score: ${a.top_score.toFixed(1)}`}
                >
                  <div
                    className={cn(
                      "w-full rounded-t transition-opacity group-hover:opacity-80",
                      a.top_score >= 10
                        ? "bg-red-500"
                        : a.top_score >= 7
                          ? "bg-orange-500"
                          : a.top_score >= 4
                            ? "bg-yellow-500"
                            : "bg-green-500"
                    )}
                    style={{ height: `${Math.max(pct, 4)}%` }}
                  />
                </Link>
              );
            })}
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-muted-foreground">
            <span>oldest</span>
            <span>newest</span>
          </div>
        </div>
      )}

      {/* Analysis list */}
      <div>
        <h2 className="text-lg font-semibold">All Versions</h2>
        <div className="mt-3 grid gap-3">
          {analyses.map((a) => (
            <Link
              key={a.id}
              href={`/analysis/${a.id}`}
              className="group flex items-center justify-between rounded-xl border bg-card p-4 transition-colors hover:border-foreground/20"
            >
              <div>
                <p className="text-sm font-medium group-hover:text-blue-600 dark:group-hover:text-blue-400">
                  {a.id}
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {a.arch} &middot; {formatDate(a.created_at)}
                </p>
              </div>
              <div className="flex items-center gap-6 text-sm">
                <span>
                  <strong>{a.total_findings}</strong>{" "}
                  <span className="text-muted-foreground">findings</span>
                </span>
                {a.reachable_findings > 0 && (
                  <span className="text-orange-600 dark:text-orange-400">
                    <strong>{a.reachable_findings}</strong> reachable
                  </span>
                )}
                <span className={cn("font-mono text-lg font-bold", scoreColor(a.top_score))}>
                  {a.top_score.toFixed(1)}
                </span>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
