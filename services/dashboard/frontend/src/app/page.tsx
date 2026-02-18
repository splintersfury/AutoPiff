import Link from "next/link";
import { getAnalyses } from "@/lib/api";
import {
  cn,
  scoreColor,
  formatDate,
  reachabilityBadge,
  reachabilityLabel,
} from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  let data;
  try {
    data = await getAnalyses();
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

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          AutoPiff Patch Intelligence overview
        </p>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total Analyses</p>
          <p className="mt-1 text-2xl font-semibold">{analyses.length}</p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Total Findings</p>
          <p className="mt-1 text-2xl font-semibold">
            {analyses.reduce((sum, a) => sum + a.total_findings, 0)}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Reachable Findings</p>
          <p className="mt-1 text-2xl font-semibold">
            {analyses.reduce((sum, a) => sum + a.reachable_findings, 0)}
          </p>
        </div>
        <div className="rounded-xl border bg-card p-5">
          <p className="text-sm text-muted-foreground">Highest Score</p>
          <p
            className={cn(
              "mt-1 text-2xl font-semibold",
              scoreColor(
                Math.max(0, ...analyses.map((a) => a.top_score))
              )
            )}
          >
            {analyses.length > 0
              ? Math.max(...analyses.map((a) => a.top_score)).toFixed(2)
              : "N/A"}
          </p>
        </div>
      </div>

      {/* Analysis list */}
      <div>
        <h2 className="text-lg font-semibold">Recent Analyses</h2>
        {analyses.length === 0 ? (
          <div className="mt-4 rounded-lg border bg-muted/50 p-8 text-center">
            <p className="text-muted-foreground">No analyses yet.</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Upload analysis artifacts or run the AutoPiff pipeline to get
              started.
            </p>
          </div>
        ) : (
          <div className="mt-4 overflow-x-auto rounded-lg border">
            <table className="w-full text-left text-sm">
              <thead className="border-b bg-muted/50">
                <tr>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Driver
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Date
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Findings
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Top Score
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-muted-foreground">
                    Decision
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {analyses.map((a) => (
                  <tr
                    key={a.id}
                    className="transition-colors hover:bg-muted/50"
                  >
                    <td className="px-4 py-3">
                      <Link
                        href={`/analysis/${a.id}`}
                        className="font-medium text-blue-600 hover:underline"
                      >
                        {a.driver_name || a.id}
                      </Link>
                      <p className="text-xs text-muted-foreground">{a.arch}</p>
                    </td>
                    <td className="px-4 py-3 text-sm text-muted-foreground">
                      {formatDate(a.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-semibold">
                        {a.total_findings}
                      </span>
                      {a.reachable_findings > 0 && (
                        <span className="ml-1 text-xs text-orange-600">
                          ({a.reachable_findings} reachable)
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          "font-mono font-semibold",
                          scoreColor(a.top_score)
                        )}
                      >
                        {a.top_score.toFixed(2)}
                      </span>
                    </td>
                    <td className="px-4 py-3">
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
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
