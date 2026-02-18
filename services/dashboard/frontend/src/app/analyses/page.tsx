import Link from "next/link";
import { getAnalyses } from "@/lib/api";
import { cn, scoreColor, formatDate } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function AnalysesPage() {
  let data;
  try {
    data = await getAnalyses();
  } catch {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Analyses</h1>
        <p className="mt-4 text-muted-foreground">
          Could not load analyses. Is the backend running?
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Analyses</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {data.total} analysis result{data.total !== 1 ? "s" : ""}
          </p>
        </div>
      </div>

      {data.analyses.length === 0 ? (
        <div className="rounded-lg border bg-muted/50 p-8 text-center">
          <p className="text-muted-foreground">No analyses found.</p>
        </div>
      ) : (
        <div className="grid gap-4">
          {data.analyses.map((a) => (
            <Link
              key={a.id}
              href={`/analysis/${a.id}`}
              className="group rounded-xl border bg-card p-5 transition-colors hover:border-foreground/20"
            >
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-medium group-hover:text-blue-600">
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
                  <span className="text-orange-600">
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
