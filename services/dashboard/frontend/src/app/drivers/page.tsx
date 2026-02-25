import Link from "next/link";
import { getDrivers } from "@/lib/api";
import { cn, scoreColor, formatDate } from "@/lib/utils";

export const dynamic = "force-dynamic";

export default async function DriversPage() {
  let drivers;
  try {
    drivers = await getDrivers();
  } catch {
    return (
      <div>
        <h1 className="text-2xl font-semibold">Drivers</h1>
        <p className="mt-4 text-muted-foreground">
          Could not load drivers. Is the backend running?
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Drivers</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {drivers.length} monitored driver{drivers.length !== 1 ? "s" : ""} across all analyses
        </p>
      </div>

      {drivers.length === 0 ? (
        <div className="rounded-lg border bg-muted/50 p-8 text-center">
          <p className="text-muted-foreground">No drivers found.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-left text-sm">
            <thead className="border-b bg-muted/50">
              <tr>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Driver</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Arch</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Analyses</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Findings</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Reachable</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Highest Score</th>
                <th className="px-4 py-3 text-xs font-medium text-muted-foreground">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {drivers.map((d) => (
                <tr key={d.driver_name} className="transition-colors hover:bg-muted/50">
                  <td className="px-4 py-3">
                    <Link
                      href={`/drivers/${encodeURIComponent(d.driver_name)}`}
                      className="font-medium text-blue-600 hover:underline dark:text-blue-400"
                    >
                      {d.driver_name}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{d.arch}</td>
                  <td className="px-4 py-3 font-mono">{d.analysis_count}</td>
                  <td className="px-4 py-3 font-mono">{d.total_findings}</td>
                  <td className="px-4 py-3">
                    {d.reachable_findings > 0 ? (
                      <span className="font-mono text-orange-600 dark:text-orange-400">{d.reachable_findings}</span>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn("font-mono font-semibold", scoreColor(d.highest_score))}>
                      {d.highest_score.toFixed(1)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {d.latest_date ? formatDate(d.latest_date) : "N/A"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
