import { cn, scoreColor, confidenceBadge } from "@/lib/utils";
import type { Analysis } from "@/types";

interface StatCardProps {
  label: string;
  value: string | number;
  detail?: string;
  className?: string;
}

function StatCard({ label, value, detail, className }: StatCardProps) {
  return (
    <div className={cn("rounded-xl border bg-card p-5", className)}>
      <p className="text-sm text-muted-foreground">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      {detail && <p className="mt-1 text-xs text-muted-foreground">{detail}</p>}
    </div>
  );
}

export function OverviewCards({ analysis }: { analysis: Analysis }) {
  const reachable = analysis.findings.filter(
    (f) => f.reachability_class === "ioctl" || f.reachability_class === "irp"
  ).length;

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard
        label="Total Findings"
        value={analysis.findings.length}
        detail={`${reachable} externally reachable`}
      />
      <StatCard
        label="Top Score"
        value={analysis.summary?.top_score.toFixed(2) ?? "N/A"}
        className={
          analysis.summary && analysis.summary.top_score >= 8
            ? "border-red-300"
            : ""
        }
      />
      <StatCard
        label="Match Rate"
        value={`${(analysis.summary?.match_rate ?? 0).toFixed(1)}%`}
        detail={`${analysis.matching?.matched_count ?? 0} functions matched`}
      />
      <StatCard
        label="Pairing"
        value={analysis.pairing?.decision ?? "N/A"}
        detail={`Noise: ${analysis.pairing?.noise_risk ?? "N/A"} | Conf: ${(
          (analysis.pairing?.confidence ?? 0) * 100
        ).toFixed(0)}%`}
      />
    </div>
  );
}

export function TrustIndicators({ analysis }: { analysis: Analysis }) {
  const items = [
    {
      label: "Pairing Confidence",
      value: analysis.pairing?.confidence ?? 0,
      ok: (analysis.pairing?.confidence ?? 0) >= 0.8,
    },
    {
      label: "Matching Quality",
      value: analysis.matching?.quality ?? "N/A",
      ok: analysis.matching?.quality === "high",
    },
    {
      label: "Noise Risk",
      value: analysis.pairing?.noise_risk ?? "N/A",
      ok: analysis.pairing?.noise_risk === "low",
    },
  ];

  return (
    <div className="flex flex-wrap gap-3">
      {items.map((item) => (
        <div
          key={item.label}
          className={cn(
            "rounded-full border px-3 py-1 text-xs font-medium",
            item.ok
              ? "border-green-300 bg-green-50 text-green-700"
              : "border-yellow-300 bg-yellow-50 text-yellow-700"
          )}
        >
          {item.label}: {typeof item.value === "number" ? `${(item.value * 100).toFixed(0)}%` : item.value}
        </div>
      ))}
    </div>
  );
}
