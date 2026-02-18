import { cn, scoreColor } from "@/lib/utils";
import type { ScoreBreakdown as ScoreBreakdownType } from "@/types";

interface ScoreBreakdownProps {
  breakdown: ScoreBreakdownType;
  finalScore: number;
}

export function ScoreBreakdown({ breakdown, finalScore }: ScoreBreakdownProps) {
  const items = [
    { label: "Semantic", value: breakdown.semantic, color: "bg-blue-500" },
    {
      label: "Reachability",
      value: breakdown.reachability,
      color: "bg-orange-500",
    },
    { label: "Sink Bonus", value: breakdown.sinks, color: "bg-purple-500" },
    {
      label: "Penalties",
      value: -breakdown.penalties,
      color: "bg-red-500",
      negative: true,
    },
  ];

  const maxPossible = 15;
  const barWidth = (val: number) =>
    `${Math.min(100, (Math.abs(val) / maxPossible) * 100)}%`;

  return (
    <div className="space-y-3">
      <div className="flex items-baseline gap-2">
        <span className="text-sm font-medium text-muted-foreground">
          Final Score
        </span>
        <span className={cn("text-2xl font-bold", scoreColor(finalScore))}>
          {finalScore.toFixed(2)}
        </span>
        <span className="text-xs text-muted-foreground">/ 15.00</span>
      </div>

      <div className="space-y-2">
        {items.map((item) => (
          <div key={item.label} className="space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">{item.label}</span>
              <span
                className={cn(
                  "font-mono",
                  item.negative && item.value < 0
                    ? "text-red-500"
                    : "text-foreground"
                )}
              >
                {item.value >= 0 ? "+" : ""}
                {item.value.toFixed(2)}
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-muted">
              <div
                className={cn("h-1.5 rounded-full transition-all", item.color)}
                style={{ width: barWidth(item.value) }}
              />
            </div>
          </div>
        ))}
      </div>

      {breakdown.gates.length > 0 && (
        <div className="mt-2">
          <p className="text-xs text-muted-foreground">Gates Applied:</p>
          <div className="mt-1 flex flex-wrap gap-1">
            {breakdown.gates.map((gate) => (
              <span
                key={gate}
                className="rounded bg-yellow-100 px-1.5 py-0.5 text-xs text-yellow-800"
              >
                {gate}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
