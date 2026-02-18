import { cn, reachabilityBadge, reachabilityLabel } from "@/lib/utils";

interface ReachabilityPathProps {
  path: string[];
  reachabilityClass: string;
}

export function ReachabilityPath({
  path,
  reachabilityClass,
}: ReachabilityPathProps) {
  if (!path || path.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">
        No reachability path available
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground">Class:</span>
        <span
          className={cn(
            "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
            reachabilityBadge(reachabilityClass)
          )}
        >
          {reachabilityLabel(reachabilityClass)}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1">
        {path.map((node, i) => (
          <div key={i} className="flex items-center gap-1">
            <span
              className={cn(
                "rounded-md border px-2 py-1 text-xs font-mono",
                i === 0
                  ? "border-blue-300 bg-blue-50 text-blue-700"
                  : i === path.length - 1
                    ? "border-red-300 bg-red-50 text-red-700 font-semibold"
                    : "border-border bg-muted text-foreground"
              )}
            >
              {node}
            </span>
            {i < path.length - 1 && (
              <svg
                className="h-3 w-3 text-muted-foreground"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5l7 7-7 7"
                />
              </svg>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
