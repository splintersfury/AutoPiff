"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { searchDashboard } from "@/lib/api";
import { cn, scoreColor } from "@/lib/utils";
import type { SearchResult } from "@/types";

export default function SearchPage() {
  const searchParams = useSearchParams();
  const query = searchParams.get("q") || "";
  const [results, setResults] = useState<SearchResult[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (query.length < 2) {
      setResults([]);
      setTotal(0);
      return;
    }
    setLoading(true);
    searchDashboard(query)
      .then((data) => {
        setResults(data.results);
        setTotal(data.total);
      })
      .catch(() => {
        setResults([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  }, [query]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Search Results</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {query ? (
            <>
              {total} result{total !== 1 ? "s" : ""} for &ldquo;{query}&rdquo;
            </>
          ) : (
            "Enter a search term in the sidebar."
          )}
        </p>
      </div>

      {loading && (
        <div className="py-8 text-center">
          <div className="animate-pulse text-muted-foreground">Searching...</div>
        </div>
      )}

      {!loading && results.length === 0 && query.length >= 2 && (
        <div className="rounded-lg border bg-muted/50 p-8 text-center">
          <p className="text-muted-foreground">No results found.</p>
          <p className="mt-1 text-sm text-muted-foreground">
            Try searching for a driver name, function, rule ID, or sink.
          </p>
        </div>
      )}

      {results.length > 0 && (
        <div className="space-y-2">
          {results.map((r) => (
            <Link
              key={r.id}
              href={r.link}
              className="flex items-start justify-between rounded-xl border bg-card p-4 transition-colors hover:border-foreground/20"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span
                    className={cn(
                      "rounded px-1.5 py-0.5 text-[10px] font-medium uppercase",
                      r.type === "finding"
                        ? "bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300"
                        : "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300"
                    )}
                  >
                    {r.type}
                  </span>
                  <p className="text-sm font-medium truncate">{r.title}</p>
                </div>
                <p className="mt-0.5 text-xs text-muted-foreground truncate">
                  {r.detail}
                </p>
              </div>
              {r.score != null && (
                <span className={cn("ml-4 font-mono text-sm font-semibold", scoreColor(r.score))}>
                  {r.score.toFixed(1)}
                </span>
              )}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
