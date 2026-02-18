"use client";

import { useState, useMemo } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import type { Finding } from "@/types";
import {
  cn,
  scoreColor,
  categoryLabel,
  reachabilityLabel,
  reachabilityBadge,
  confidenceBadge,
} from "@/lib/utils";

interface FindingsTableProps {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  selectedFunction?: string;
}

export function FindingsTable({
  findings,
  onSelect,
  selectedFunction,
}: FindingsTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "final_score", desc: true },
  ]);
  const [categoryFilter, setCategoryFilter] = useState<string>("");

  const columns = useMemo<ColumnDef<Finding>[]>(
    () => [
      {
        id: "rank",
        header: "#",
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground font-mono">
            {row.index + 1}
          </span>
        ),
        size: 40,
        enableSorting: false,
      },
      {
        accessorKey: "function",
        header: "Function",
        cell: ({ getValue }) => (
          <span className="font-mono text-sm">{getValue<string>()}</span>
        ),
      },
      {
        accessorKey: "final_score",
        header: "Score",
        cell: ({ getValue }) => {
          const score = getValue<number>();
          return (
            <span className={cn("font-semibold font-mono", scoreColor(score))}>
              {score.toFixed(2)}
            </span>
          );
        },
        size: 80,
      },
      {
        accessorKey: "category",
        header: "Category",
        cell: ({ getValue }) => (
          <span className="inline-block rounded-md bg-muted px-2 py-0.5 text-xs">
            {categoryLabel(getValue<string>())}
          </span>
        ),
      },
      {
        accessorKey: "confidence",
        header: "Conf",
        cell: ({ getValue }) => {
          const c = getValue<number>();
          return (
            <span
              className={cn(
                "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
                confidenceBadge(c)
              )}
            >
              {(c * 100).toFixed(0)}%
            </span>
          );
        },
        size: 70,
      },
      {
        accessorKey: "reachability_class",
        header: "Reach",
        cell: ({ getValue }) => {
          const cls = getValue<string>();
          return (
            <span
              className={cn(
                "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
                reachabilityBadge(cls)
              )}
            >
              {reachabilityLabel(cls)}
            </span>
          );
        },
        size: 80,
      },
      {
        accessorKey: "rule_id",
        header: "Rule",
        cell: ({ getValue }) => (
          <span className="text-xs text-muted-foreground font-mono">
            {getValue<string>()}
          </span>
        ),
      },
    ],
    []
  );

  const filteredData = useMemo(() => {
    if (!categoryFilter) return findings;
    return findings.filter((f) => f.category === categoryFilter);
  }, [findings, categoryFilter]);

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

  const categories = Array.from(new Set(findings.map((f) => f.category)));

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Filter:</span>
        <button
          onClick={() => setCategoryFilter("")}
          className={cn(
            "rounded-md px-2.5 py-1 text-xs transition-colors",
            !categoryFilter
              ? "bg-foreground text-background"
              : "bg-muted text-muted-foreground hover:bg-accent"
          )}
        >
          All
        </button>
        {categories.map((cat) => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={cn(
              "rounded-md px-2.5 py-1 text-xs transition-colors",
              categoryFilter === cat
                ? "bg-foreground text-background"
                : "bg-muted text-muted-foreground hover:bg-accent"
            )}
          >
            {categoryLabel(cat)}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-left text-sm">
          <thead className="border-b bg-muted/50">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((header) => (
                  <th
                    key={header.id}
                    className="whitespace-nowrap px-4 py-3 text-xs font-medium text-muted-foreground"
                    style={{ width: header.getSize() }}
                    onClick={header.column.getToggleSortingHandler()}
                    role={header.column.getCanSort() ? "button" : undefined}
                  >
                    <div className="flex items-center gap-1">
                      {flexRender(
                        header.column.columnDef.header,
                        header.getContext()
                      )}
                      {header.column.getIsSorted() === "asc" && " ^"}
                      {header.column.getIsSorted() === "desc" && " v"}
                    </div>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y">
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                onClick={() => onSelect(row.original)}
                className={cn(
                  "cursor-pointer transition-colors hover:bg-muted/50",
                  row.original.function === selectedFunction && "bg-accent"
                )}
              >
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-4 py-3">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {filteredData.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            No findings match the current filter.
          </div>
        )}
      </div>
    </div>
  );
}
