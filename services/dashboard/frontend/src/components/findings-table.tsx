"use client";

import { useState, useMemo, useCallback } from "react";
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import type { Finding, TriageEntry, TriageState } from "@/types";
import { bulkTriage } from "@/lib/api";
import {
  cn,
  scoreColor,
  categoryLabel,
  reachabilityLabel,
  reachabilityBadge,
  confidenceBadge,
  triageBadge,
  triageLabel,
} from "@/lib/utils";

interface FindingsTableProps {
  findings: Finding[];
  onSelect: (finding: Finding) => void;
  selectedFunction?: string;
  triageStates?: Record<string, TriageEntry>;
  analysisId?: string;
  onTriageUpdate?: () => void;
}

export function FindingsTable({
  findings,
  onSelect,
  selectedFunction,
  triageStates = {},
  analysisId,
  onTriageUpdate,
}: FindingsTableProps) {
  const [sorting, setSorting] = useState<SortingState>([
    { id: "final_score", desc: true },
  ]);
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkSaving, setBulkSaving] = useState(false);

  const toggleSelect = useCallback((func: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(func)) next.delete(func);
      else next.add(func);
      return next;
    });
  }, []);

  const toggleAll = useCallback(() => {
    if (selected.size === findings.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.function)));
    }
  }, [findings, selected.size]);

  const handleBulkTriage = useCallback(
    async (state: TriageState) => {
      if (!analysisId || selected.size === 0) return;
      setBulkSaving(true);
      try {
        await bulkTriage(analysisId, Array.from(selected), state);
        setSelected(new Set());
        onTriageUpdate?.();
      } catch (e) {
        console.error("Bulk triage failed:", e);
      } finally {
        setBulkSaving(false);
      }
    },
    [analysisId, selected, onTriageUpdate]
  );

  const columns = useMemo<ColumnDef<Finding>[]>(
    () => [
      ...(analysisId
        ? [
            {
              id: "select",
              header: () => (
                <input
                  type="checkbox"
                  checked={selected.size === findings.length && findings.length > 0}
                  onChange={toggleAll}
                  className="h-3.5 w-3.5 rounded border-gray-300"
                />
              ),
              cell: ({ row }: { row: { original: Finding } }) => (
                <input
                  type="checkbox"
                  checked={selected.has(row.original.function)}
                  onChange={(e) => {
                    e.stopPropagation();
                    toggleSelect(row.original.function);
                  }}
                  onClick={(e) => e.stopPropagation()}
                  className="h-3.5 w-3.5 rounded border-gray-300"
                />
              ),
              size: 36,
              enableSorting: false,
            } as ColumnDef<Finding>,
          ]
        : []),
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
      {
        id: "triage",
        header: "Triage",
        cell: ({ row }) => {
          const state = triageStates[row.original.function]?.state || "untriaged";
          if (state === "untriaged") {
            return (
              <span className="inline-block h-2 w-2 rounded-full bg-gray-300" title="Untriaged" />
            );
          }
          return (
            <span
              className={cn(
                "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
                triageBadge(state)
              )}
            >
              {triageLabel(state)}
            </span>
          );
        },
        size: 100,
        enableSorting: false,
      },
    ],
    [triageStates, analysisId, selected, findings.length, toggleAll, toggleSelect]
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

      {/* Batch triage action bar */}
      {selected.size > 0 && analysisId && (
        <div className="flex items-center gap-2 rounded-lg border border-blue-500/30 bg-blue-500/10 px-3 py-2">
          <span className="text-xs font-medium">
            {selected.size} selected
          </span>
          <span className="text-xs text-muted-foreground">|</span>
          {(
            [
              ["investigating", "Investigating", "bg-blue-600 hover:bg-blue-700 text-white"],
              ["confirmed", "Confirmed", "bg-red-600 hover:bg-red-700 text-white"],
              ["false_positive", "False Positive", "bg-yellow-600 hover:bg-yellow-700 text-white"],
              ["resolved", "Resolved", "bg-green-600 hover:bg-green-700 text-white"],
            ] as [TriageState, string, string][]
          ).map(([state, label, cls]) => (
            <button
              key={state}
              onClick={() => handleBulkTriage(state)}
              disabled={bulkSaving}
              className={cn(
                "rounded px-2 py-1 text-xs font-medium transition-colors",
                cls,
                bulkSaving && "opacity-50 cursor-not-allowed"
              )}
            >
              {label}
            </button>
          ))}
          <button
            onClick={() => setSelected(new Set())}
            className="ml-auto text-xs text-muted-foreground hover:text-foreground"
          >
            Clear
          </button>
        </div>
      )}

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
