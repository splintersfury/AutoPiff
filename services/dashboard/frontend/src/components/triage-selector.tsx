"use client";

import { useState } from "react";
import { setTriageState } from "@/lib/api";
import { cn, triageBadge, triageLabel } from "@/lib/utils";
import type { TriageState } from "@/types";

const STATES: TriageState[] = [
  "untriaged",
  "investigating",
  "confirmed",
  "false_positive",
  "resolved",
];

interface TriageSelectorProps {
  analysisId: string;
  functionName: string;
  currentState: TriageState;
  currentNote: string;
}

export function TriageSelector({
  analysisId,
  functionName,
  currentState,
  currentNote,
}: TriageSelectorProps) {
  const [state, setState] = useState<TriageState>(currentState);
  const [note, setNote] = useState(currentNote);
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(false);

  const handleSelect = async (newState: TriageState) => {
    setSaving(true);
    try {
      await setTriageState(analysisId, functionName, newState, note);
      setState(newState);
      setOpen(false);
    } catch (e) {
      console.error("Failed to update triage state:", e);
    } finally {
      setSaving(false);
    }
  };

  const handleNoteSubmit = async () => {
    if (state === "untriaged") return;
    setSaving(true);
    try {
      await setTriageState(analysisId, functionName, state, note);
    } catch (e) {
      console.error("Failed to save note:", e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <span className="text-xs font-medium text-muted-foreground">
          Triage:
        </span>
        <div className="relative">
          <button
            onClick={() => setOpen(!open)}
            className={cn(
              "rounded-full px-3 py-1 text-xs font-medium transition-colors",
              triageBadge(state),
              saving && "opacity-50"
            )}
            disabled={saving}
          >
            {triageLabel(state)}
          </button>
          {open && (
            <div className="absolute left-0 top-full z-10 mt-1 w-40 rounded-lg border bg-card shadow-lg">
              {STATES.map((s) => (
                <button
                  key={s}
                  onClick={() => handleSelect(s)}
                  className={cn(
                    "flex w-full items-center gap-2 px-3 py-2 text-left text-xs transition-colors hover:bg-muted/50",
                    s === state && "font-medium"
                  )}
                >
                  <span
                    className={cn(
                      "inline-block h-2 w-2 rounded-full",
                      s === "untriaged" && "bg-gray-400",
                      s === "investigating" && "bg-blue-500",
                      s === "confirmed" && "bg-red-500",
                      s === "false_positive" && "bg-yellow-500",
                      s === "resolved" && "bg-green-500"
                    )}
                  />
                  {triageLabel(s)}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
      {state !== "untriaged" && (
        <div className="flex gap-2">
          <input
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            onBlur={handleNoteSubmit}
            onKeyDown={(e) => e.key === "Enter" && handleNoteSubmit()}
            placeholder="Add a note..."
            className="flex-1 rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>
      )}
    </div>
  );
}
