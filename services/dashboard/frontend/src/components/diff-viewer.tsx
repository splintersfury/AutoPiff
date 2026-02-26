interface DiffViewerProps {
  snippet: string;
  shaNew?: string;
  shaOld?: string;
}

function classifyLine(line: string): string {
  if (line.startsWith("@@")) return "diff-line-header";
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-line-header";
  if (line.startsWith("+")) return "diff-line-add";
  if (line.startsWith("-")) return "diff-line-remove";
  return "diff-line-context";
}

export function DiffViewer({ snippet, shaNew, shaOld }: DiffViewerProps) {
  if (!snippet) {
    return (
      <div className="rounded-lg border bg-muted/50 p-4 text-center">
        <p className="text-sm text-muted-foreground">No diff snippet available for this finding.</p>
        {(shaNew || shaOld) && (
          <div className="mt-2 flex items-center justify-center gap-3">
            <span className="text-xs text-muted-foreground">Download binaries to diff manually:</span>
            {shaOld && (
              <a
                href={`https://www.virustotal.com/gui/file/${shaOld}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded px-2 py-1 text-xs font-medium bg-blue-500/10 text-blue-600 hover:bg-blue-500/20 dark:text-blue-400 transition-colors"
              >
                Old (VT)
              </a>
            )}
            {shaNew && (
              <a
                href={`https://www.virustotal.com/gui/file/${shaNew}`}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded px-2 py-1 text-xs font-medium bg-blue-500/10 text-blue-600 hover:bg-blue-500/20 dark:text-blue-400 transition-colors"
              >
                New (VT)
              </a>
            )}
          </div>
        )}
      </div>
    );
  }

  const lines = snippet.split("\n");

  return (
    <div className="overflow-x-auto rounded-lg border">
      <pre className="text-xs leading-relaxed">
        <code>
          {lines.map((line, i) => (
            <div key={i} className={`px-4 py-0.5 ${classifyLine(line)}`}>
              {line || "\u00A0"}
            </div>
          ))}
        </code>
      </pre>
    </div>
  );
}
