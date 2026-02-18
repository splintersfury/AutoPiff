interface DiffViewerProps {
  snippet: string;
}

function classifyLine(line: string): string {
  if (line.startsWith("@@")) return "diff-line-header";
  if (line.startsWith("+++") || line.startsWith("---")) return "diff-line-header";
  if (line.startsWith("+")) return "diff-line-add";
  if (line.startsWith("-")) return "diff-line-remove";
  return "diff-line-context";
}

export function DiffViewer({ snippet }: DiffViewerProps) {
  if (!snippet) {
    return (
      <div className="rounded-lg border bg-muted/50 p-4 text-sm text-muted-foreground">
        No diff available
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
