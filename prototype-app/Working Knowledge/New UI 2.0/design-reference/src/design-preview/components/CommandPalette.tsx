import React from 'react';
import { CornerDownLeft, Search } from 'lucide-react';

export type Command = { id: string; group: string; label: string; hint?: string; run: () => void };

export function CommandPalette({ open, onClose, commands }: { open: boolean; onClose: () => void; commands: Command[] }) {
  const [query, setQuery] = React.useState('');
  const [cursor, setCursor] = React.useState(0);

  React.useEffect(() => {
    if (open) {
      setQuery('');
      setCursor(0);
    }
  }, [open]);

  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter((command) => {
      // Every typed term must appear, so "kev find" matches "Findings · Known exploited (KEV)".
      const hay = `${command.group} ${command.label}`.toLowerCase();
      return q.split(/\s+/).every((term) => hay.includes(term));
    });
  }, [commands, query]);

  if (!open) return null;

  const runAt = (index: number) => {
    const command = filtered[index];
    if (!command) return;
    command.run();
    onClose();
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') onClose();
    if (event.key === 'ArrowDown') { event.preventDefault(); setCursor((c) => Math.min(filtered.length - 1, c + 1)); }
    if (event.key === 'ArrowUp') { event.preventDefault(); setCursor((c) => Math.max(0, c - 1)); }
    if (event.key === 'Enter') { event.preventDefault(); runAt(cursor); }
  };

  return (
    <div className="dp-palette-root" onKeyDown={onKeyDown}>
      <div className="dp-scrim visible" onClick={onClose} />
      <div className="dp-palette" role="dialog" aria-label="Command palette">
        <div className="dp-palette-input">
          <Search size={16} />
          <input
            autoFocus
            value={query}
            placeholder="Search pages, saved views, CVEs, actions…"
            onChange={(event) => { setQuery(event.target.value); setCursor(0); }}
          />
          <kbd>esc</kbd>
        </div>
        <div className="dp-palette-list">
          {filtered.length === 0 ? <div className="dp-palette-empty">No results for “{query}”</div> : null}
          {filtered.map((command, index) => {
            const header = index === 0 || filtered[index - 1].group !== command.group ? command.group : null;
            return (
              <React.Fragment key={command.id}>
                {header ? <div className="dp-palette-group">{header}</div> : null}
                <button
                  type="button"
                  className={`dp-palette-item${index === cursor ? ' active' : ''}`}
                  onMouseEnter={() => setCursor(index)}
                  onClick={() => runAt(index)}
                >
                  <span>{command.label}</span>
                  {command.hint ? <kbd>{command.hint}</kbd> : null}
                  {index === cursor ? <CornerDownLeft size={13} className="dp-ml-auto dp-muted" /> : null}
                </button>
              </React.Fragment>
            );
          })}
        </div>
        <div className="dp-palette-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> navigate</span>
          <span><kbd>↵</kbd> open</span>
          <span><kbd>⌘K</kbd> toggle</span>
        </div>
      </div>
    </div>
  );
}
