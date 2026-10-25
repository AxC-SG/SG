import React from 'react';

export type ColumnDef = {
  key: string;
  label: string;
  defaultVisible: boolean;
};

type Props = {
  columns: ColumnDef[];
  visible: Set<string>;
  onChange: (visible: Set<string>) => void;
};

export function ColumnVisibilityToggle({ columns, visible, onChange }: Props) {
  const [open, setOpen] = React.useState(false);
  const containerRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    function handleOutsideClick(event: MouseEvent): void {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, [open]);

  function toggle(key: string): void {
    const next = new Set(visible);
    if (next.has(key)) {
      // always keep at least one column visible
      if (next.size > 1) next.delete(key);
    } else {
      next.add(key);
    }
    onChange(next);
  }

  function resetToDefaults(): void {
    onChange(new Set(columns.filter((c) => c.defaultVisible).map((c) => c.key)));
  }

  const hiddenCount = columns.filter((c) => !visible.has(c.key)).length;

  return (
    <div className="col-toggle" ref={containerRef}>
      <button
        type="button"
        className={`btn btn-secondary btn-inline col-toggle-btn${hiddenCount > 0 ? ' col-toggle-btn--active' : ''}`}
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-label="Show or hide columns"
      >
        <svg viewBox="0 0 16 16" width="14" height="14" fill="none" aria-hidden="true">
          <rect x="1" y="3" width="14" height="2" rx="1" fill="currentColor" />
          <rect x="1" y="7" width="14" height="2" rx="1" fill="currentColor" />
          <rect x="1" y="11" width="14" height="2" rx="1" fill="currentColor" />
          <rect x="10" y="1.5" width="2" height="5" rx="1" fill="currentColor" />
          <rect x="4" y="5.5" width="2" height="5" rx="1" fill="currentColor" />
          <rect x="10" y="9.5" width="2" height="5" rx="1" fill="currentColor" />
        </svg>
        Columns{hiddenCount > 0 ? ` (${hiddenCount} hidden)` : ''}
      </button>

      {open && (
        <div className="col-toggle-dropdown">
          <div className="col-toggle-dropdown-header">
            <span>Visible Columns</span>
            <button type="button" className="col-toggle-reset" onClick={resetToDefaults}>
              Reset
            </button>
          </div>
          <div className="col-toggle-list">
            {columns.map((col) => (
              <label key={col.key} className="col-toggle-item">
                <input
                  type="checkbox"
                  checked={visible.has(col.key)}
                  onChange={() => toggle(col.key)}
                />
                <span>{col.label}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
