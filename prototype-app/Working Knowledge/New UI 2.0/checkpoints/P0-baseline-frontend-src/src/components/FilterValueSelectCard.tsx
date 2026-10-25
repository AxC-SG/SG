import React from 'react';

export type FilterValueOption = {
  value: string;
  label: string;
  tone?: 'critical' | 'high' | 'medium' | 'low' | 'neutral';
};

type Props = {
  label: string;
  selectedValues: string[];
  options: FilterValueOption[];
  onChange: (values: string[]) => void;
  onRemove?: () => void;
};

function toneBadgeLetter(tone: FilterValueOption['tone']): string {
  if (tone === 'critical') return 'C';
  if (tone === 'high') return 'H';
  if (tone === 'medium') return 'M';
  if (tone === 'low') return 'L';
  if (tone === 'neutral') return 'N';
  return '';
}

function summary(selectedValues: string[], options: FilterValueOption[]): string {
  if (selectedValues.length === 0) {
    return 'Any';
  }
  const selectedLabels = options
    .filter((item) => selectedValues.includes(item.value))
    .map((item) => item.label);
  if (selectedLabels.length <= 2) {
    return selectedLabels.join(', ');
  }
  return `${selectedLabels.slice(0, 2).join(', ')} +${selectedLabels.length - 2}`;
}

export function FilterValueSelectCard({ label, selectedValues, options, onChange, onRemove }: Props) {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState('');
  const rootRef = React.useRef<HTMLDivElement | null>(null);

  const selectedSet = React.useMemo(() => new Set(selectedValues), [selectedValues]);
  const searchTerm = search.trim().toLowerCase();
  const filtered = options.filter((item) => item.label.toLowerCase().includes(searchTerm));

  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent): void => {
      const target = event.target as Node | null;
      if (!target) return;
      if (!rootRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const onEscape = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onEscape);
    };
  }, [open]);

  const toggleValue = (value: string): void => {
    const next = new Set(selectedSet);
    if (next.has(value)) {
      next.delete(value);
    } else {
      next.add(value);
    }
    onChange(Array.from(next));
  };

  return (
    <div className={open ? 'filter-select-card open' : 'filter-select-card'} ref={rootRef}>
      <div className="filter-select-card-head">
        <span className="filter-select-label">{label}</span>
        {onRemove && (
          <button
            type="button"
            className="filter-select-remove"
            onClick={onRemove}
            aria-label={`Remove ${label} filter`}
          >
            x
          </button>
        )}
      </div>
      <button
        type="button"
        className="filter-select-trigger"
        onClick={() => setOpen((current) => !current)}
      >
        <span>{summary(selectedValues, options)}</span>
        <span className="filter-pill-chevron" aria-hidden="true">
          <svg viewBox="0 0 24 24">
            <path d="M6 9.5 12 15l6-5.5" />
          </svg>
        </span>
      </button>

      {open && (
        <div className="filter-select-menu">
          <div className="filter-dropdown-search-wrap">
            <span className="filter-dropdown-search-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <circle cx="10.5" cy="10.5" r="6.5" />
                <path d="m15.4 15.4 5.1 5.1" />
              </svg>
            </span>
            <input
              className="filter-dropdown-search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search..."
            />
          </div>

          <div className="filter-dropdown-actions">
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => onChange(options.map((item) => item.value))}>
              Select all
            </button>
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => onChange([])}>
              Clear
            </button>
          </div>

          <div className="filter-dropdown-options">
            {filtered.length === 0 && (
              <div className="filter-dropdown-empty">No options found.</div>
            )}
            {filtered.map((item) => {
              const selected = selectedSet.has(item.value);
              return (
                <button
                  key={item.value}
                  type="button"
                  className={selected ? 'filter-option-row selected' : 'filter-option-row'}
                  onClick={() => toggleValue(item.value)}
                >
                  <span className={selected ? 'filter-option-check checked' : 'filter-option-check'} aria-hidden="true">
                    {selected && (
                      <svg viewBox="0 0 24 24">
                        <path d="m5 12.5 4.2 4.1L19 7.8" />
                      </svg>
                    )}
                  </span>
                  {item.tone && (
                    <span className={`filter-option-badge ${item.tone}`} aria-hidden="true">
                      {toneBadgeLetter(item.tone)}
                    </span>
                  )}
                  <span className="filter-option-label">{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
