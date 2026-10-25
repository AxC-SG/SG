import React from 'react';

export type MultiGroupByOption = {
  key: string;
  label: string;
};

type Props = {
  options: MultiGroupByOption[];
  value: string[];
  onChange: (next: string[]) => void;
  label?: string;
  placeholder?: string;
  maxInlineSelections?: number;
  allowEmptyPrimary?: boolean;
  emptyPrimaryLabel?: string;
  showSelectorsByDefault?: boolean;
};

function summarize(
  selectedKeys: string[],
  optionMap: Map<string, MultiGroupByOption>,
  placeholder: string,
  maxInlineSelections: number
): string {
  if (selectedKeys.length === 0) {
    return placeholder;
  }
  if (selectedKeys.length > maxInlineSelections) {
    return `one of ${selectedKeys.length} options`;
  }
  const labels = selectedKeys
    .map((key) => optionMap.get(key)?.label)
    .filter((label): label is string => Boolean(label));
  return labels.join(' or ');
}

export function MultiGroupBy({
  options,
  value,
  onChange,
  label = 'GROUP BY',
  placeholder = 'Select...',
  maxInlineSelections = 3,
  allowEmptyPrimary = false,
  emptyPrimaryLabel = 'Select...',
  showSelectorsByDefault = true
}: Props) {
  const [primaryOpen, setPrimaryOpen] = React.useState(false);
  const [secondaryOpen, setSecondaryOpen] = React.useState(false);
  const [search, setSearch] = React.useState('');

  const rootRef = React.useRef<HTMLDivElement | null>(null);
  const optionMap = React.useMemo(() => new Map(options.map((option) => [option.key, option])), [options]);
  const normalizedKeys = React.useMemo(
    () => value.filter((key) => optionMap.has(key)),
    [value, optionMap]
  );
  const primaryKey = React.useMemo(
    () => {
      if (normalizedKeys[0]) {
        return normalizedKeys[0];
      }
      if (allowEmptyPrimary) {
        return '';
      }
      return options[0]?.key ?? '';
    },
    [normalizedKeys, allowEmptyPrimary, options]
  );
  const secondaryKeys = React.useMemo(
    () => normalizedKeys.slice(1).filter((key) => key !== primaryKey),
    [normalizedKeys, primaryKey]
  );
  const selectedSet = React.useMemo(() => new Set(secondaryKeys), [secondaryKeys]);
  const searchTerm = search.trim().toLowerCase();
  const secondaryOptions = React.useMemo(
    () => options.filter((option) => option.key !== primaryKey && option.label.toLowerCase().includes(searchTerm)),
    [options, primaryKey, searchTerm]
  );
  const secondarySummary = React.useMemo(
    () => summarize(secondaryKeys, optionMap, placeholder, maxInlineSelections),
    [secondaryKeys, optionMap, placeholder, maxInlineSelections]
  );
  const [selectorsVisible, setSelectorsVisible] = React.useState<boolean>(
    showSelectorsByDefault || normalizedKeys.length > 0
  );

  React.useEffect(() => {
    if (normalizedKeys.length > 0) {
      setSelectorsVisible(true);
    }
  }, [normalizedKeys.length]);

  React.useEffect(() => {
    if (!primaryOpen && !secondaryOpen) return;
    const onPointerDown = (event: MouseEvent): void => {
      const target = event.target as Node | null;
      if (!target) return;
      if (!rootRef.current?.contains(target)) {
        setPrimaryOpen(false);
        setSecondaryOpen(false);
      }
    };
    const onEscape = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        setPrimaryOpen(false);
        setSecondaryOpen(false);
      }
    };
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onEscape);
    };
  }, [primaryOpen, secondaryOpen]);

  React.useEffect(() => {
    if (options.length === 0) return;
    const normalized = primaryKey ? [primaryKey, ...secondaryKeys] : [];
    const current = value.filter((key) => optionMap.has(key));
    const sameLength = normalized.length === current.length;
    const sameValues = sameLength && normalized.every((key, index) => key === current[index]);
    if (!sameValues) {
      onChange(normalized);
      return;
    }
    if (!allowEmptyPrimary && normalized.length === 0) {
      onChange([options[0].key]);
    }
  }, [options, value, optionMap, onChange, allowEmptyPrimary, primaryKey, secondaryKeys]);

  React.useEffect(() => {
    if (!primaryKey) {
      setSecondaryOpen(false);
    }
  }, [primaryKey]);

  const onPrimarySelect = (nextPrimary: string): void => {
    if (!nextPrimary) {
      if (allowEmptyPrimary) {
        onChange([]);
      }
      setPrimaryOpen(false);
      return;
    }
    const nextSecondary = secondaryKeys.filter((key) => key !== nextPrimary);
    onChange([nextPrimary, ...nextSecondary]);
    setPrimaryOpen(false);
  };

  const toggleSecondary = (key: string): void => {
    if (!primaryKey || key === primaryKey) return;
    const next = new Set(secondaryKeys);
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
    }
    onChange([primaryKey, ...Array.from(next)]);
  };

  return (
    <div className="multi-groupby" ref={rootRef}>
      <div className="multi-groupby-label">{label}</div>

      {!selectorsVisible ? (
        <button
          type="button"
          className="multi-groupby-trigger"
          onClick={() => {
            setSelectorsVisible(true);
            setPrimaryOpen(true);
          }}
        >
          <span>{emptyPrimaryLabel}</span>
          <span className="filter-pill-chevron" aria-hidden="true">
            <svg viewBox="0 0 24 24">
              <path d="M6 9.5 12 15l6-5.5" />
            </svg>
          </span>
        </button>
      ) : (
        <div className="multi-groupby-select">
          <button
            type="button"
            className={primaryOpen ? 'multi-groupby-trigger active' : 'multi-groupby-trigger'}
            onClick={() => {
              setPrimaryOpen((current) => !current);
              setSecondaryOpen(false);
            }}
          >
            <span>{primaryKey ? optionMap.get(primaryKey)?.label ?? emptyPrimaryLabel : emptyPrimaryLabel}</span>
            <span className="filter-pill-chevron" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M6 9.5 12 15l6-5.5" />
              </svg>
            </span>
          </button>

          {primaryOpen && (
            <div className="multi-groupby-menu">
              <div className="multi-groupby-options">
                {allowEmptyPrimary && (
                  <button
                    type="button"
                    className={!primaryKey ? 'multi-groupby-option selected' : 'multi-groupby-option'}
                    onClick={() => onPrimarySelect('')}
                  >
                    {emptyPrimaryLabel}
                  </button>
                )}
                {options.map((option) => (
                  <button
                    key={option.key}
                    type="button"
                    className={option.key === primaryKey ? 'multi-groupby-option selected' : 'multi-groupby-option'}
                    onClick={() => onPrimarySelect(option.key)}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {primaryKey && (
        <div className="multi-groupby-select">
          <button
            type="button"
            className={secondaryOpen ? 'multi-groupby-trigger active' : 'multi-groupby-trigger'}
            onClick={() => {
              setSecondaryOpen((current) => !current);
              setPrimaryOpen(false);
            }}
          >
            <span>{secondarySummary}</span>
            <span className="filter-pill-chevron" aria-hidden="true">
              <svg viewBox="0 0 24 24">
                <path d="M6 9.5 12 15l6-5.5" />
              </svg>
            </span>
          </button>

          {secondaryOpen && (
            <div className="multi-groupby-menu multi-groupby-menu-wide">
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

              <div className="multi-groupby-options">
                {secondaryOptions.length === 0 && (
                  <div className="filter-dropdown-empty">No options found.</div>
                )}
                {secondaryOptions.map((option) => (
                  <button
                    key={option.key}
                    type="button"
                    className={selectedSet.has(option.key) ? 'multi-groupby-option selected' : 'multi-groupby-option'}
                    onClick={() => toggleSecondary(option.key)}
                  >
                    <span className={selectedSet.has(option.key) ? 'filter-option-check checked' : 'filter-option-check'} aria-hidden="true">
                      {selectedSet.has(option.key) && (
                        <svg viewBox="0 0 24 24">
                          <path d="m5 12.5 4.2 4.1L19 7.8" />
                        </svg>
                      )}
                    </span>
                    <span>{option.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
