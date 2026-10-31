import React from 'react';

// Presentation-only queue controls. The feature owns filter semantics, paging and selection; these
// components only state them consistently. Server-side paging gaps belong to the feature (N05).

export type ActiveFilter = {
  key: string;
  label: string;
  value: string;
  onRemove: () => void;
};

export function ActiveFilterChips({
  filters,
  onClearAll,
  label = 'Active filters',
}: {
  filters: ActiveFilter[];
  onClearAll?: () => void;
  label?: string;
}) {
  if (filters.length === 0) return null;
  return (
    <div className="queue-filter-chips" role="group" aria-label={label}>
      {filters.map((filter) => (
        <span key={filter.key} className="queue-filter-chip">
          <span className="queue-filter-chip-label">{filter.label}:</span>
          <span className="queue-filter-chip-value">{filter.value}</span>
          <button
            type="button"
            className="queue-filter-chip-remove"
            onClick={filter.onRemove}
            aria-label={`Remove filter ${filter.label}: ${filter.value}`}
          >
            ×
          </button>
        </span>
      ))}
      {onClearAll && (
        <button type="button" className="btn btn-secondary btn-sm" onClick={onClearAll}>
          Clear filters
        </button>
      )}
    </div>
  );
}

type ResultScopeProps = {
  // Zero-based offset of the first row shown and the number of rows shown.
  offset: number;
  count: number;
  // Null when the source does not report a total; the label then says only what is shown.
  total: number | null;
  noun: string;
  pluralNoun?: string;
  filtered?: boolean;
  selectedCount?: number;
  selectionScope?: 'page' | 'all';
};

function resultScopeText({ offset, count, total, noun, pluralNoun, filtered = false }: ResultScopeProps): string {
  const plural = pluralNoun ?? `${noun}s`;
  const qualifier = filtered ? ' matching the filters' : '';
  if (count === 0) return `No ${plural}${qualifier}`;
  const range = `${(offset + 1).toLocaleString()}–${(offset + count).toLocaleString()}`;
  if (total == null) return `Showing ${range} ${plural}${qualifier}`;
  return `Showing ${range} of ${total.toLocaleString()} ${total === 1 ? noun : plural}${qualifier}`;
}

export function ResultScope(props: ResultScopeProps) {
  const { selectedCount = 0, selectionScope = 'page' } = props;
  return (
    <p className="queue-result-scope" role="status">
      <span>{resultScopeText(props)}</span>
      {selectedCount > 0 && (
        <span className="queue-result-selection">
          {` · ${selectedCount.toLocaleString()} selected${selectionScope === 'page' ? ' on this page' : ' across all pages'}`}
        </span>
      )}
    </p>
  );
}

export function Pager({
  page,
  totalPages,
  hasNext,
  onPrevious,
  onNext,
  disabled = false,
  label = 'Pagination',
}: {
  // Zero-based current page.
  page: number;
  // Null when the source does not report a page count.
  totalPages: number | null;
  // Cursor-paged sources say whether another page exists; this decides Next whenever it is given.
  hasNext?: boolean;
  onPrevious: () => void;
  onNext: () => void;
  disabled?: boolean;
  label?: string;
}) {
  const canNext = hasNext ?? (totalPages != null && page + 1 < totalPages);
  const pageLabel = totalPages == null ? `Page ${page + 1}` : `Page ${totalPages === 0 ? 0 : page + 1} of ${Math.max(totalPages, 1)}`;
  return (
    <nav className="pagination-row" aria-label={label}>
      <button type="button" className="btn btn-secondary" onClick={onPrevious} disabled={disabled || page <= 0}>
        Previous
      </button>
      <span className="panel-caption pagination-caption">{pageLabel}</span>
      <button type="button" className="btn btn-secondary" onClick={onNext} disabled={disabled || !canNext}>
        Next
      </button>
    </nav>
  );
}
