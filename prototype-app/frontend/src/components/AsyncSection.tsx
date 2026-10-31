import React from 'react';

// Presentation-only: the feature decides the state from its own queries and supplies truthful copy.
// A parent never hides an independent section's failure; each widget gets its own AsyncSection.
export type AsyncSectionState = 'pending' | 'ready' | 'empty' | 'filtered-empty' | 'error' | 'unavailable';

type Props = {
  state: AsyncSectionState;
  children?: React.ReactNode;
  loadingLabel?: string;
  emptyTitle?: string;
  emptyMessage?: React.ReactNode;
  filteredEmptyMessage?: React.ReactNode;
  onClearFilters?: () => void;
  errorMessage?: React.ReactNode;
  unavailableMessage?: React.ReactNode;
  onRetry?: () => void;
  retryLabel?: string;
  retrying?: boolean;
  // Cached data stays visible when a background refresh fails or the data is known to be stale.
  refreshError?: React.ReactNode;
  staleMessage?: React.ReactNode;
  isRefreshing?: boolean;
};

function RetryButton({ onRetry, retryLabel, retrying }: Pick<Props, 'onRetry' | 'retryLabel' | 'retrying'>) {
  if (!onRetry) return null;
  return (
    <button type="button" className="btn btn-sm" disabled={retrying} onClick={onRetry}>
      {retrying ? 'Retrying…' : retryLabel ?? 'Retry'}
    </button>
  );
}

export function AsyncSection({
  state,
  children,
  loadingLabel = 'Loading…',
  emptyTitle,
  emptyMessage = 'Nothing to show yet.',
  filteredEmptyMessage = 'No results match the current filters.',
  onClearFilters,
  errorMessage = 'This section could not be loaded.',
  unavailableMessage = 'This information is currently unavailable.',
  onRetry,
  retryLabel,
  retrying = false,
  refreshError,
  staleMessage,
  isRefreshing = false,
}: Props) {
  if (state === 'pending') {
    return <p className="muted async-section-pending" role="status">{loadingLabel}</p>;
  }
  if (state === 'error') {
    return (
      <div className="notice error async-section-notice" role="alert">
        <span>{errorMessage}</span>
        <RetryButton onRetry={onRetry} retryLabel={retryLabel} retrying={retrying} />
      </div>
    );
  }
  if (state === 'unavailable') {
    return <div className="notice warning async-section-notice" role="status">{unavailableMessage}</div>;
  }
  if (state === 'empty') {
    return (
      <div className="empty-state" role="status">
        {emptyTitle ? <strong>{emptyTitle}</strong> : null}
        <p>{emptyMessage}</p>
      </div>
    );
  }
  if (state === 'filtered-empty') {
    return (
      <div className="empty-state async-section-notice" role="status">
        <p>{filteredEmptyMessage}</p>
        {onClearFilters ? <button type="button" className="btn btn-sm" onClick={onClearFilters}>Clear filters</button> : null}
      </div>
    );
  }
  return (
    <>
      {refreshError ? (
        <div className="notice warning async-section-notice" role="status">
          <span>{refreshError}</span>
          <RetryButton onRetry={onRetry} retryLabel={retryLabel} retrying={retrying} />
        </div>
      ) : staleMessage ? (
        <div className="notice warning async-section-notice" role="status">{staleMessage}</div>
      ) : null}
      {isRefreshing ? <span className="ui2-sr-only" role="status">Refreshing…</span> : null}
      {children}
    </>
  );
}
