import React from 'react';

type FreshnessValue = number | string | null | undefined;
function resolveTimestamp(value: FreshnessValue): number | null {
  if (value == null) {
    return null;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) && value > 0 ? value : null;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function formatTimestamp(value: FreshnessValue): string | null {
  const timestamp = resolveTimestamp(value);
  if (timestamp == null) {
    return null;
  }
  return new Date(timestamp).toLocaleString();
}

export function latestFreshnessValue(values: FreshnessValue[]): number | null {
  return values.reduce<number | null>((latest, value) => {
    const resolved = resolveTimestamp(value);
    if (resolved == null) {
      return latest;
    }
    return latest == null ? resolved : Math.max(latest, resolved);
  }, null);
}

export function PageFreshnessStatus({
  updatedAt,
  isRefreshing = false,
  delayedMessage,
  refreshLabel = 'Refreshing current view…',
}: {
  updatedAt?: FreshnessValue;
  isRefreshing?: boolean;
  delayedMessage?: string | null;
  refreshLabel?: string;
}) {
  const formatted = formatTimestamp(updatedAt);
  const statusText = isRefreshing
    ? formatted
      ? `${refreshLabel} Last updated ${formatted}.`
      : refreshLabel
    : formatted
      ? `Last updated ${formatted}`
      : null;

  if (!statusText && !delayedMessage) {
    return null;
  }

  return (
    <div style={{ marginBottom: 12 }}>
      {statusText ? (
        <div className="panel-caption" role="status" aria-live="polite" style={{ marginBottom: delayedMessage ? 8 : 0 }}>
          {statusText}
        </div>
      ) : null}
      {delayedMessage ? (
        <div className="notice warning" role="status" aria-live="polite">
          {delayedMessage}
        </div>
      ) : null}
    </div>
  );
}
