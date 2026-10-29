import React from 'react';

// Availability is supplied separately from the number: a valid zero renders 0, and missing data is never inferred to be zero.
export type MetricAvailability = 'available' | 'pending' | 'unavailable';

type Props = {
  availability: MetricAvailability;
  value?: number | null;
  format?: (value: number) => string;
  unavailableReason?: string;
};

export function MetricValue({ availability, value, format = (n) => n.toLocaleString(), unavailableReason = 'Unavailable' }: Props) {
  if (availability === 'pending') {
    return (
      <span className="metric-value metric-pending">
        <span aria-hidden="true">…</span>
        <span className="ui2-sr-only">Loading</span>
      </span>
    );
  }
  if (availability === 'unavailable' || value == null || !Number.isFinite(value)) {
    return (
      <span className="metric-value metric-unavailable" title={unavailableReason}>
        <span aria-hidden="true">—</span>
        <span className="ui2-sr-only">{unavailableReason}</span>
      </span>
    );
  }
  return <span className="metric-value">{format(value)}</span>;
}
