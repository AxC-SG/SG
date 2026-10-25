import React from 'react';

type EolBadgeProps = {
  isEol?: boolean | null;
  daysRemaining?: number | null;
  eolDate?: string | null;
  onClick?: () => void;
};

/**
 * Displays end-of-life status as a coloured pill badge.
 *
 * Colours:
 *   EOL (past)       → red
 *   ≤30 days         → orange
 *   ≤90 days         → yellow
 *   >90 days         → green
 *   unknown/no data  → grey
 */
export function EolBadge({ isEol, daysRemaining, eolDate, onClick }: EolBadgeProps) {
  const label = resolveLabel(isEol, daysRemaining);
  const className = resolveClass(isEol, daysRemaining);
  const title = resolveTitle(isEol, daysRemaining, eolDate);

  if (onClick) {
    return (
      <button
        type="button"
        className={`eol-badge ${className} eol-badge-btn`}
        title={title}
        onClick={onClick}
      >
        {label}
      </button>
    );
  }

  return (
    <span className={`eol-badge ${className}`} title={title}>
      {label}
    </span>
  );
}

function resolveLabel(isEol?: boolean | null, daysRemaining?: number | null): string {
  if (isEol === true) {
    return 'EOL';
  }
  if (isEol === false && daysRemaining != null) {
    if (daysRemaining <= 90) {
      return `EOL in ${daysRemaining}d`;
    }
    return 'Supported';
  }
  return 'Unknown';
}

function resolveClass(isEol?: boolean | null, daysRemaining?: number | null): string {
  if (isEol === true) {
    return 'eol-badge-eol';
  }
  if (isEol === false && daysRemaining != null) {
    if (daysRemaining <= 30) {
      return 'eol-badge-critical';
    }
    if (daysRemaining <= 90) {
      return 'eol-badge-warn';
    }
    return 'eol-badge-ok';
  }
  return 'eol-badge-unknown';
}

function resolveTitle(isEol?: boolean | null, daysRemaining?: number | null, eolDate?: string | null): string {
  if (isEol === true) {
    return eolDate ? `End of life: ${eolDate}` : 'This product has reached end of life';
  }
  if (isEol === false && daysRemaining != null) {
    if (eolDate) {
      return `EOL date: ${eolDate} (${daysRemaining} days remaining)`;
    }
    return `${daysRemaining} days until end of life`;
  }
  return 'EOL status unknown — no matching endoflife.date entry found';
}
