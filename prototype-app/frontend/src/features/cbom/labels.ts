/** Presentation helpers for CBOM visibility. Pure; no data access. */

export function titleCase(value: string | null | undefined): string {
  if (!value) return '—';
  const words = value.toLowerCase().replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function severityBadgeClass(severity: string | null | undefined): string {
  const value = (severity ?? '').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(value) ? `status-badge--${value}` : 'status-badge--info';
}

export function percent(value: number | null | undefined): string {
  return value == null ? '—' : `${Math.round(value * 100)}%`;
}

/** Diff outcome copy. Remediation, omission, withdrawal and accepted risk must never read alike. */
export const FINDING_OUTCOMES: Record<string, { label: string; description: string }> = {
  REMEDIATED: { label: 'Remediated', description: 'The component is still declared and the unsafe condition is gone.' },
  NOT_OBSERVED: { label: 'Not observed', description: 'The new document omitted the component; this is not proof of remediation.' },
  WITHDRAWN: { label: 'Withdrawn', description: 'The source evidence was superseded or deleted.' },
  ACCEPTED_RISK: { label: 'Accepted risk', description: 'The condition remains under a valid suppression.' },
  PERSISTING: { label: 'Still open', description: 'The condition is present in both documents.' },
  INTRODUCED: { label: 'Introduced', description: 'The condition is new in this document.' },
  AMBIGUOUS: { label: 'Ambiguous match', description: 'The component identity matched more than one asset, so no outcome is guessed.' },
};

export const COMPONENT_CHANGES: Record<string, string> = {
  ADDED: 'Added',
  NOT_OBSERVED: 'Not observed',
  CHANGED: 'Changed',
};

/** Claim assurance (how strongly a claim is verified) is distinct from evidence presence. */
export function assuranceLabel(level: string): string {
  return `Assurance: ${titleCase(level)}`;
}

export function presenceLabel(state: string | null | undefined): string {
  return `Evidence: ${titleCase(state)}`;
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function newIdempotencyKey(prefix: string): string {
  const random = typeof crypto !== 'undefined' && 'randomUUID' in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return `${prefix}-${random}`;
}
