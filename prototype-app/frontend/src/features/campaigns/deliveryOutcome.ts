import type { CampaignDeliveryAttempt } from './types';

// Router state the wizard hands to campaign detail after a successful create. It carries the
// delivery attempts the create response recorded, so detail can state what the server did at launch
// without re-reading attempts later events may have added.
export type CampaignLaunchState = {
  launchedDeliveries: CampaignDeliveryAttempt[];
};

export function readLaunchState(state: unknown): CampaignLaunchState | null {
  if (!state || typeof state !== 'object') return null;
  const deliveries = (state as Partial<CampaignLaunchState>).launchedDeliveries;
  return Array.isArray(deliveries) ? { launchedDeliveries: deliveries } : null;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

// Delivery states come from the server. QUEUED means accepted for sending, not delivered; the UI
// never upgrades it to "sent". Unknown states are reported by name rather than guessed.
export function deliveryStateLabel(state: string): string {
  const normalized = state.toUpperCase();
  if (normalized === 'QUEUED') return 'Queued';
  if (normalized === 'SKIPPED') return 'Skipped';
  if (normalized === 'SENT' || normalized === 'DELIVERED') return 'Sent';
  if (normalized === 'FAILED') return 'Failed';
  return normalized.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

export function summarizeDeliveries(attempts: CampaignDeliveryAttempt[]): string {
  if (attempts.length === 0) return 'No launch notifications were recorded.';
  const counts = new Map<string, number>();
  for (const attempt of attempts) {
    const label = deliveryStateLabel(attempt.deliveryState);
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const parts = Array.from(counts.entries()).map(([label, count]) => `${label.toLowerCase()} ${count}`);
  return `${plural(attempts.length, 'launch notification')} recorded: ${parts.join(', ')}.`;
}
