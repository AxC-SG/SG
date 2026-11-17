import type { TicketRoutingSource } from '../connect/types';
import type { FindingTicketAttempt } from '../cbom/types';
import type { OwnershipSummary } from '../../types/ownership';

export const MAX_OVERRIDE_REASON = 500;

export function routingSourceLabel(source: TicketRoutingSource | FindingTicketAttempt['routingSource'] | null | undefined): string {
  switch (source) {
    case 'TEAM_MAPPING': return 'Team mapping';
    case 'TENANT_DEFAULT': return 'Tenant default group';
    case 'USER_SELECTED': return 'Selected by a user';
    case 'OVERRIDE': return 'Override';
    case 'LEGACY': return 'Existing routing';
    default: return 'Not recorded';
  }
}

/**
 * True when the owner team changed after the latest successful ticket was raised. Only canonical values on both sides
 * count: a legacy attempt or a pending-migration finding never produces a note (Phase 0B §4.9).
 */
export function ownerChangedSinceTicket(
  attempts: FindingTicketAttempt[] | undefined,
  ownership: Pick<OwnershipSummary, 'authorityState' | 'ownershipStatus' | 'ownerTeamId'> | undefined,
): boolean {
  if (ownership?.authorityState !== 'CANONICAL' || ownership.ownershipStatus !== 'OWNED' || !ownership.ownerTeamId) return false;
  const latest = (attempts ?? [])
    .filter((attempt) => attempt.outcome === 'SUCCEEDED')
    .sort((a, b) => b.attemptedAt.localeCompare(a.attemptedAt))[0];
  return !!latest?.ownerTeamId && latest.ownerTeamId !== ownership.ownerTeamId;
}
