import type { CampaignOwnership } from './types';

/**
 * Display label for a campaign member's current owner (Phase 0B §4.5): the team name when canonical, Unowned or
 * Conflict otherwise, and the legacy label while the campaigns read wave is off. Team names are joined by the server.
 */
export function campaignOwnerLabel(ownership: CampaignOwnership | null | undefined): string {
  if (!ownership || ownership.authorityState !== 'CANONICAL') return ownership?.legacyOwnerLabel ?? 'Pending migration';
  if (ownership.ownershipStatus === 'OWNED') return ownership.ownerTeamName ?? 'Owned';
  return ownership.ownershipStatus === 'CONFLICT' ? 'Conflict' : 'Unowned';
}
