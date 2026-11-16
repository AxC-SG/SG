import type { CampaignOwnership } from './types';

/** One owner bucket of a campaign or PQC wave (Phase 0B §4.5): a team by ID, or Unowned, Conflict or Pending Migration. */
export type OwnerBucket = {
  bucket: 'TEAM' | 'UNOWNED' | 'CONFLICT' | 'PENDING_MIGRATION' | 'NOT_RECORDED' | string;
  teamId: string | null;
  teamName: string | null;
  members: number;
  activeRemaining: number;
  outcomes: Record<string, number>;
};

/** Label for an owner bucket; team names are joined by the server, so a rename changes only this label. */
export function ownerBucketLabel(bucket: Pick<OwnerBucket, 'bucket' | 'teamName'>): string {
  switch (bucket.bucket) {
    case 'TEAM': return bucket.teamName ?? 'Owned';
    case 'UNOWNED': return 'Unowned';
    case 'CONFLICT': return 'Conflict';
    case 'NOT_RECORDED': return 'Not recorded';
    default: return 'Pending migration';
  }
}

/**
 * Display label for a campaign member's current owner (Phase 0B §4.5): the team name when canonical, Unowned or
 * Conflict otherwise, and the legacy label while the campaigns read wave is off. Team names are joined by the server.
 */
export function campaignOwnerLabel(ownership: CampaignOwnership | null | undefined): string {
  if (!ownership || ownership.authorityState !== 'CANONICAL') return ownership?.legacyOwnerLabel ?? 'Pending migration';
  if (ownership.ownershipStatus === 'OWNED') return ownership.ownerTeamName ?? 'Owned';
  return ownership.ownershipStatus === 'CONFLICT' ? 'Conflict' : 'Unowned';
}
