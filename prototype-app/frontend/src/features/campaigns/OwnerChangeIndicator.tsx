import type { CampaignMember } from './types';

/**
 * Owner movement since a member was added (Phase 0B §4.5). A change between two canonical owners is flagged; a member
 * that was pending migration and now has a canonical owner is a calm note, never a warning.
 */
export function OwnerChangeIndicator({ member }: { member: Pick<CampaignMember, 'ownershipChanged' | 'ownerAssignedSinceLaunch'> }) {
  if (member.ownershipChanged) {
    return <span className="status-pill status-open" title="The owner team differs from the owner recorded when the finding was added">Owner changed</span>;
  }
  if (member.ownerAssignedSinceLaunch) {
    return <span className="panel-caption">Owner assigned since launch</span>;
  }
  return null;
}
