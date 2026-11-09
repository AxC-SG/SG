/**
 * Resolved-ownership envelope returned beside raw inventory evidence (ownership MVP plan §7.5, §9.3, §9.4).
 * Mirrors the backend `OwnershipReadAdapter.Summary`. `authorityState` is `CANONICAL` once the row's migration
 * domain has switched; until then it is `LEGACY_PENDING_MIGRATION` and only `legacyOwnerLabel` is set.
 */
export type ResolvedOwnership = {
  objectId: string;
  authorityDomain: 'CORE' | 'CLOUD_BOM' | 'AI_GRID' | string;
  authorityState: 'CANONICAL' | 'LEGACY_PENDING_MIGRATION' | string;
  subjectId?: string | null;
  ownerTeamId?: string | null;
  ownerTeamName?: string | null;
  /** OWNED, UNOWNED or CONFLICT; null while a linked row's cached result is still being computed. */
  ownershipStatus?: 'OWNED' | 'UNOWNED' | 'CONFLICT' | string | null;
  originSubjectId?: string | null;
  assignmentId?: string | null;
  sourceKind?: string | null;
  resolvedAt?: string | null;
  stale?: boolean | null;
  inheritanceDepth?: number | null;
  legacyOwnerLabel?: string | null;
};

export function isCanonicalOwnership(ownership: ResolvedOwnership | null | undefined): ownership is ResolvedOwnership {
  return ownership?.authorityState === 'CANONICAL';
}

/** Display label for a canonical envelope; never a raw CMDB/cloud value. */
export function resolvedOwnerLabel(ownership: ResolvedOwnership): string {
  switch (ownership.ownershipStatus) {
    case 'OWNED':
      return ownership.ownerTeamName ?? 'Unknown team';
    case 'CONFLICT':
      return 'Ownership conflict';
    case 'UNOWNED':
      return 'Unowned';
    default:
      return 'Refreshing ownership';
  }
}

/** True when a canonical envelope has no single accountable team (Unowned, Conflict or not yet computed). */
export function lacksResolvedOwner(ownership: ResolvedOwnership): boolean {
  return ownership.ownershipStatus !== 'OWNED';
}

export function ownershipAssignmentKind(ownership: ResolvedOwnership): string | undefined {
  if (ownership.inheritanceDepth == null || ownership.ownershipStatus !== 'OWNED') return undefined;
  return ownership.inheritanceDepth === 0 ? 'Direct' : `Inherited (${ownership.inheritanceDepth} level${ownership.inheritanceDepth === 1 ? '' : 's'} up)`;
}
