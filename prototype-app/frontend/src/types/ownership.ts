export type OwnershipAuthority =
  | 'NONE'
  | 'LEGACY'
  | 'SOURCE_DERIVED'
  | 'SOURCE_PROVIDED'
  | 'CMDB'
  | string;

export type OwnershipSummary = {
  displayName: string;
  ownerTeam?: string;
  ownerEmail?: string;
  managedBy?: string;
  department?: string;
  supportGroup?: string;
  assignedTo?: string;
  sourceSystem?: string;
  sourceType?: string;
  authority?: OwnershipAuthority;
  updatedAt?: string;
  /**
   * Ownership compatibility keys (ownership MVP plan §7.5, §15.4). `CANONICAL` rows carry the resolved team and status;
   * `LEGACY_PENDING_MIGRATION` rows show the legacy display and must never be reported as Unowned.
   */
  authorityState?: 'CANONICAL' | 'LEGACY_PENDING_MIGRATION' | string;
  authorityDomain?: string;
  ownershipStatus?: 'OWNED' | 'UNOWNED' | 'CONFLICT' | string;
  ownerTeamId?: string;
  assignmentId?: string;
  stale?: string;
  inheritanceDepth?: string;
};
