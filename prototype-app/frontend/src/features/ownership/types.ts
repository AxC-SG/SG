// Ownership & Directory API types (ownership MVP plan §8, §9.1). Mirrors the backend records exactly.

export type OwnershipTeam = {
  id: string;
  name: string;
  parentTeamId: string | null;
  ticketAssignmentGroup: string | null;
  status: 'ACTIVE' | 'ARCHIVED';
  version: number;
};

export type OwnershipTeamRequest = {
  name?: string;
  parentTeamId?: string | null;
  ticketAssignmentGroup?: string | null;
  status?: 'ACTIVE' | 'ARCHIVED';
  version?: number;
};

export type OwnershipTeamAlias = {
  id: string;
  teamId: string;
  alias: string;
  sourceKind: string;
  sourceId: string | null;
};

/** Directory people are always returned masked; plaintext email/employee ID never reach the browser. */
export type DirectoryPerson = {
  id: string;
  displayName: string;
  emailMasked: string | null;
  employeeIdMasked: string | null;
  managerUserId: string | null;
  status: 'ACTIVE' | 'INACTIVE';
  version: number;
};

export type DirectoryPersonCreate = {
  displayName: string;
  email?: string;
  employeeId?: string;
};

export type DirectoryPersonUpdate = {
  status?: 'ACTIVE' | 'INACTIVE';
  version: number;
};

export type DirectoryGroup = {
  id: string;
  displayName: string;
  status: 'ACTIVE' | 'INACTIVE';
  version: number;
};

export type DirectoryMembership = {
  groupId: string;
  userId: string;
  sourceId: string | null;
  status: 'ACTIVE' | 'REMOVED';
};

export type DirectoryImportKind = 'USERS' | 'GROUPS' | 'MEMBERSHIPS' | 'TEAMS' | 'TEAM_ALIASES';

export type DirectoryImportOutcome = 'CREATE' | 'UPDATE' | 'UNCHANGED' | 'DUPLICATE' | 'AMBIGUOUS' | 'REJECTED';

export type DirectoryImportRow = { row: number; outcome: DirectoryImportOutcome; message: string | null };

export type DirectoryImportReport = {
  /** For a preview this is the dry-run token the commit must quote. */
  runId: string;
  kind: DirectoryImportKind;
  state: string;
  counts: Partial<Record<DirectoryImportOutcome, number>>;
  rows: DirectoryImportRow[];
  warnings: DirectoryImportRow[];
};

export type OwnershipReviewType =
  | 'UNMAPPED_VALUE'
  | 'AMBIGUOUS_IDENTITY'
  | 'CONFLICT'
  | 'INACTIVE_OWNER'
  | 'INHERITANCE_ERROR'
  | 'PRODUCER_ANOMALY';

export type OwnershipReviewItem = {
  id: string;
  itemType: OwnershipReviewType;
  subjectId: string | null;
  sourceKind: string | null;
  /** JSON object of stable IDs and counts; never names or unresolved personal values. */
  details: string | null;
  state: 'OPEN' | 'RESOLVED' | 'DISMISSED';
  occurrenceCount: number;
  firstSeenAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  resolvedBy: string | null;
};

export type OwnershipCoverage = {
  authorityState: 'CANONICAL' | 'LEGACY_PENDING_MIGRATION';
  owned: number;
  unowned: number;
  conflict: number;
  unlinked: number;
  refreshing: number;
};

export type OwnershipEncryptionStatus = { ready: boolean; reason: string | null };

export type OwnershipAuthorityState = 'LEGACY' | 'DARK' | 'CANONICAL';

export type OwnershipQualification = {
  domain: string;
  state: OwnershipAuthorityState;
  passed: boolean;
  blockers: string[];
  checks: Record<string, number>;
  comparison: { match: number; mismatch: number; legacyOnly: number; canonicalOnly: number; bothEmpty: number };
  reportHash: string;
};
