// Ownership & Directory API types (ownership MVP plan §8, §9.1). Mirrors the backend records exactly.

export type OwnershipTeam = {
  id: string;
  name: string;
  parentTeamId: string | null;
  ticketAssignmentGroup: string | null;
  status: 'ACTIVE' | 'ARCHIVED';
  /** True when a notification email is stored; the address itself is never returned. */
  notificationChannel?: boolean;
  version: number;
};

export type OwnershipTeamRequest = {
  name?: string;
  parentTeamId?: string | null;
  ticketAssignmentGroup?: string | null;
  status?: 'ACTIVE' | 'ARCHIVED';
  /** Write-only: omitted or null keeps the stored address, blank clears it. */
  notificationEmail?: string | null;
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

/** Domains the hub can switch; AI_GRID is refused by the server. */
export type OwnershipSwitchDomain = 'CORE' | 'CLOUD_BOM';

export type OwnershipQualification = {
  domain: string;
  state: OwnershipAuthorityState;
  passed: boolean;
  blockers: string[];
  checks: Record<string, number>;
  comparison: { match: number; mismatch: number; legacyOnly: number; canonicalOnly: number; bothEmpty: number };
  reportHash: string;
};

// ── Identity sources (Phase 0B contract §1.1–§1.7) ───────────────────────────────────────────────────────────────

export type IdentitySourceState = 'DISABLED' | 'ENABLED' | 'PAUSED' | 'ERROR';

export type IdentitySourceTable = 'sys_user' | 'sys_user_group' | 'sys_user_grmember';

/** Credentials are write-only: the server reports only whether they exist. */
export type IdentitySource = {
  id: string;
  kind: 'MANUAL' | 'CSV' | 'SERVICENOW' | 'ENTRA' | 'OKTA';
  displayName: string;
  instanceUrl: string | null;
  authType: 'BASIC' | 'BEARER' | null;
  hasCredentials: boolean;
  filters: Partial<Record<IdentitySourceTable, string>>;
  schedule: string | null;
  state: IdentitySourceState;
  health: 'UNKNOWN' | 'HEALTHY' | 'DEGRADED' | 'FAILING';
  lastSuccessAt: string | null;
  lastError: string | null;
  version: number;
};

/** A null secret keeps the stored one; the server refuses that when the URL, auth type or username changes. */
export type IdentitySourceRequest = {
  displayName: string;
  instanceUrl: string;
  authType: 'BASIC' | 'BEARER';
  username: string | null;
  secret: string | null;
  filters: Partial<Record<IdentitySourceTable, string>>;
  schedule: string | null;
  version?: number;
};

export type IdentitySourceTableCheck = { table: IdentitySourceTable; outcome: 'READABLE' | 'DENIED'; rowCount: number | null };

export type IdentitySourceConnectionTest = {
  succeeded: boolean;
  failure: string | null;
  message: string;
  tables: IdentitySourceTableCheck[];
};

/** Samples carry full names and emails for tenant admins only (§1.6); they are shown, never stored. */
export type IdentitySourcePreview = {
  succeeded: boolean;
  failure: string | null;
  message: string;
  tables: Array<{ table: IdentitySourceTable; outcome: 'READABLE' | 'DENIED'; rowCount: number | null; samples: Array<Record<string, string>> }>;
  previewToken: string | null;
  expiresAt: string | null;
};

export type IdentitySourceSyncRequest = { runId: string; complete: boolean };

// ── Group-to-team mappings (Phase 0B contract §1.8) ──────────────────────────────────────────────────────────────

export type GroupTeamMapping = {
  id: string;
  externalGroupId: string;
  teamId: string;
  teamName: string;
  state: 'PROPOSED' | 'ACTIVE' | 'RETIRED';
  provenance: 'MANUAL' | 'CSV' | 'SUGGESTED';
  reason: string | null;
  actor: string;
  effectiveFrom: string;
  effectiveTo: string | null;
};

export type ExternalGroupRow = {
  externalGroupId: string;
  sourceId: string;
  sourceName: string;
  displayName: string;
  status: 'ACTIVE' | 'INACTIVE' | 'DELETED';
  active: GroupTeamMapping | null;
  suggestion: GroupTeamMapping | null;
};

export type GroupMappingImpact = {
  externalGroupId: string;
  currentTeamId: string | null;
  targetTeamId: string | null;
  sameInstance: boolean;
  affectedCis: number;
  affectedSubjects: number;
  openFindings: number;
  sampleSubjectIds: string[];
  largeChange: boolean;
  previewToken: string;
  expiresAt: string;
};

/** republishSkipped names why the affected CIs wait for the next CMDB sync, or is null. */
export type GroupMappingChange = { mapping: GroupTeamMapping; republishedCis: number; republishSkipped: string | null };

/** An AWS or GCP ownership producer as the Sources view shows it (Phase 0B §2.1, §2.2). */
export type CloudOwnershipSettings = {
  ownerKey: boolean;
  teamKey: boolean;
  accountInput: boolean;
  intervalMinutes: number | null;
};

export type CloudOwnershipSource = {
  provider: 'AWS' | 'GCP';
  deploymentEnabled: boolean;
  configured: boolean;
  domainState: OwnershipAuthorityState;
  paused: boolean;
  pauseReason: string | null;
  intervalValid: boolean;
  intervalMinutes: number | null;
  settings: CloudOwnershipSettings | null;
  accountTagsConfigured: boolean;
  activeClaims: number;
  openAnomalies: number;
};

export type CloudOwnershipSettingsRequest = {
  ownerKeyEnabled?: boolean;
  teamKeyEnabled?: boolean;
  accountInputEnabled?: boolean;
};

/** The AWS Organizations role for account tags (Phase 0B §2.2.1). The external ID is write-only. */
export type AwsOrganizationsRole = { configured: boolean; roleArn: string | null; externalIdSet: boolean };

export type AwsOrganizationsRoleTest = {
  succeeded: boolean;
  code: string | null;
  message: string;
  accountId: string | null;
  accountName: string | null;
};
