import type { OwnerBucket } from './ownership';

export type CampaignStatus =
  | 'DRAFT'
  | 'ACTIVE'
  | 'PAUSED'
  | 'BLOCKED'
  | 'IN_REVIEW'
  | 'CLOSED'
  | 'CANCELLED';

export type CampaignWatchlistEntryType = 'USER' | 'GROUP';

export type CampaignRecipientType = 'TEAM' | 'CUSTOM';

/** Phase 0B §4.6: TEAM recipients use the team's channel; CUSTOM recipients are never owner recipients. */
export type CampaignNotifyGroup = {
  id: string;
  recipientType: CampaignRecipientType;
  teamId: string | null;
  groupName: string;
  groupEmail: string | null;
  channelConfigured: boolean;
  ownerRecipient: boolean;
  roleLabel: string | null;
  triggerSummary: string | null;
  notificationsPaused: boolean;
};

export type CampaignWatchlistEntry = {
  id: string;
  entryType: CampaignWatchlistEntryType;
  label: string;
  email: string | null;
  triggerPolicy: string | null;
  active: boolean;
};

export type CampaignVulnerability = {
  externalId: string;
  title: string | null;
  severity: string | null;
};

export type CampaignNote = {
  id: string;
  author: string;
  body: string;
  createdAt: string;
};

export type CampaignExceptionStatus =
  | 'PENDING_DECISION'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXPIRED';

export type CampaignException = {
  id: string;
  findingId: string | null;
  /** False for exceptions written before they named a finding; those count in no outcome bucket. */
  linked: boolean;
  findingDisplayId: string | null;
  assetName: string | null;
  packageName: string | null;
  ownerTeamIdAtRequest: string | null;
  title: string;
  reason: string;
  status: CampaignExceptionStatus;
  requestedBy: string;
  requestedAt: string;
  decisionDueAt: string | null;
  decisionedBy: string | null;
  decisionedAt: string | null;
};

export type CampaignActivity = {
  id: string;
  activityType: string;
  actor: string;
  body: string;
  createdAt: string;
};

export type CampaignDeliveryAttempt = {
  id: string;
  targetType: string;
  targetLabel: string;
  targetAddress: string | null;
  subject: string;
  deliveryState: string;
  detail: string | null;
  createdAt: string;
};

/** Server read envelope for a member's current owner (`OwnershipReadAdapter.Summary`). */
export type CampaignOwnership = {
  objectId: string;
  authorityDomain: string | null;
  authorityState: 'CANONICAL' | 'LEGACY_PENDING_MIGRATION' | string;
  ownerTeamId: string | null;
  ownerTeamName: string | null;
  ownershipStatus: 'OWNED' | 'UNOWNED' | 'CONFLICT' | string | null;
  sourceKind: string | null;
  resolvedAt: string | null;
  legacyOwnerLabel: string | null;
};

/** Owner recorded when the member was added; a null status is a member added before the ledger (NOT_RECORDED). */
export type CampaignOwnerAtAdd = {
  teamId: string | null;
  teamName: string | null;
  status: 'OWNED' | 'UNOWNED' | 'CONFLICT' | 'LEGACY_PENDING_MIGRATION' | null;
  assignmentId: string | null;
};

export type CampaignOutcome =
  | 'OPEN'
  | 'REOPENED'
  | 'CAMPAIGN_EXCEPTED'
  | 'REMEDIATED'
  | 'SUPPRESSED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK'
  | 'CLOSED_OTHER';

export type CampaignFindingRow = {
  findingId: string | null;
  displayId: string | null;
  vulnerabilityId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  packageName: string | null;
  severity: string | null;
  status: string;
  outcome: CampaignOutcome;
  dueAt: string | null;
  incidentId: string | null;
  ownerAtAdd: CampaignOwnerAtAdd;
  currentOwnership: CampaignOwnership | null;
};

export type CampaignEvidenceRow = {
  cveId: string | null;
  displayId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  packageName: string | null;
  severity: string | null;
  status: string;
  outcome: CampaignOutcome;
  incidentId: string | null;
  dueAt: string | null;
  currentOwnership: CampaignOwnership | null;
};

export type CampaignAssetRow = {
  assetId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  environment: string | null;
  activeFindings: number;
  remediatedFindings: number;
  members: number;
};

export type CampaignSoftwareItem = {
  id: string;
  displayName: string;
  vendor: string | null;
  assetCount: number;
  openFindingCount: number;
};

export type CampaignSummary = {
  id: string;
  name: string;
  summary: string | null;
  status: CampaignStatus;
  scopeKind: 'CVE' | 'FINDINGS';
  membershipState: 'MATERIALIZING' | 'COMPLETE';
  assigneePrincipalId: string | null;
  coordinatingTeamId: string | null;
  dueAt: string | null;
  startedAt: string | null;
  updatedAt: string;
  cveIds: string[];
  totalFindings: number;
  /** Phase 0B §4.8: REMEDIATED members only; completionPercent is remediatedCount over members. */
  remediatedCount: number;
  /** OPEN plus REOPENED members. */
  activeRemainingCount: number;
  outcomes: Record<CampaignOutcome, number>;
  assetCount: number;
  exceptionCount: number;
  notifyGroupCount: number;
  watchlistCount: number;
  completionPercent: number;
};

export type CampaignDetail = {
  summary: CampaignSummary;
  vulnerabilities: CampaignVulnerability[];
  notifyGroups: CampaignNotifyGroup[];
  watchlist: CampaignWatchlistEntry[];
  notes: CampaignNote[];
  exceptions: CampaignException[];
  activity: CampaignActivity[];
  deliveryAttempts: CampaignDeliveryAttempt[];
  findings: CampaignFindingRow[];
  assets: CampaignAssetRow[];
  evidence: CampaignEvidenceRow[];
  /** Always present from the server; pages still tolerate an older response without it. */
  softwareItems: CampaignSoftwareItem[];
};

export type CampaignNotifyGroupRequest = {
  recipientType?: CampaignRecipientType;
  teamId?: string | null;
  groupName?: string;
  groupEmail?: string | null;
  roleLabel?: string | null;
  triggerSummary?: string | null;
  notificationsPaused?: boolean | null;
};

export type CampaignWatchlistEntryRequest = {
  entryType: CampaignWatchlistEntryType;
  label: string;
  email?: string | null;
  triggerPolicy?: string | null;
  active?: boolean | null;
};

export type CampaignWatchlistEntryUpdateRequest = {
  label: string;
  email?: string | null;
  triggerPolicy?: string | null;
  active?: boolean | null;
};

/** Phase 0B §4.7: the finding must be a campaign member. */
export type CampaignExceptionRequest = {
  findingId?: string | null;
  findingDisplayId?: string | null;
  title: string;
  reason: string;
  decisionDueAt?: string | null;
};

export type CampaignCreateRequest = {
  name: string;
  summary?: string | null;
  cveIds?: string[];
  findingIds?: string[];
  dueAt?: string | null;
  assigneePrincipalId?: string | null;
  coordinatingTeamId?: string | null;
  includeExcepted?: boolean;
  notifyGroups?: CampaignNotifyGroupRequest[];
  watchlist?: CampaignWatchlistEntryRequest[];
  launchNote?: string | null;
};

export type CampaignMember = {
  findingId: string;
  displayId: string;
  title: string | null;
  findingKind: string;
  severity: string | null;
  findingStatus: string;
  closedReason: string | null;
  outcome: CampaignOutcome;
  suppressedUntil: string | null;
  dueAt: string | null;
  assetId: string | null;
  assetName: string | null;
  addedAt: string;
  addedBy: string;
  addSource: 'CREATE' | 'RECONCILER' | 'MANUAL' | 'BACKFILL' | null;
  ownerAtAdd: CampaignOwnerAtAdd;
  currentOwnership: CampaignOwnership | null;
  ownershipChanged: boolean;
  ownerAssignedSinceLaunch: boolean;
  campaignExceptionStatus: CampaignExceptionStatus | null;
};

export type CampaignMemberPage = { items: CampaignMember[]; nextCursor: string | null };

export type CampaignPreview = {
  memberCount: number;
  exceedsCreateBound: boolean;
  distribution: OwnerBucket[];
  /** Counts of findings left out, keyed by state such as CLOSED, SUPPRESSED, ACCEPTED_RISK, FALSE_POSITIVE. */
  excluded: Record<string, number>;
  teamsWithoutChannel: Array<{ teamId: string; teamName: string }>;
};

export type CampaignReconciliation = {
  campaignId: string;
  scopeKind: 'CVE' | 'FINDINGS';
  membershipState: 'MATERIALIZING' | 'COMPLETE';
  reconciledAt: string | null;
  watermark: string | null;
  lastAdded: number | null;
  lastError: string | null;
  consecutiveFailures: number;
  members: number;
};

export type CampaignOwnerGrouping = 'current' | 'atAdd';

export type CampaignMemberQuery = {
  outcome?: CampaignOutcome;
  includeHidden?: boolean;
  groupBy?: CampaignOwnerGrouping;
  bucket?: string;
  teamId?: string;
  cursor?: string;
  limit?: number;
};
