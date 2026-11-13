import type { OwnershipSummary } from '../../types/ownership';

export type Finding = {
  id: string;
  displayId: string;
  componentId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  packageName: string;
  packageVersion: string;
  vulnerabilityId: string;
  /** VULNERABILITY (or absent), AI_POSTURE, AI_EXPOSURE, or CRYPTO for a mirrored CBOM finding. */
  findingKind?: string;
  workflowSubstate?: string;
  targetState?: string;
  verificationRequired?: boolean;
  verificationStatus?: 'NOT_REQUIRED' | 'REQUESTED' | 'ACCEPTED' | 'REJECTED';
  verificationEvidence?: string;
  verificationRequestedAt?: string;
  verificationCompletedAt?: string;
  verificationActor?: string;
  source: string;
  creationSource: 'MANUAL' | 'AUTOMATIC';
  severity: string;
  inKev: boolean;
  epss?: number;
  riskScore: number;
  confidenceScore: number;
  matchedBy: string;
  assignedTo?: string;
  dueAt?: string;
  suppressionReason?: string;
  suppressedUntil?: string;
  suppressedByRuleId?: string;
  suppressedByRuleName?: string;
  evidence: string;
  precedenceTrace?: string;
  vexStatus?: string;
  vexProvider?: string;
  vexFreshness?: string;
  matchedVexAssertionId?: string;
  impactReason?: string;
  firstObservedAt: string;
  lastObservedAt: string;
  decisionState: 'AFFECTED' | 'NOT_AFFECTED' | 'FIXED' | 'UNDER_INVESTIGATION' | 'NEEDS_REVIEW';
  status: 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';
  updatedAt: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  incidentId?: string;
  incidentStatus?: string;
  findingsScore?: number;
  ownerGroup?: string;
  consecutiveMisses?: number;
  autoCloseEligibleAt?: string;
  closedAt?: string;
  closedBy?: string;
  closedReason?: 'MANUAL_FIXED' | 'MANUAL_FALSE_POSITIVE' | 'MANUAL_ACCEPTED_RISK' |
    'AUTO_NOT_OBSERVED' | 'AUTO_COMPONENT_REMOVED' | 'AUTO_ASSET_RETIRED' |
    'AUTO_DUPLICATE' | 'AUTO_SOURCE_DISABLED' | 'AUTO_POLICY_PLATFORM_DEPRECATED' |
    'AUTO_POLICY_TENANT_DISABLED' | 'AUTO_SUPPRESSED_BY_RULE';
  closedRuleId?: string;
  ownershipSyncedAt?: string;
  ownership?: OwnershipSummary;
  /** Declared AI-BOM resources this VULNERABILITY finding transitively affects, if any. */
  affectedAiResources?: Array<{ id: string; name: string; resourceKind: string }>;
};
export type FindingPage = {
  items: Finding[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
  nextCursor?: string | null;
};

export type FindingsFilterModel = {
  groupField?: string;
  groupValue?: string;
  page?: number;
  size?: number;
  cursor?: string;
  limit?: number;
  queueKey?: string;
  severity?: string[];
  status?: string[];
  decisionState?: string[];
  creationSource?: Array<'MANUAL' | 'AUTOMATIC'>;
  matchMethod?: string[];
  vexStatus?: string[];
  vexFreshness?: string[];
  vexProvider?: string[];
  minConfidence?: number;
  vulnerabilityId?: string;
  packageName?: string;
  ecosystem?: string;
  ownerGroup?: string;
  assignedTo?: string;
  unassignedOnly?: boolean;
  incidentLinked?: boolean;
  dueDateBand?: 'overdue' | 'due-soon' | 'on-track' | 'no-sla';
  assetName?: string;
  supportGroup?: string;
  patchAvailable?: boolean;
  suppressedUntilBand?: 'expiring-soon' | 'expired';
  assetType?: string[];
  /**
   * Finding kinds to include. Omitted or empty means every kind, which keeps All Findings
   * inclusive; the AI Findings "Software Vulnerabilities" tab selects VULNERABILITY explicitly.
   */
  findingKind?: string[];
  /** Restricts to findings transitively affecting one of these declared AI-BOM resource ids. */
  affectedAiResourceId?: string[];
  /** true = affects any declared AI resource; false = affects none. Independent of the id filter. */
  hasAffectedAiResource?: boolean;
  /** Canonical owner team (stable ID) and resolved status; server-side, cursor paging only (ownership plan §9.7). */
  ownerTeamId?: string;
  ownershipStatus?: 'OWNED' | 'UNOWNED' | 'CONFLICT';
};

export type FindingQueueKind = 'BUILT_IN' | 'PERSONAL';

export type FindingQueueSummary = FindingSummary;

export type FindingQueueDefinition = {
  id?: string | null;
  key: string;
  title: string;
  description?: string | null;
  kind: FindingQueueKind;
  ownerType: 'SYSTEM' | 'USER' | 'TEAM';
  editable: boolean;
  isDefault: boolean;
  matchingCount: number;
  filter: FindingsFilterModel;
  summary: FindingQueueSummary;
};

export type ActiveFindingsQueryContext = {
  queueKey: string;
  title: string;
  queueKind: FindingQueueKind;
  editable: boolean;
  baseFilter: FindingsFilterModel;
  adHocFilters: FindingsFilterModel;
  healthScopeLabel: string;
};

export type FindingQueueUpsertRequest = {
  title: string;
  description?: string;
  filter: FindingsFilterModel;
  displayOrder?: number;
  sourceQueueKey?: string;
  setAsDefault?: boolean;
};

export type FindingCountBucket = {
  key: string;
  count: number;
};

export type FindingAssetCount = {
  assetName: string;
  count: number;
};

export type FindingSummary = {
  openCount: number;
  criticalOpenCount: number;
  withIncidentCount: number;
  unassignedOpenCount: number;
  overdueOpenCount: number;
  noSlaOpenCount: number;
};

export type FindingDistributions = {
  severityCounts: FindingCountBucket[];
  statusCounts: FindingCountBucket[];
  topAssets: FindingAssetCount[];
};

export type FindingBacklogHealth = {
  overdue: number;
  dueSoon: number;
  onTrack: number;
  noSla: number;
};

export type FindingProjectionStatus = {
  lastComputedAt?: string;
  findingCount: number;
  sourceFindingCount: number;
  stale: boolean;
  driftCount: number;
  lastRebuildDurationMs?: number | null;
};

export type FindingFilterValues = {
  severities: string[];
  statuses: string[];
  decisionStates: string[];
  matchMethods: string[];
  vexStatuses: string[];
  vexFreshness: string[];
  vexProviders: string[];
  owners: string[];
  supportGroups: string[];
  assignedTo: string[];
  ownershipSources: string[];
};

export type FindingBulkWorkflowRequest = {
  findingIds?: string[];
  applyToFiltered?: boolean;
  severity?: string[];
  status?: string[];
  decisionState?: string[];
  matchMethod?: string[];
  vexStatus?: string[];
  vexFreshness?: string[];
  vexProvider?: string[];
  minConfidence?: number;
  vulnerabilityId?: string;
  packageName?: string;
  ecosystem?: string;
  owner?: string[];
  supportGroup?: string[];
  ownershipSource?: string[];
  workflowStatus?: 'OPEN' | 'RESOLVED' | 'SUPPRESSED' | 'AUTO_CLOSED';
  assignedTo?: string;
  dueAt?: string;
  suppressionReason?: string;
  suppressedUntil?: string;
  actor?: string;
};

export type FindingBulkWorkflowResponse = {
  targeted: number;
  updated: number;
  failed: number;
  message: string;
};

export type FindingSuppressionRequestCreate = {
  reason: string;
  compensatingControl: string;
  proposedSuppressedUntil: string;
};

export type FindingSuppressionRequest = FindingSuppressionRequestCreate & {
  id: string;
  findingId: string;
  findingKind: string;
  severityAtRequest: string;
  requestedBy: string;
  requestedAt: string;
  decisionDueAt: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED' | 'EXPIRED';
  decidedBy?: string | null;
  decidedAt?: string | null;
  decisionReason?: string | null;
  appliedEventId?: string | null;
};

export type FindingSuppressionDecision = {
  decision: 'APPROVE' | 'REJECT';
  reason?: string;
};
export type FindingVerificationRequest = {
  action: 'REQUEST' | 'ACCEPT' | 'REJECT';
  targetState?: string;
  evidence?: string;
  assessmentRunId?: string;
};
export type FindingVerificationResponse = {
  findingId: string;
  workflowSubstate?: string;
  targetState?: string;
  verificationRequired: boolean;
  verificationStatus: 'NOT_REQUIRED' | 'REQUESTED' | 'ACCEPTED' | 'REJECTED';
  verificationEvidence?: string;
  verificationRequestedAt?: string;
  verificationCompletedAt?: string;
  verificationActor?: string;
};
export type FindingComment = {
  id: string;
  author: string;
  body: string;
  createdAt: string;
};

export type FindingEvent = {
  id: string;
  eventType: string;
  actor: string;
  summary: string;
  detailsJson?: string;
  createdAt: string;
};

export type FindingTimeline = {
  findingId: string;
  events: FindingEvent[];
  comments: FindingComment[];
};

export type VulnerabilityDetail = {
  externalId: string;
  source: string;
  title: string;
  description: string;
  severity: string;
  cvssScore?: number;
  cvssVersion?: string;
  cvssVector?: string;
  attackVector?: string;
  attackComplexity?: string;
  privilegesRequired?: string;
  userInteraction?: string;
  scope?: string;
  exploitabilityScore?: number;
  impactScore?: number;
  cweIds?: string;
  references: string[];
  sourceIdentifier?: string;
  vulnStatus?: string;
  publishedAt?: string;
  lastModifiedAt?: string;
  inKev: boolean;
  relatedOpenFindings: number;
};
