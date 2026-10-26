export type CampaignStatus =
  | 'DRAFT'
  | 'ACTIVE'
  | 'PAUSED'
  | 'BLOCKED'
  | 'IN_REVIEW'
  | 'CLOSED'
  | 'CANCELLED';

export type CampaignWatchlistEntryType = 'USER' | 'GROUP';

export type CampaignNotifyGroup = {
  id: string;
  groupName: string;
  groupEmail: string | null;
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
  findingDisplayId: string | null;
  assetName: string | null;
  packageName: string | null;
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

export type CampaignFindingRow = {
  findingId: string | null;
  displayId: string | null;
  vulnerabilityId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  packageName: string | null;
  severity: string | null;
  ownerGroup: string | null;
  status: string;
  dueAt: string | null;
  incidentId: string | null;
};

export type CampaignEvidenceRow = {
  cveId: string | null;
  displayId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  packageName: string | null;
  severity: string | null;
  ownerGroup: string | null;
  status: string;
  incidentId: string | null;
  dueAt: string | null;
};

export type CampaignAssetRow = {
  assetId: string | null;
  assetName: string | null;
  assetIdentifier: string | null;
  environment: string | null;
  supportGroup: string | null;
  openFindings: number;
  resolvedFindings: number;
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
  dueAt: string | null;
  startedAt: string | null;
  updatedAt: string;
  cveIds: string[];
  totalFindings: number;
  resolvedFindings: number;
  openFindings: number;
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
  softwareItems?: CampaignSoftwareItem[];
};

export type CampaignNotifyGroupRequest = {
  groupName: string;
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

export type CampaignExceptionRequest = {
  findingDisplayId?: string | null;
  assetName?: string | null;
  packageName?: string | null;
  title: string;
  reason: string;
  decisionDueAt?: string | null;
};

export type CampaignCreateRequest = {
  name: string;
  summary?: string | null;
  cveIds: string[];
  dueAt?: string | null;
  notifyGroups?: CampaignNotifyGroupRequest[];
  watchlist?: CampaignWatchlistEntryRequest[];
  launchNote?: string | null;
};
