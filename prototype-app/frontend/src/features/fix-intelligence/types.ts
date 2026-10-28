export type FixView = 'all' | 'patches' | 'workarounds' | 'compensating-controls';

export type FixSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
export type FixEcosystem = 'WINDOWS' | 'LINUX' | 'MACOS' | 'CROSS_PLATFORM';
export type FixStatus = 'DRAFT' | 'PROPOSED' | 'APPROVED' | 'ACTIVE' | 'SUPERSEDED' | 'RETIRED';
export type ControlFixType = 'WORKAROUND' | 'CONFIGURATION_CHANGE' | 'COMPENSATING_CONTROL';

export type FixSummaryBucket = { key: string; count: number; percent: number };

export type FixSummary = {
  totalFixes: number;
  criticalSeverity: number;
  highPriority: number;
  ecosystemsCovered: number;
  severityDistribution: FixSummaryBucket[];
  ecosystems: FixSummaryBucket[];
};

export type FixListItem = {
  id: string;
  displayId: string;
  title: string;
  fixType: string;
  severity: string | null;
  ecosystem: string | null;
  status: string;
  sources: string[];
  applicableAssets: number;
  remediatedAssets: number;
  /** Remediated / applicable, capped at 100; null when no asset applies. */
  coveragePercent: number | null;
  cveCount: number;
  updatedAt: string | null;
};

export type FixListPage = {
  items: FixListItem[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type FixListFilters = {
  view: FixView;
  severity?: string;
  ecosystem?: string;
  status?: string;
  search?: string;
  page?: number;
  size?: number;
};

export type FixDetailCve = { cveId: string; source: string; confidence: string | null; severity: string | null; inKev: boolean };

export type FixPatchSource = {
  provider: string;
  externalId: string;
  kbArticle: string | null;
  bulletinId: string | null;
  vendor: string | null;
  product: string | null;
  classification: string | null;
  vendorSeverity: string | null;
  releaseDate: string | null;
  superseded: boolean;
  infoUrl: string | null;
  lastSeenAt: string | null;
};

export type FixControl = {
  controlType: string | null;
  scopeDescription: string | null;
  verificationMethod: string | null;
  residualRisk: string | null;
};

export type FixAssetState = {
  assetId: string;
  assetName: string | null;
  assetIdentifier: string | null;
  provider: string;
  status: string;
  deploymentName: string | null;
  scheduledAt: string | null;
  deadlineAt: string | null;
  installedAt: string | null;
  errorCode: string | null;
  lastReportedAt: string | null;
};

export type FixDetail = {
  id: string;
  displayId: string;
  title: string;
  description: string | null;
  fixType: string;
  severity: string | null;
  ecosystem: string | null;
  status: string;
  origin: string;
  editable: boolean;
  owner: string | null;
  proposedBy: string | null;
  approvedBy: string | null;
  approvedAt: string | null;
  reviewDueAt: string | null;
  installationInstructions: string | null;
  rollbackInstructions: string | null;
  knownLimitations: string | null;
  requiresReboot: boolean | null;
  estimatedDowntimeMinutes: number | null;
  version: number;
  cves: FixDetailCve[];
  patchSources: FixPatchSource[];
  control: FixControl | null;
  applicableAssets: number;
  remediatedAssets: number;
  coveragePercent: number | null;
  assetTotal: number;
  assets: FixAssetState[];
  createdAt: string | null;
  updatedAt: string | null;
};

export type FixControlRequest = {
  fixType: ControlFixType;
  title: string;
  description?: string | null;
  severity?: string | null;
  ecosystem?: string | null;
  installationInstructions?: string | null;
  rollbackInstructions?: string | null;
  knownLimitations?: string | null;
  reviewDueAt?: string | null;
  controlType?: string | null;
  scopeDescription?: string | null;
  verificationMethod?: string | null;
  residualRisk?: string | null;
  owner?: string | null;
  cveIds: string[];
  assetIds: string[];
  submit: boolean;
  version?: number | null;
};

export type FixContextItem = {
  fixId: string;
  displayId: string;
  title: string;
  fixType: string;
  status: string;
  severity: string | null;
  cveIds: string[];
  assetStatus: string | null;
  assetProvider: string | null;
  scheduledAt: string | null;
  deadlineAt: string | null;
  installedAt: string | null;
  coveragePercent: number | null;
};

export type FixContext = { cveId: string | null; assetId: string | null; fixes: FixContextItem[] };

export type PatchProvider = 'sccm' | 'intune' | 'bigfix' | 'tanium';

export type PatchConnectorConfig = {
  id: string | null;
  provider: string;
  displayName: string;
  configured: boolean;
  hasSecret: boolean;
  baseUrl: string | null;
  directoryId: string | null;
  clientId: string | null;
  username: string | null;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus: string | null;
  lastTestMessage: string | null;
  lastTestedAt: string | null;
  lastSyncAt: string | null;
};

export type PatchConnectorConfigRequest = {
  baseUrl?: string | null;
  directoryId?: string | null;
  clientId?: string | null;
  username?: string | null;
  /** Write-only; omit to keep the stored value. */
  secret?: string | null;
  enabled?: boolean;
  autoSyncEnabled?: boolean;
  intervalMinutes?: number;
};

export type PatchConnectionCheck = { name: string; passed: boolean; required: boolean; detail: string | null };

export type PatchConnectionTest = {
  status: string;
  message: string;
  checks: PatchConnectionCheck[];
  testedAt: string;
};

export type PatchSyncStatus = { active: boolean; status: string };
