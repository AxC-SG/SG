export type IngestionResult = {
  status: string;
  fetched: number;
  inserted: number;
  updated: number;
  message: string;
};

export type SyncTriggerResponse = {
  runId: string;
  status: string;
  message: string;
};

export type SyncRun = {
  id: string;
  syncType: string;
  runDomain: 'INVENTORY' | 'VULN_INTEL' | 'PROCESSING';
  runClass: 'INGESTION' | 'REPAIR' | 'BACKFILL' | 'RECOMPUTE';
  status: string;
  queuePosition?: number;
  recordsFetched: number;
  recordsInserted: number;
  recordsUpdated: number;
  recordsFailed: number;
  startedAt: string;
  completedAt?: string;
  errorMessage?: string;
  metadataJson?: string;
};

export type VexAssertionRepairSummary = {
  vexLikeTargetCount: number;
  persistedAssertionCount: number;
  activeMatchedComponentCount: number;
  activeApplicableAwaitingVexCount: number;
  sourceSystems: string[];
  vexPolicyEnabled: boolean;
  vexRiskModifiersEnabled: boolean;
  vexRolloutControlsEnabled: boolean;
  vexRolloutBackfillEnabled: boolean;
  latestRepairRun?: SyncRunSnapshot;
  latestMicrosoftRun?: SyncRunSnapshot;
  latestRedhatRun?: SyncRunSnapshot;
  latestBackfillRun?: SyncRunSnapshot;
  latestBackfillComparison?: VexRolloutComparison;
  generatedAt: string;
};

export type SyncRunSnapshot = {
  runId: string;
  status: string;
  startedAt?: string;
  completedAt?: string;
  errorMessage?: string;
};

export type VexRolloutMetricsSnapshot = {
  vexLikeTargetCount: number;
  persistedAssertionCount: number;
  activeMatchedComponentCount: number;
  activeApplicableAwaitingVexCount: number;
  capturedAt: string;
};

export type VexRolloutComparison = {
  before: VexRolloutMetricsSnapshot;
  after: VexRolloutMetricsSnapshot;
};

export type IngestionEvidence = {
  id: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  status: 'IN_PROGRESS' | 'SUCCESS' | 'FAILURE';
  format: string;
  uploadedAt: string;
  originalFilename: string;
  ingestionSourceType?: string;
  ingestionSourceSystem?: string;
  sourceReference?: string;
  sourceEndpoint?: string;
  fetchStatusCode?: number;
  contentType?: string;
  contentLengthBytes?: number;
  contentSha256?: string;
  componentCount?: number;
  findingsGenerated?: number;
  evidenceJson?: string;
};
export type CmdbAssetRecord = {
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE' | 'CLOUD_RESOURCE';
  assetName: string;
  assetIdentifier: string;
  serviceName?: string;
  environment?: string;
  ownerTeam?: string;
  ownerEmail?: string;
  businessCriticality?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  state?: 'ACTIVE' | 'INACTIVE' | 'RETIRED' | 'DECOMMISSIONED';
  // BLG-011: OCI/container artifact identity (only for CONTAINER_IMAGE assets)
  imageDigest?: string;
  imageTag?: string;
  imageRepository?: string;
  baseImageDigest?: string;
};

export type CmdbAssetSyncResponse = {
  received: number;
  inserted: number;
  updated: number;
  message: string;
};

export type CmdbInventorySyncResponse = {
  sourceSystem: string;
  installRowsProcessed: number;
  discoveryRowsProcessed: number;
  unmatchedDiscoveryRows: number;
  ciCreated: number;
  ciAliasesCreated: number;
  softwareInstancesCreated: number;
  softwareInstancesUpdated: number;
  inventoryComponentsCreated: number;
  inventoryComponentsUpdated: number;
  findingsRecomputed: number;
  message: string;
};

export type ServiceNowCmdbAuthType = 'BASIC' | 'BEARER';

export type ServiceNowCmdbConfig = {
  id?: string;
  sourceSystem: string;
  configured: boolean;
  baseUrl: string;
  authType: ServiceNowCmdbAuthType;
  username: string;
  hasCredentialSecret: boolean;
  installTable: string;
  discoveryModelTable: string;
  ciTable: string;
  installQuery: string;
  discoveryQuery: string;
  installFields: string;
  discoveryFields: string;
  pageSize: number;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type ServiceNowCmdbConfigRequest = {
  baseUrl: string;
  authType: ServiceNowCmdbAuthType;
  username?: string;
  credentialSecret?: string;
  installTable: string;
  discoveryModelTable: string;
  ciTable: string;
  installQuery?: string;
  discoveryQuery?: string;
  installFields?: string;
  discoveryFields?: string;
  pageSize: number;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
};

export type ServiceNowCmdbConnectionTest = {
  status: 'SUCCESS' | 'FAILED';
  message: string;
  ciTableReachable: boolean;
  installTableReachable: boolean;
  discoveryTableReachable: boolean;
  testedAt: string;
};

export type JiraAuthType = 'BASIC' | 'BEARER';

export type JiraTicketingConfig = {
  id?: string;
  configured: boolean;
  baseUrl: string;
  authType: JiraAuthType;
  username: string;
  hasCredentialSecret: boolean;
  projectKey: string;
  issueTypeId: string;
  issueTypeName: string;
  defaultLabels: string;
  includePriority: boolean;
  enabled: boolean;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
};

export type JiraTicketingConfigRequest = {
  baseUrl: string;
  authType: JiraAuthType;
  username?: string;
  /** Write-only: omit to keep the stored token. */
  credentialSecret?: string;
  projectKey: string;
  issueTypeId?: string;
  issueTypeName?: string;
  defaultLabels?: string;
  includePriority: boolean;
  enabled: boolean;
};

export type JiraConnectionTest = {
  status: 'SUCCESS' | 'FAILED';
  message: string;
  credentialsValid: boolean;
  projectReachable: boolean;
  testedAt: string;
};

/** Provider-neutral ticket request; omitted fields are derived from the finding. */
export type CreateFindingTicketRequest = {
  title?: string;
  severity?: string;
  priority?: string;
  dueDate?: string;
  assignee?: string;
  assignmentGroup?: string;
  notes?: string;
  solutionInfo?: string;
};

export type FindingTicketResponse = {
  provider: string;
  providerName: string;
  ticketKey: string;
  ticketId?: string;
  url?: string;
  status?: string;
  message?: string;
};

/** Which ticketing system new tickets go to, and which configured ones it outranks. */
export type TicketingProviderStatus = {
  activeProvider: string | null;
  activeProviderName: string | null;
  configuredProviders: string[];
  overridden: string[];
};

export type GcpDiscoveryConfig = {
  id?: string;
  configured: boolean;
  /** Whether a service account key is stored. The key itself is never returned. */
  hasCredential: boolean;
  /** Read from the customer's key, for display. */
  serviceAccountEmail?: string;
  keyProjectId?: string;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  requiredRoles: string[];
  supportedResourceTypes: string[];
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type GcpDiscoveryConfigRequest = {
  /** Service account key JSON; write-only, omit to keep the stored key. */
  credentialJson?: string;
  enabled?: boolean;
  autoSyncEnabled?: boolean;
  intervalMinutes?: number;
};

export type GcpDiscoveryTarget = {
  id: string;
  projectId: string;
  displayName?: string;
  enabled: boolean;
  resourceTypes: string[];
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type GcpDiscoveryTargetRequest = {
  projectId?: string;
  displayName?: string;
  enabled?: boolean;
  resourceTypes?: string[];
};

export type GcpConnectionTestResponse = {
  status: 'SUCCESS' | 'SUCCESS_WITH_WARNINGS' | 'FAILED';
  message: string;
  serviceAccountEmail?: string;
  permissions: Array<{ permission: string; granted: boolean; required: boolean }>;
  testedAt: string;
};

export type CloudResource = {
  id: string;
  name: string;
  identifier: string;
  assetType: 'HOST' | 'CLOUD_RESOURCE' | 'APPLICATION' | 'CONTAINER_IMAGE';
  state: string;
  provider: string;
  accountId?: string;
  region?: string;
  availabilityZone?: string;
  resourceType?: string;
  instanceType?: string;
  network?: string;
  subnet?: string;
  labels: Record<string, string>;
  createdAt?: string;
  lastSeenAt?: string;
};

export type CloudResourceFacetValue = { value: string; count: number };

export type CloudResourcePage = {
  items: CloudResource[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
  facets: {
    providers: CloudResourceFacetValue[];
    accounts: CloudResourceFacetValue[];
    regions: CloudResourceFacetValue[];
    resourceTypes: CloudResourceFacetValue[];
    states: CloudResourceFacetValue[];
  };
};

export type CloudResourceFilters = {
  provider?: string;
  accountId?: string;
  region?: string;
  resourceType?: string;
  state?: string;
  search?: string;
  page?: number;
  size?: number;
};

export type SccmAuthType = 'SQL_AUTH' | 'WINDOWS_AUTH';

export type SccmCmdbConfig = {
  id?: string;
  sourceSystem: string;
  configured: boolean;
  jdbcUrl: string;
  authType: SccmAuthType;
  username: string;
  hasCredential: boolean;
  siteCode: string;
  databaseName: string;
  fetchSize: number;
  queryTimeoutSeconds: number;
  mockMode: boolean;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type SccmCmdbConfigRequest = {
  jdbcUrl?: string;
  authType?: SccmAuthType;
  username?: string;
  credentialSecret?: string;
  siteCode?: string;
  databaseName?: string;
  fetchSize?: number;
  queryTimeoutSeconds?: number;
  mockMode?: boolean;
  enabled?: boolean;
  autoSyncEnabled?: boolean;
  intervalMinutes?: number;
};

export type SccmConnectionTestResponse = {
  status: 'SUCCESS' | 'FAILED';
  message: string;
  systemViewReachable: boolean;
  softwareViewReachable: boolean;
  testedAt: string;
};

export type VulnerabilitySourceSystem = 'nvd' | 'kev' | 'ghsa' | 'redhat' | 'microsoft' | 'euvd' | 'jvn' | 'advisory' | 'epss';

export type VulnerabilitySourceFilterConfig = {
  sourceSystem: VulnerabilitySourceSystem;
  configured: boolean;
  enabledForCorrelation?: boolean;
  cpeName?: string;
  isVulnerable: boolean;
  hasKev: boolean;
  cvssV3Severity?: string;
  cvssV4Severity?: string;
  vendorProject?: string;
  product?: string;
  dateAddedFrom?: string;
  dateAddedTo?: string;
  dueDateFrom?: string;
  dueDateTo?: string;
  knownRansomwareCampaignUse: boolean;
  severity?: string;
  cvssScore?: number;
  cvss3Score?: number;
  updatedAt?: string;
};

export type VulnerabilitySourceFilterConfigRequest = {
  enabledForCorrelation?: boolean;
  cpeName?: string;
  isVulnerable?: boolean;
  hasKev?: boolean;
  cvssV3Severity?: string;
  cvssV4Severity?: string;
  vendorProject?: string;
  product?: string;
  dateAddedFrom?: string;
  dateAddedTo?: string;
  dueDateFrom?: string;
  dueDateTo?: string;
  knownRansomwareCampaignUse?: boolean;
  severity?: string;
  cvssScore?: number;
  cvss3Score?: number;
};

// ── AWS Cloud Discovery ────────────────────────────────────────────────────────

export type AwsAuthType = 'INSTANCE_METADATA' | 'ACCESS_KEY' | 'CROSS_ACCOUNT_ROLE';

export type AwsDiscoveryConfig = {
  id?: string;
  sourceSystem: string;
  configured: boolean;
  authType: AwsAuthType;
  accessKeyId: string;
  hasCredential: boolean;
  crossAccountRoleArn: string;
  externalId: string;
  awsAccountId?: string;
  regionsJson: string;
  resourceTypesJson: string;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type AwsDiscoveryConfigRequest = {
  authType?: AwsAuthType;
  accessKeyId?: string;
  credentialSecret?: string;
  crossAccountRoleArn?: string;
  externalId?: string;
  regionsJson?: string;
  resourceTypesJson?: string;
  enabled?: boolean;
  autoSyncEnabled?: boolean;
  intervalMinutes?: number;
};

export type AwsDiscoveryTarget = {
  id: string;
  accountId?: string;
  accountName?: string;
  roleArn?: string;
  externalId?: string;
  enabled: boolean;
  regionsJson: string;
  resourceTypesJson: string;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
  hostCount: number;
  ssmManagedHostCount: number;
  missingIamInstanceProfileCount: number;
  softwareInventoryHostCount: number;
};

export type AwsDiscoveryTargetRequest = {
  accountId?: string;
  accountName?: string;
  roleArn?: string;
  externalId?: string;
  enabled?: boolean;
  regionsJson?: string;
  resourceTypesJson?: string;
};

export type AwsConnectionTestResponse = {
  status: 'SUCCESS' | 'SUCCESS_WITH_WARNINGS' | 'FAILED';
  message: string;
  resolvedAccountId?: string;
  reachableRegions: string[];
  warnings: string[];
  regionErrors: Record<string, string>;
  testedAt: string;
};

// ── Azure Cloud Discovery ───────────────────────────────────────────────────────

export type AzureAuthType = 'CLIENT_SECRET' | 'MANAGED_IDENTITY';

export type AzureDiscoveryConfig = {
  id?: string;
  sourceSystem: string;
  configured: boolean;
  authType: AzureAuthType;
  azureTenantId: string;
  clientId: string;
  hasCredential: boolean;
  subscriptionIdsJson: string;
  regionsJson: string;
  enabled: boolean;
  autoSyncEnabled: boolean;
  intervalMinutes: number;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
};

export type AzureDiscoveryConfigRequest = {
  authType?: AzureAuthType;
  azureTenantId?: string;
  clientId?: string;
  credentialSecret?: string;
  subscriptionIdsJson?: string;
  regionsJson?: string;
  enabled?: boolean;
  autoSyncEnabled?: boolean;
  intervalMinutes?: number;
};

export type AzureDiscoveryTarget = {
  id: string;
  subscriptionId?: string;
  subscriptionName?: string;
  enabled: boolean;
  regionsJson: string;
  lastTestStatus?: string;
  lastTestMessage?: string;
  lastTestedAt?: string;
  lastSyncAt?: string;
  hostCount: number;
};

export type AzureDiscoveryTargetRequest = {
  subscriptionId?: string;
  subscriptionName?: string;
  enabled?: boolean;
  regionsJson?: string;
};

export type AzureConnectionTestResponse = {
  status: 'SUCCESS' | 'SUCCESS_WITH_WARNINGS' | 'FAILED';
  message: string;
  resolvedTenantId?: string;
  reachableSubscriptions: string[];
  warnings: string[];
  subscriptionErrors: Record<string, string>;
  testedAt: string;
};

export type GithubSbomSource = {
  id: string;
  name: string;
  owner: string;
  repo: string;
  path: string;
  assetType: string;
  assetName: string;
  assetIdentifier: string;
  frequency: 'ONCE' | 'INTERVAL';
  intervalMinutes: number;
  enabled: boolean;
  lastRunAt?: string;
  lastRunStatus?: string;
  lastError?: string;
  hasToken: boolean;
};
