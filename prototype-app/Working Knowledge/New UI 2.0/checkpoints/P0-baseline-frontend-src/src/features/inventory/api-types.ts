export type Asset = {
  id: string;
  type: string;
  name: string;
  identifier: string;
  serviceName?: string;
  environment?: string;
  ownerTeam?: string;
  ownerEmail?: string;
  businessCriticality: string;
  state: string;
  lastInventoryAt?: string;
  lastCmdbSyncAt?: string;
};

export type HostAssetSummary = {
  assetId: string;
  ciId: string;
  name: string;
  identifier: string;
  sysId: string;
  environment?: string;
  ownerEmail?: string;
  managedBy?: string;
  department?: string;
  supportGroup?: string;
  assignedTo?: string;
  businessCriticality?: string;
  state?: string;
  lastInventoryAt?: string;
  lastCmdbSyncAt?: string;
  ssmManaged?: boolean;
  ssmPingStatus?: string;
  ssmLastPingAt?: string;
  ssmInventoryAvailable?: boolean;
  ssmInventoryLastCapturedAt?: string;
  missingIamInstanceProfile?: boolean;
  aliasCount: number;
  installedSoftwareCount: number;
  openFindingCount: number;
  totalFindingCount: number;
  unresolvedReviewCount: number;
};

export type HostAliasRecord = {
  id: string;
  aliasName: string;
  sourceSystem: string;
  confidence?: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
};

export type HostSoftwareInstanceRecord = {
  id: string;
  inventoryComponentId?: string;
  displayName: string;
  publisher?: string;
  version?: string;
  normalizedPublisher?: string;
  normalizedProduct?: string;
  normalizedVersion?: string;
  sourceSystem: string;
  versionEvidence?: string;
  activeInstall: boolean;
  unlicensedInstall: boolean;
  installDate?: string;
  lastScanned?: string;
  lastUsed?: string;
  discoveryModelPrimaryKey?: string;
  softwareIdentity?: string;
  cpe23?: string;
  needsVersionReview: boolean;
  needsIdentityReview: boolean;
  needsDiscoveryModelReview: boolean;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type HostFindingRecord = {
  id: string;
  displayId?: string;
  vulnerabilityId?: string;
  packageName?: string;
  packageVersion?: string;
  severity?: string;
  status?: string;
  decisionState?: string;
  riskScore?: number;
  confidenceScore?: number;
  matchedBy?: string;
  assignedTo?: string;
  ownerGroup?: string;
  creationSource?: 'MANUAL' | 'AUTOMATIC';
  dueAt?: string;
  firstObservedAt?: string;
  lastObservedAt?: string;
};

export type HostApplicableCveRecord = {
  stateId: string;
  vulnerabilityId: string;
  externalId?: string;
  severity?: string;
  cvssScore?: number;
  epssScore?: number;
  packageName?: string;
  version?: string;
  impactState?: string;
  lastEvaluatedAt?: string;
};

export type BomEvidenceDocument = {
  bomId: string;
  assetId?: string;
  bomType?: string;
  specFamily?: string;
  documentFormat?: string;
  sourceType?: string;
  sourceSystem?: string;
  sourceReference?: string;
  sourceLabel?: string;
  documentName?: string;
  checksumSha256?: string;
  componentCount: number;
  evidenceCount: number;
  vulnerabilityLinkCount: number;
  ingestedAt?: string;
};

export type BomEvidenceComponent = {
  componentId: string;
  bomId: string;
  name: string;
  version?: string;
  supplier?: string;
  purl?: string;
  cpe?: string;
  license?: string;
  workflowStatus?: string;
  evidenceCount: number;
  vulnerabilityCount: number;
  sourceSystem?: string;
  sourceReference?: string;
};

export type BomEvidenceSummary = {
  documentCount: number;
  componentCount: number;
  evidenceCount: number;
  vulnerabilityLinkCount: number;
  componentsInWorkflow: number;
  documents: BomEvidenceDocument[];
  components: BomEvidenceComponent[];
};

export type HostAssetDetail = {
  host: HostAssetSummary;
  bomEvidence: BomEvidenceSummary;
  aliases: HostAliasRecord[];
  software: HostSoftwareInstanceRecord[];
  findings: HostFindingRecord[];
  applicableCves: HostApplicableCveRecord[];
};

export type InventoryComponentRecord = {
  id: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';
  componentStatus: 'ACTIVE' | 'RETIRED';
  ecosystem: string;
  packageName: string;
  packageGroup?: string;
  license?: string;
  scope?: string;
  version?: string;
  normalizedName?: string;
  normalizedVersion?: string;
  purl: string;
  componentDigest?: string;
  softwareIdentity?: string;
  cveCount: number;
  impactedCveCount: number;
  cveIds: string[];
  sourceSystem?: string;
  sourceType?: string;
  sourceReference?: string;
  uploadedAt?: string;
  lastObservedAt: string;
  retiredAt?: string;
  needsReview: boolean;
  reviewItemCount: number;
  reviewMissingVersion: boolean;
  reviewUnmappedSoftware: boolean;
  reviewLowConfidenceAlias: boolean;
  reviewDiscoveryModel: boolean;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type InventoryComponentPage = {
  items: InventoryComponentRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type InventoryComponentFilterValues = {
  assetTypes: string[];
  componentStatuses: string[];
  sourceSystems: string[];
  ecosystems: string[];
};
