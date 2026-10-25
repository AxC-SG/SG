export type SoftwareIdentitySummary = {
  id: string;
  displayName: string;
  canonicalKey: string;
  vendor?: string;
  product?: string;
  normalizedKey: string;
  assetTypes: string[];
  ecosystems: string[];
  sourceSystems: string[];
  eolSlug?: string;
  mappingConfirmed: boolean;
  needsEolMapping: boolean;
  assetCount: number;
  componentCount: number;
  versionCount: number;
  eolComponentCount: number;
  nearEolComponentCount: number;
  unknownEolComponentCount: number;
  openFindingCount: number;
  criticalFindingCount: number;
  highFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type SoftwareIdentityPage = {
  content: SoftwareIdentitySummary[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

export type SoftwareIdentityCoverage =
  | 'records-found'
  | 'unique-software'
  | 'with-vulnerabilities'
  | 'with-findings';

export type SoftwareIdentityFunnel = {
  recordsFound: number;
  uniqueSoftware: number;
  softwareWithVulnerabilities: number;
  softwareWithFindings: number;
  sourceCount: number;
  updatedAt?: string;
};

export type SoftwareIdentityVersion = {
  version: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  supportEndDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  assetCount: number;
  componentCount: number;
  openFindingCount: number;
  criticalFindingCount: number;
  highFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type SoftwareIdentityAsset = {
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  componentId: string;
  packageName: string;
  ecosystem?: string;
  version?: string;
  sourceSystem?: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type {
  BomEvidenceDocument,
  BomEvidenceComponent,
  BomEvidenceSummary,
} from '../inventory/api-types';
import type { BomEvidenceSummary } from '../inventory/api-types';

export type SoftwareIdentityDetail = {
  id: string;
  displayName: string;
  canonicalKey: string;
  vendor?: string;
  product?: string;
  normalizedKey: string;
  purl?: string;
  cpe23?: string;
  assetTypes: string[];
  ecosystems: string[];
  sourceSystems: string[];
  eolSlug?: string;
  mappingConfirmed: boolean;
  needsEolMapping: boolean;
  assetCount: number;
  componentCount: number;
  versionCount: number;
  eolComponentCount: number;
  nearEolComponentCount: number;
  unknownEolComponentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
  bomEvidence: BomEvidenceSummary;
  versions: SoftwareIdentityVersion[];
  assets: SoftwareIdentityAsset[];
};

export type SoftwareIdentityMetadata = {
  softwareIdentityId: string;
  owner: string;
  licensed: string;
  licenseType: string;
  supportGroup: string;
  recommendation: string;
  recommendationUpdatedAt?: string;
  updatedAt?: string;
};

export type SoftwareIdentityMetadataRequest = {
  owner?: string;
  licensed?: string;
  licenseType?: string;
  supportGroup?: string;
  recommendation?: string;
};

export type VulnRepoSoftwareAsset = {
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  assetType: string;
  componentId: string;
  version?: string;
  sourceSystem?: string;
  openCveCount: number;
  openFindingCount: number;
  lastObservedAt?: string;
};

export type VulnRepoSoftwareAssetsDetail = {
  softwareIdentityId: string;
  displayName: string;
  vendor?: string;
  impactedAssetCount: number;
  assets: VulnRepoSoftwareAsset[];
};
