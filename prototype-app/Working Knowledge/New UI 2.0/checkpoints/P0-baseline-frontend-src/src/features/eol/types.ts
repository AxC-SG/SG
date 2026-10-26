export type EolSummary = {
  totalTracked: number;
  eolCount: number;
  nearEolCount: number;
  supportedCount: number;
  unknownCount: number;
};

export type ComponentEolStatus = {
  componentId: string;
  packageName: string;
  ecosystem: string;
  version?: string;
  assetName: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
};

export type EolProductCatalog = {
  slug: string;
  displayName?: string;
  cpeVendor?: string;
  cpeProduct?: string;
  purlType?: string;
  purlNamespace?: string;
  aliases?: string[];
  releaseCount?: number;
  lastModified?: string;
  lastFetchedAt?: string;
};

export type EolRelease = {
  cycle: string;
  releaseDate?: string;
  eolDate?: string;
  eolBoolean?: boolean;
  supportEndDate?: string;
  extendedSupportDate?: string;
  securitySupportDate?: string;
  latestVersion?: string;
  latestReleaseDate?: string;
  lts: boolean;
  isEol: boolean;
  isEoas?: boolean;
  isEoes?: boolean;
  discontinued: boolean;
  officialSourceUrl?: string;
  supportPhase?: string;
};

export type EolComponentPage = {
  content: ComponentEolStatus[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

export type UnresolvedEolMapping = {
  softwareIdentityId: string;
  vendor: string;
  product: string;
  displayName: string;
  normalizedKey: string;
  assetCount: number;
  componentCount: number;
  versionCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  lastObservedAt?: string;
};

export type EolSlugSuggestion = {
  slug: string;
  displayName: string;
  confidence: string;
  method: string;
};

export type UnresolvedEolMappingPage = {
  content: UnresolvedEolMapping[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

export type PackageEolStatus = {
  packageName: string;
  ecosystem: string;
  eolSlug?: string;
  eolCycle?: string;
  eolDate?: string;
  isEol?: boolean;
  eolDaysRemaining?: number;
  assetCount: number;
};

export type PackageEolStatusPage = {
  content: PackageEolStatus[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};

export type PackageAsset = {
  assetName: string;
  versions: string;
};

export type PackageAssetPage = {
  content: PackageAsset[];
  number: number;
  size: number;
  totalElements: number;
  totalPages: number;
};
