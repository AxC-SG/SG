import type { Finding } from '../findings/types';

export type Dashboard = {
  assets: number;
  components: number;
  openFindings: number;
  criticalFindings: number;
  openCritical: number;
  openHigh: number;
  openMedium: number;
  openLow: number;
  averageOpenRiskScore: number;
  averageOpenConfidenceScore: number;
  highConfidenceOpenFindings: number;
  topVulnerabilities: TopFindingMetric[];
  topInstalledComponents: TopFindingMetric[];
  topAssetsAtRisk: TopFindingMetric[];
  topVulnerabilityProductIdentities: TopFindingMetric[];
  latestFindings: Finding[];
  noiseReduction: DashboardNoiseReduction;
  csafVexAnalytics: DashboardCsafVexAnalytics;
  correlationEfficiency: DashboardCorrelationEfficiency;
};

export type TopFindingMetric = {
  key: string;
  count: number;
};

export type DashboardNoiseReduction = {
  totalFilteredNotApplicable: number;
  neverOpenedNotApplicable: number;
  autoResolvedNotApplicable: number;
  deferredUnderInvestigation: number;
  potentialFindingsWithoutCorrelation: number;
  filteredPercentOfPotential: number;
  categories: TopFindingMetric[];
  trendLast30Days: TopFindingMetric[];
};

export type DashboardCsafVexAnalytics = {
  csafRunsLast30Days: number;
  csafSuccessfulRunsLast30Days: number;
  csafPartialFailureRunsLast30Days: number;
  csafNormalizationSuccessRate: number;
  csafPartialFailureRate: number;
  activeVexCoveragePercent: number;
  activeVexMatchedStateCount: number;
  activeApplicableAwaitingVexCount: number;
  activeVexConfirmedImpactedCount: number;
  activeVexConfirmedNotAffectedCount: number;
  activeVexNoPatchCount: number;
  findingsSuppressedByVex: number;
  suppressedByStaleVex: number;
  underInvestigationAging: number;
  vexCoverageByProvider: TopFindingMetric[];
  staleSuppressionsTrendLast30Days: TopFindingMetric[];
};

export type DashboardCorrelationEfficiency = {
  activeComponents: number;
  cpeEligibleActiveComponents: number;
  cpeIneligibleActiveComponents: number;
  cpeCoveragePercent: number;
  openFindingsMatchedByCpe: number;
  openFindingsCpeDirect: number;
  openFindingsCpeFallback: number;
  cpeDirectSharePercent: number;
  cpeFallbackSharePercent: number;
  averageOpenCpeConfidenceScore: number;
  cpeFindingsCreatedLast24Hours: number;
  nonCpeFindingsCreatedLast24Hours: number;
};

export type ApplicableSoftwareRecord = {
  componentId: string;
  assetId: string;
  assetName: string;
  assetIdentifier: string;
  ecosystem: string;
  packageName: string;
  version: string;
  applicableCveCount: number;
  awaitingVexCveCount: number;
  vexMatchedCveCount: number;
  impactedCveCount: number;
  noPatchCveCount: number;
  lastEvaluatedAt?: string;
};

export type ApplicableSoftwarePage = {
  items: ApplicableSoftwareRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type ImpactedCveRecord = {
  vulnerabilityId: string;
  externalId: string;
  severity: string;
  cvssScore?: number;
  epssScore?: number;
  inKev: boolean;
  impactedComponentCount: number;
  impactedAssetCount: number;
  noPatchComponentCount: number;
  lastEvaluatedAt?: string;
  lastModifiedAt?: string;
};

export type ImpactedCvePage = {
  items: ImpactedCveRecord[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type CveInventoryMappingRecord = {
  vulnerabilityId: string;
  externalId: string;
  severity: string;
  cvssScore?: number;
  epssScore?: number;
  inKev: boolean;
  impactedComponentCount: number;
  noPatchComponentCount: number;
  lastModifiedAt?: string;
  matchedIdentifiers: string[];
  mappedSoftware: string[];
  mappedSoftwareCount: number;
};

export type DashboardCveInventoryMap = {
  topHighRisk: CveInventoryMappingRecord[];
  latest: CveInventoryMappingRecord[];
};

export type GridExposureRow = {
  assetType: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

export type GridExposure = {
  rows: GridExposureRow[];
};
