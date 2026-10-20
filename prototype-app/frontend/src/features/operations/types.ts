import type { TopFindingMetric } from '../dashboard/types';

export type OperationalEndpointMetric = {
  key: string;
  label: string;
  requestCount: number;
  successCount: number;
  errorCount: number;
  averageMs: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
  lastMs: number;
  lastRecordedAt?: string;
};

export type OperationalExecutiveHealth = {
  ingestionSuccessRateLast24h: number;
  recomputeP95Ms: number;
  normalizationCoveragePercent: number;
  correlationNoiseReductionPercent: number;
  openCriticalFindings: number;
};

export type OperationalIngestionSourceMetric = {
  source: string;
  runs: number;
  successes: number;
  failures: number;
  successRatePercent: number;
  fetched: number;
  inserted: number;
  updated: number;
};

export type OperationalIngestionEfficiency = {
  sbomIngestionsLast24h: number;
  sbomIngestionsPerHour: number;
  sbomSuccessRatePercent: number;
  syncRunsLast24h: number;
  syncSuccessRatePercent: number;
  queueBacklog: number;
  recordsFetchedLast24h: number;
  recordsInsertedLast24h: number;
  recordsUpdatedLast24h: number;
  sourceBreakdown: OperationalIngestionSourceMetric[];
};

export type OperationalNormalizationQuality = {
  activeComponents: number;
  normalizedNameCoveragePercent: number;
  normalizedVersionCoveragePercent: number;
  softwareIdentityCoveragePercent: number;
};

export type OperationalCorrelationEffectiveness = {
  openFindings: number;
  highConfidenceAffectedRatePercent: number;
  unknownDecisionRatePercent: number;
  selectedMethodDistribution: TopFindingMetric[];
  decisionStateDistribution: TopFindingMetric[];
  workflowStatusDistribution: TopFindingMetric[];
};

export type OperationalNoiseLifecycle = {
  totalFilteredNotApplicable: number;
  neverOpenedNotApplicable: number;
  autoResolvedNotApplicable: number;
  deferredUnderInvestigation: number;
  filteredPercentOfPotential: number;
  reopenRatePercent: number;
  notApplicableCategories: TopFindingMetric[];
};

export type OperationalApiReadPath = {
  summaryReadModelReady: boolean;
  canonicalCveCount: number;
  summaryCveCount: number;
  summaryCoveragePercent: number;
  filterCacheActive: boolean;
  filterCacheExpiresAt?: string;
  filterCacheHits: number;
  filterCacheMisses: number;
  filterCacheHitRatioPercent: number;
  endpointMetrics: OperationalEndpointMetric[];
  sampleScope?: 'JVM_LOCAL_RECENT_REQUESTS';
  maximumSamplesPerMetric?: number;
};

export type OperationalSourceFreshness = {
  source: string;
  lastSuccessfulAt?: string;
  ageHours: number;
  stale: boolean;
};

export type OperationalFreshnessDrift = {
  staleThresholdHours: number;
  staleSourceCount: number;
  normalizationCoverageDrift7d: number;
  cpeFallbackShareDrift7d: number;
  sourceFreshness: OperationalSourceFreshness[];
};

export type OperationalMetricDefinition = {
  section: string;
  key: string;
  label: string;
  description: string;
};

export type PerformanceRouteScorecardItem = {
  key: string;
  label: string;
  path: string;
  category: string;
  status: 'PASS' | 'FAIL' | 'NO_DATA' | string;
  unit: string;
  targetP95Ms: number;
  targetP99Ms: number;
  requestCount: number;
  currentP95Ms: number;
  currentP99Ms: number;
  compliant: boolean;
  note: string;
};

export type PerformanceSloScorecardItem = {
  key: string;
  label: string;
  unit: string;
  targetValue: number;
  currentValue: number;
  compliant: boolean;
  window: string;
};

export type PerformanceResourceCeilingItem = {
  key: string;
  label: string;
  category: string;
  status: 'PASS' | 'FAIL' | 'NO_DATA' | string;
  unit: string;
  targetValue: number;
  currentValue: number;
  compliant: boolean;
  note: string;
};

export type PerformanceScorecard = {
  generatedAt: string;
  scaleProfile: string;
  overallCompliant: boolean;
  routeFailureCount: number;
  routeNoDataCount: number;
  freshnessFailureCount: number;
  resourceFailureCount: number;
  resourceNoDataCount: number;
  routeItems: PerformanceRouteScorecardItem[];
  freshnessItems: PerformanceSloScorecardItem[];
  resourceItems: PerformanceResourceCeilingItem[];
};

export type TenantAttentionRow = {
  tenantId: string;
  tenantName: string;
  tenantStatus: string;
  reasons: string[];
  affectedConnectors: string[];
  latestRelevantSyncAt: string | null;
};

export type ConnectorIssueGroup = {
  connectorKey: string;
  affectedTenantCount: number;
  affectedTenants: string[];
};

export type OperationalSectionResponse<T> = {
  generatedAt: string;
  data: T;
};

export type OperationalQualityDomainCount = {
  domain: string;
  issueCount: number;
};

export type OperationalQualitySummary = {
  generatedAt: string;
  totalIssues: number;
  criticalIssues: number;
  affectsActiveFindingsCount: number;
  newIssuesLast24h: number;
  domainCounts: OperationalQualityDomainCount[];
};

export type OperationalQualityIssue = {
  id: string;
  issueKey: string;
  domain: string;
  issueType: string;
  severity: string;
  reasonCode: string;
  title: string;
  sourceObjectType: string;
  sourceObjectId?: string;
  primaryLabel?: string;
  secondaryLabel?: string;
  assetType?: string;
  sourceSystem?: string;
  ecosystem?: string;
  affectsActiveFindings: boolean;
  affectedAssetCount: number;
  affectedComponentCount: number;
  openFindingCount: number;
  openVulnerabilityCount: number;
  firstSeenAt?: string;
  lastSeenAt?: string;
};

export type OperationalQualityDrilldownTarget = {
  label: string;
  href: string;
};

export type OperationalQualitySampleRecord = {
  label: string;
  primaryValue: string;
  secondaryValue?: string;
};

export type OperationalQualityIssueDetail = OperationalQualityIssue & {
  whyThisMatters: string;
  evidenceJson: string;
  recommendedAction: string;
  drilldownTargets: OperationalQualityDrilldownTarget[];
  sampleRecords: OperationalQualitySampleRecord[];
  hasActiveOverride: boolean;
  overrideActor?: string;
  overrideAt?: string;
};

export type SoftwareIdentitySearchResult = {
  id: string;
  displayName: string;
  canonicalKey: string;
};

export type NormalizationOverridePayload = {
  softwareIdentityId: string;
  reason: string;
  applyToFuture: boolean;
};

export type ClusterImpactResult = {
  affectedAssetCount: number;
  affectedInstanceCount: number;
};

export type CorrelationOverridePayload = {
  disposition: 'IMPACTED' | 'NOT_IMPACTED' | 'UNKNOWN';
  reason: string;
};

export type OperationalQualityIssuePage = {
  items: OperationalQualityIssue[];
  page: number;
  size: number;
  totalItems: number;
  totalPages: number;
};

export type OperationalQualityFilterValues = {
  domains: string[];
  issueTypes: string[];
  severities: string[];
  assetTypes: string[];
  sourceSystems: string[];
  ecosystems: string[];
};

export type OperationalDashboard = {
  generatedAt: string;
  executiveHealth: OperationalExecutiveHealth;
  ingestionEfficiency: OperationalIngestionEfficiency;
  normalizationQuality: OperationalNormalizationQuality;
  correlationEffectiveness: OperationalCorrelationEffectiveness;
  noiseLifecycle: OperationalNoiseLifecycle;
  apiReadPath: OperationalApiReadPath;
  freshnessDrift: OperationalFreshnessDrift;
  metricCatalog: OperationalMetricDefinition[];
};
// BLG-014: SLO status types
export type SloEntry = {
  name: string;
  description: string;
  unit: string;
  target: number;
  current: number;
  compliant: boolean;
  window: string;
};

export type SloStatus = {
  evaluatedAt: string;
  overallCompliant: boolean;
  slos: SloEntry[];
};
