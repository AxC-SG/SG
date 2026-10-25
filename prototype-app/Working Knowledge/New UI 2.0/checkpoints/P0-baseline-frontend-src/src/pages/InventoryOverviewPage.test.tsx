import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { InventoryOverviewPage } from './InventoryOverviewPage';

function buildSoftwareIdentity(overrides = {}) {
  return {
    id: 'si-1',
    displayName: 'lodash',
    canonicalKey: 'npm/lodash',
    normalizedKey: 'npm:lodash',
    assetTypes: ['HOST'],
    ecosystems: ['npm'],
    sourceSystems: ['sbom'],
    mappingConfirmed: false,
    needsEolMapping: false,
    assetCount: 1,
    componentCount: 1,
    versionCount: 1,
    eolComponentCount: 0,
    nearEolComponentCount: 0,
    unknownEolComponentCount: 0,
    openFindingCount: 0,
    criticalFindingCount: 0,
    highFindingCount: 0,
    openVulnerabilityCount: 0,
    ...overrides,
  };
}

const SW_PAGE_WITH_DATA = {
  content: [buildSoftwareIdentity()],
  number: 0,
  size: 25,
  totalElements: 1,
  totalPages: 1,
};

const EMPTY_EOL_SUMMARY = {
  totalTracked: 0,
  eolCount: 0,
  nearEolCount: 0,
  supportedCount: 0,
  unknownCount: 0,
};

const EMPTY_EOL_MAPPING_PAGE = {
  content: [],
  number: 0,
  size: 1,
  totalElements: 0,
  totalPages: 0,
};

const EMPTY_QUALITY_SUMMARY = {
  generatedAt: '2026-01-01T00:00:00Z',
  totalIssues: 0,
  criticalIssues: 0,
  affectsActiveFindingsCount: 0,
  newIssuesLast24h: 0,
  domainCounts: [],
};

const EMPTY_COMPONENT_PAGE = {
  items: [],
  page: 0,
  size: 100,
  totalItems: 0,
  totalPages: 0,
};

const EMPTY_SW_APPLICABLE_PAGE = {
  items: [],
  page: 0,
  size: 100,
  totalItems: 0,
  totalPages: 0,
};

function buildDashboard() {
  return {
    assets: 0,
    components: 0,
    openFindings: 0,
    criticalFindings: 0,
    openCritical: 0,
    openHigh: 0,
    openMedium: 0,
    openLow: 0,
    averageOpenRiskScore: 0,
    averageOpenConfidenceScore: 0,
    highConfidenceOpenFindings: 0,
    topVulnerabilities: [],
    topInstalledComponents: [],
    topAssetsAtRisk: [],
    topVulnerabilityProductIdentities: [],
    latestFindings: [],
    noiseReduction: {
      totalFilteredNotApplicable: 0,
      neverOpenedNotApplicable: 0,
      autoResolvedNotApplicable: 0,
      deferredUnderInvestigation: 0,
      potentialFindingsWithoutCorrelation: 0,
      filteredPercentOfPotential: 0,
      categories: [],
      trendLast30Days: [],
    },
    csafVexAnalytics: {
      csafRunsLast30Days: 0,
      csafSuccessfulRunsLast30Days: 0,
      csafPartialFailureRunsLast30Days: 0,
      csafNormalizationSuccessRate: 0,
      csafPartialFailureRate: 0,
      activeVexCoveragePercent: 0,
      activeVexMatchedStateCount: 0,
      activeApplicableAwaitingVexCount: 0,
      activeVexConfirmedImpactedCount: 0,
      activeVexConfirmedNotAffectedCount: 0,
      activeVexNoPatchCount: 0,
      findingsSuppressedByVex: 0,
      suppressedByStaleVex: 0,
      underInvestigationAging: 0,
      vexCoverageByProvider: [],
      staleSuppressionsTrendLast30Days: [],
    },
    correlationEfficiency: {
      activeComponents: 0,
      cpeEligibleActiveComponents: 0,
      cpeIneligibleActiveComponents: 0,
      cpeCoveragePercent: 0,
      openFindingsMatchedByCpe: 0,
      openFindingsCpeDirect: 0,
      openFindingsCpeFallback: 0,
      cpeDirectSharePercent: 0,
      cpeFallbackSharePercent: 0,
      averageOpenCpeConfidenceScore: 0,
      cpeFindingsCreatedLast24Hours: 0,
      nonCpeFindingsCreatedLast24Hours: 0,
    },
  };
}

function mockAllResolved() {
  vi.spyOn(api, 'getDashboard').mockResolvedValue(buildDashboard());
  // Provide non-empty software so overviewHasData=true, bypassing the disabled
  // hostDetailsQuery (empty assets) which stays isPending in React Query v5.
  vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(SW_PAGE_WITH_DATA);
  vi.spyOn(api, 'getEolSummary').mockResolvedValue(EMPTY_EOL_SUMMARY);
  vi.spyOn(api, 'listEolUnresolvedMappings').mockResolvedValue(EMPTY_EOL_MAPPING_PAGE);
  vi.spyOn(api, 'getOperationalQualitySummary').mockResolvedValue(EMPTY_QUALITY_SUMMARY);
  vi.spyOn(api, 'listInventoryComponents').mockResolvedValue(EMPTY_COMPONENT_PAGE);
  vi.spyOn(api, 'listApplicableSoftware').mockResolvedValue(EMPTY_SW_APPLICABLE_PAGE);
  vi.spyOn(api, 'listAssets').mockResolvedValue([]);
}

function mockAllPending() {
  vi.spyOn(api, 'getDashboard').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'listSoftwareIdentities').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'getEolSummary').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'listEolUnresolvedMappings').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'getOperationalQualitySummary').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'listInventoryComponents').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'listApplicableSoftware').mockReturnValue(new Promise(() => {}));
  vi.spyOn(api, 'listAssets').mockReturnValue(new Promise(() => {}));
}

describe('InventoryOverviewPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows loading state while all queries are fetching', () => {
    mockAllPending();
    renderWithProviders(<InventoryOverviewPage />);
    expect(screen.getByText('Loading combined inventory overview…')).toBeInTheDocument();
  });

  it('renders empty-state widgets for a new tenant without hanging on loading', async () => {
    vi.spyOn(api, 'getDashboard').mockResolvedValue(buildDashboard());
    vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue({
      content: [],
      number: 0,
      size: 25,
      totalElements: 0,
      totalPages: 0,
    });
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(EMPTY_EOL_SUMMARY);
    vi.spyOn(api, 'listEolUnresolvedMappings').mockResolvedValue(EMPTY_EOL_MAPPING_PAGE);
    vi.spyOn(api, 'getOperationalQualitySummary').mockResolvedValue(EMPTY_QUALITY_SUMMARY);
    vi.spyOn(api, 'listInventoryComponents').mockResolvedValue(EMPTY_COMPONENT_PAGE);
    vi.spyOn(api, 'listApplicableSoftware').mockResolvedValue(EMPTY_SW_APPLICABLE_PAGE);
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);

    renderWithProviders(<InventoryOverviewPage />);

    await waitFor(() =>
      expect(screen.getByText('Inventory Funnel')).toBeInTheDocument()
    );
    expect(screen.queryByText('Loading combined inventory overview…')).not.toBeInTheDocument();
    expect(screen.getByText('Total assets')).toBeInTheDocument();
  });

  it('renders the Inventory Funnel stat card label after data loads', async () => {
    mockAllResolved();
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(screen.getByText('Inventory Funnel')).toBeInTheDocument()
    );
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders the Lifecycle breakdown panel after data loads', async () => {
    mockAllResolved();
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(screen.getByText('Lifecycle breakdown')).toBeInTheDocument()
    );
  });

  it('renders the Assets by OS stat card label', async () => {
    mockAllResolved();
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(screen.getByText('Assets by OS')).toBeInTheDocument()
    );
  });

  it('renders the High Risk Vendors stat card label', async () => {
    mockAllResolved();
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(screen.getByText('High Risk Vendors')).toBeInTheDocument()
    );
  });

  it('shows software summary error banner when dashboard fetch fails', async () => {
    mockAllResolved();
    vi.spyOn(api, 'getDashboard').mockRejectedValue(new Error('Dashboard unavailable'));
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(
        screen.getByText(/Failed to load software summary: Dashboard unavailable/i)
      ).toBeInTheDocument()
    );
  });

  it('shows asset summary error banner when assets fetch fails', async () => {
    mockAllResolved();
    vi.spyOn(api, 'listAssets').mockRejectedValue(new Error('Assets unavailable'));
    renderWithProviders(<InventoryOverviewPage />);
    await waitFor(() =>
      expect(
        screen.getByText(/Failed to load asset summary: Assets unavailable/i)
      ).toBeInTheDocument()
    );
  });
});
