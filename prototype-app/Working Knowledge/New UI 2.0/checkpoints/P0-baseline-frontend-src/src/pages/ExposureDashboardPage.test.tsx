import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { Dashboard, GridExposure } from '../features/dashboard/types';
import type { EolSummary } from '../features/eol/types';
import type { VulnRepoDashboard } from '../features/vuln-repo-dashboard/types';
import { renderWithProviders } from '../test/test-utils';
import { ExposureDashboardPage } from './ExposureDashboardPage';

const { navigateMock } = vi.hoisted(() => ({ navigateMock: vi.fn() }));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return { ...actual, useNavigate: () => navigateMock };
});

function buildGridExposure(overrides: Partial<GridExposure> = {}): GridExposure {
  return {
    rows: [
      { assetType: 'HOST', critical: 3, high: 2, medium: 0, low: 0, total: 5 },
      { assetType: 'APPLICATION', critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      { assetType: 'CONTAINER_IMAGE', critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      { assetType: 'CLOUD_RESOURCE', critical: 0, high: 0, medium: 0, low: 0, total: 0 },
    ],
    ...overrides,
  };
}

function buildDashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    assets: 42,
    components: 310,
    openFindings: 17,
    criticalFindings: 5,
    openCritical: 5,
    openHigh: 8,
    openMedium: 3,
    openLow: 1,
    averageOpenRiskScore: 6.4,
    averageOpenConfidenceScore: 0.87,
    highConfidenceOpenFindings: 14,
    topVulnerabilities: [],
    topInstalledComponents: [],
    topAssetsAtRisk: [],
    topVulnerabilityProductIdentities: [],
    latestFindings: [],
    noiseReduction: {
      totalFilteredNotApplicable: 120,
      neverOpenedNotApplicable: 80,
      autoResolvedNotApplicable: 30,
      deferredUnderInvestigation: 10,
      potentialFindingsWithoutCorrelation: 500,
      filteredPercentOfPotential: 24,
      categories: [],
      trendLast30Days: [],
    },
    csafVexAnalytics: {
      csafRunsLast30Days: 7,
      csafSuccessfulRunsLast30Days: 7,
      csafPartialFailureRunsLast30Days: 0,
      csafNormalizationSuccessRate: 100,
      csafPartialFailureRate: 0,
      activeVexCoveragePercent: 62,
      activeVexMatchedStateCount: 44,
      activeApplicableAwaitingVexCount: 3,
      activeVexConfirmedImpactedCount: 8,
      activeVexConfirmedNotAffectedCount: 30,
      activeVexNoPatchCount: 6,
      findingsSuppressedByVex: 18,
      suppressedByStaleVex: 2,
      underInvestigationAging: 1,
      vexCoverageByProvider: [],
      staleSuppressionsTrendLast30Days: [],
    },
    correlationEfficiency: {
      activeComponents: 310,
      cpeEligibleActiveComponents: 280,
      cpeIneligibleActiveComponents: 30,
      cpeCoveragePercent: 90,
      openFindingsMatchedByCpe: 15,
      openFindingsCpeDirect: 12,
      openFindingsCpeFallback: 3,
      cpeDirectSharePercent: 80,
      cpeFallbackSharePercent: 20,
      averageOpenCpeConfidenceScore: 0.87,
      cpeFindingsCreatedLast24Hours: 2,
      nonCpeFindingsCreatedLast24Hours: 0,
    },
    ...overrides,
  };
}

function buildEolSummary(overrides: Partial<EolSummary> = {}): EolSummary {
  return {
    totalTracked: 100,
    eolCount: 12,
    nearEolCount: 8,
    supportedCount: 75,
    unknownCount: 5,
    ...overrides,
  };
}

function buildVulnRepoDashboard(overrides: Partial<VulnRepoDashboard> = {}): VulnRepoDashboard {
  return {
    generatedAt: new Date().toISOString(),
    summaryCards: {
      trackedCount: 0,
      trackedAddedLastWeek: 0,
      applicableCount: 0,
      applicableAddedLastWeek: 0,
      impactedInvestigationDoneCount: 0,
      impactedAddedLastWeek: 0,
      remediationCveCount: 0,
      needsAttentionCount: 0,
      criticalCount: 0,
      exploitCount: 0,
      exploitCoveragePercent: 0,
      impactedCriticalCount: 0,
      impactedHighCount: 0,
      impactedMediumCount: 0,
      impactedLowCount: 0,
      impactedKevCount: 0,
      kevAddedLastWeek: 0,
      criticalUninvestigatedCount: 0,
      kevReinvestigationCount: 0,
    },
    severityBreakdown: [],
    resolutionStatus: {
      unresolvedCount: 0,
      resolvedCount: 0,
      inProgressCount: 0,
      acceptedRiskCount: 0,
    },
    criticalUnresolved: [],
    topAffectedSoftware: [],
    recentAdvisories: [],
    impactedAssets: [],
    ...overrides,
  };
}

describe('ExposureDashboardPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockClear();
  });

  it('renders loading state while dashboard data is pending', () => {
    vi.spyOn(api, 'getExposureSummary').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'getVulnRepoDashboard').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'getEolSummary').mockReturnValue(new Promise(() => {}));
    vi.spyOn(api, 'getGridExposure').mockReturnValue(new Promise(() => {}));

    renderWithProviders(<ExposureDashboardPage />);

    expect(screen.queryByText(/loading.*dashboard/i)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Exposure dashboard')).toHaveAttribute('aria-busy', 'true');
  });

  it('renders open findings count from dashboard data', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard({ openFindings: 17 }));
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    expect(await screen.findByText('17')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders critical findings count', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard({ criticalFindings: 23, openCritical: 0 }));
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    expect(await screen.findByText('23')).toBeInTheDocument();
  });

  it('renders high severity finding count in severity breakdown', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard({ openHigh: 77 }));
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    expect(await screen.findByText('77')).toBeInTheDocument();
  });

  it('renders eol count from eol summary', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard());
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary({ eolCount: 12 }));
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    expect(await screen.findByText('12')).toBeInTheDocument();
  });

  it('renders Grid Exposure rows for every asset type and omits AI assets', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard());
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    expect(await screen.findByText('Grid Exposure')).toBeInTheDocument();
    expect(screen.getByText('Infrastructure (Hosts)')).toBeInTheDocument();
    expect(screen.getByText('Applications')).toBeInTheDocument();
    expect(screen.queryByText(/AI Assets/i)).not.toBeInTheDocument();
  });

  it('navigates to the filtered findings list when a Grid Exposure cell is clicked', async () => {
    vi.spyOn(api, 'getExposureSummary').mockResolvedValue(buildDashboard());
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());
    vi.spyOn(api, 'getEolSummary').mockResolvedValue(buildEolSummary());
    vi.spyOn(api, 'getGridExposure').mockResolvedValue(buildGridExposure());

    renderWithProviders(<ExposureDashboardPage />);

    await screen.findByText('Grid Exposure');
    const hostRow = screen.getByText('Infrastructure (Hosts)').closest('tr');
    expect(hostRow).not.toBeNull();
    const criticalCell = hostRow!.querySelector('.grid-exposure-cell--high .grid-exposure-cell-btn');
    expect(criticalCell).not.toBeNull();
    fireEvent.click(criticalCell!);

    expect(navigateMock).toHaveBeenCalledTimes(1);
    const [navigatedPath] = navigateMock.mock.calls[0] as [string];
    expect(navigatedPath.startsWith('/findings?')).toBe(true);
    const navigatedParams = new URLSearchParams(navigatedPath.split('?')[1]);
    expect(navigatedParams.getAll('assetType')).toEqual(['HOST']);
    expect(navigatedParams.getAll('severity')).toEqual(['CRITICAL']);
    expect(navigatedParams.getAll('status')).toEqual(['OPEN']);
  });
});
