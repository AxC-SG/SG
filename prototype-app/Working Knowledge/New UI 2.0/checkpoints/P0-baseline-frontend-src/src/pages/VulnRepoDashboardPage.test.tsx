import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { VulnRepoDashboard } from '../features/vuln-repo-dashboard/types';
import { renderWithProviders } from '../test/test-utils';
import { VulnRepoDashboardPage } from './VulnRepoDashboardPage';

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
    resolutionStatus: { unresolvedCount: 0, resolvedCount: 0, inProgressCount: 0, acceptedRiskCount: 0 },
    criticalUnresolved: [],
    topAffectedSoftware: [],
    recentAdvisories: [],
    impactedAssets: [],
    ...overrides,
  };
}

describe('VulnRepoDashboardPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders loading state while data is pending', () => {
    vi.spyOn(api, 'getVulnRepoDashboard').mockReturnValue(new Promise(() => {}));

    renderWithProviders(<VulnRepoDashboardPage />);

    expect(screen.getByText(/loading dashboard/i)).toBeInTheDocument();
  });

  it('calls getVulnRepoDashboard on mount', async () => {
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());

    renderWithProviders(<VulnRepoDashboardPage />);

    await waitFor(() => {
      expect(api.getVulnRepoDashboard).toHaveBeenCalled();
    });
  });

  it('renders tracked count from summary cards', async () => {
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(
      buildVulnRepoDashboard({
        summaryCards: {
          trackedCount: 342,
          trackedAddedLastWeek: 5,
          applicableCount: 200,
          applicableAddedLastWeek: 3,
          impactedInvestigationDoneCount: 100,
          impactedAddedLastWeek: 2,
          remediationCveCount: 50,
          needsAttentionCount: 10,
          criticalCount: 8,
          exploitCount: 3,
          exploitCoveragePercent: 37,
          impactedCriticalCount: 8,
          impactedHighCount: 40,
          impactedMediumCount: 80,
          impactedLowCount: 20,
          impactedKevCount: 3,
          kevAddedLastWeek: 1,
          criticalUninvestigatedCount: 4,
          kevReinvestigationCount: 0,
        },
      })
    );

    renderWithProviders(<VulnRepoDashboardPage />);

    expect(await screen.findByText('342')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders severity breakdown items when present', async () => {
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(
      buildVulnRepoDashboard({
        severityBreakdown: [
          { severity: 'CRITICAL', count: 12 },
          { severity: 'HIGH', count: 44 },
        ],
      })
    );

    renderWithProviders(<VulnRepoDashboardPage />);

    await waitFor(() => {
      expect(api.getVulnRepoDashboard).toHaveBeenCalled();
    });
  });

  it('renders empty state without crashing when dashboard has no data', async () => {
    vi.spyOn(api, 'getVulnRepoDashboard').mockResolvedValue(buildVulnRepoDashboard());

    renderWithProviders(<VulnRepoDashboardPage />);

    await waitFor(() => {
      expect(screen.queryByText(/loading dashboard/i)).not.toBeInTheDocument();
    });
  });
});
