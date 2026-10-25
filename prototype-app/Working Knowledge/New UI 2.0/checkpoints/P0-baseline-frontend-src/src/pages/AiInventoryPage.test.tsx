import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiInventoryPage } from './AiInventoryPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

function mockBaseline() {
  vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
  vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue(emptyCoverage());
  vi.spyOn(api, 'getAiTopRiskArtifacts').mockResolvedValue([]);
  vi.spyOn(api, 'getAiSeverityGrid').mockResolvedValue({ rows: [] });
  vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());
}

describe('AiInventoryPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('grid cells count distinct artifacts, roll cross-provider kinds into one category row, and open the filtered asset list', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiSeverityGrid').mockResolvedValue({
      rows: [
        { nativeKind: 'AWS_BEDROCK_GUARDRAIL', critical: 0, high: 1, medium: 0, low: 0, total: 1 },
        { nativeKind: 'AZURE_RAI_POLICIES', critical: 0, high: 2, medium: 0, low: 0, total: 2 },
        { nativeKind: 'AZURE_BOT_CHANNELS', critical: 0, high: 0, medium: 0, low: 0, total: 0 },
      ],
    });

    renderWithProviders(<AiInventoryPage />);

    // Grid section renders compactly, not with the exposure-dashboard's default cell sizing.
    const gridSection = (await screen.findByText('Severity Grid')).closest('section');
    expect(gridSection).toHaveClass('ai-severity-grid--compact');

    // Guardrails row sums both providers' HIGH artifact counts (1 + 2 = 3); wait for the real
    // severity-grid data to resolve rather than the always-present zeroed placeholder row.
    const highCell = await screen.findByRole('button', { name: '3' });
    fireEvent.click(highCell);

    expect(navigateMock).toHaveBeenCalledWith(
      '/inventory/ai/assets?nativeKind=AWS_BEDROCK_GUARDRAIL%2CAZURE_RAI_POLICIES&severity=HIGH',
    );
  });

  it('caps the severity grid at 10 rows and folds overflow into an Other row', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiSeverityGrid').mockResolvedValue({
      rows: [
        // 8 uncategorized kinds; 7 explicit category rows leave two individual rows and one Other row.
        { nativeKind: 'AWS_KIND_A', critical: 0, high: 5, medium: 0, low: 0, total: 5 },
        { nativeKind: 'AWS_KIND_B', critical: 0, high: 4, medium: 0, low: 0, total: 4 },
        { nativeKind: 'AWS_KIND_C', critical: 0, high: 3, medium: 0, low: 0, total: 3 },
        { nativeKind: 'AWS_KIND_D', critical: 0, high: 2, medium: 0, low: 0, total: 2 },
        { nativeKind: 'AWS_KIND_E', critical: 0, high: 1, medium: 0, low: 0, total: 1 },
        { nativeKind: 'AWS_KIND_F', critical: 1, high: 0, medium: 0, low: 0, total: 1 },
        { nativeKind: 'AWS_KIND_G', critical: 1, high: 0, medium: 0, low: 0, total: 1 },
        { nativeKind: 'AWS_KIND_H', critical: 1, high: 0, medium: 0, low: 0, total: 1 },
      ],
    });

    renderWithProviders(<AiInventoryPage />);

    await screen.findByText('Other (6)');
    const rows = document.querySelectorAll('.grid-exposure-table tbody tr');
    expect(rows.length).toBeLessThanOrEqual(10);
  });

  it('clicking the Policy Coverage widget opens the policies list and shows artifacts failed', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue({
      ...emptyCoverage(), ownerFacingDecisionReachabilityPercent: 72, evaluatedFail: 4, artifactsFailing: 3, unsupported: 2,
    });

    renderWithProviders(<AiInventoryPage />);

    await waitFor(() => expect(screen.getByText('Artifacts failed').closest('.fpl-kpi-card')).toHaveTextContent('3'));

    fireEvent.click(screen.getByText('Policy Coverage & Risk'));

    expect(navigateMock).toHaveBeenCalledWith('/policies');
  });

  it('ranks Top 5 Assets at Risk by open-finding score and opens the asset detail page on click', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiTopRiskArtifacts').mockResolvedValue([{
      id: 'artifact-risk-1', name: 'search-rerank-agent', nativeKind: 'AWS_BEDROCK_AGENT',
      provider: 'AWS', accountId: '123456789012', criticalCount: 2, highCount: 1, mediumCount: 0, lowCount: 0, score: 11,
    }]);

    renderWithProviders(<AiInventoryPage />, { route: '/inventory/ai' });

    fireEvent.click(await screen.findByText('search-rerank-agent'));

    expect(navigateMock).toHaveBeenCalledWith('/inventory/ai/artifact-risk-1?returnTo=%2Finventory%2Fai');
  });

  it('shows an empty state for Top 5 Assets at Risk when no artifact has an open finding', async () => {
    mockBaseline();

    renderWithProviders(<AiInventoryPage />);

    expect(await screen.findByText('No AI artifacts have an open finding.')).toBeInTheDocument();
  });

  it('clicking the Coverage Gaps widget opens connector run history', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({ ...emptySummary(), incompleteScopes: 72 });

    renderWithProviders(<AiInventoryPage />);

    fireEvent.click(await screen.findByText('Coverage Gaps'));

    expect(navigateMock).toHaveBeenCalledWith('/connect/run-history');
  });

  it('no longer shows the coverage-incomplete banner', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({ ...emptySummary(), incompleteScopes: 72 });
    vi.spyOn(api, 'getAiGridCoverage').mockResolvedValue({ ...emptyCoverage(), unsupported: 3 });

    renderWithProviders(<AiInventoryPage />);

    await screen.findByText('Coverage Gaps');
    expect(screen.queryByText(/Inventory coverage is incomplete/)).not.toBeInTheDocument();
  });

  it('clicking a By Provider row opens the asset list filtered by that provider', async () => {
    mockBaseline();
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      ...emptySummary(),
      providerCounts: { AWS: 10, AZURE: 5 },
    });

    renderWithProviders(<AiInventoryPage />);

    fireEvent.click(await screen.findByText('AZURE'));

    expect(navigateMock).toHaveBeenCalledWith('/inventory/ai/assets?provider=AZURE');
  });
});

function emptySummary() {
  return {
    artifactCounts: {},
    nativeKindCounts: {},
    providerCounts: {},
    openFindings: 0,
    incompleteScopes: 0,
    lastCompleteSnapshotAt: null,
  };
}

function emptyCoverage() {
  return {
    runId: null,
    coverageEpochId: null,
    authoritativeScopeHeads: 0,
    currentArtifacts: 0,
    applicablePublished: 0,
    required: 0,
    tenantEnabled: 0,
    preview: 0,
    tenantDisabled: 0,
    evidenceReady: 0,
    evaluatedPass: 0,
    evaluatedFail: 0,
    noDecision: 0,
    notApplicable: 0,
    stale: 0,
    unsupported: 0,
    decisionReachabilityPercent: 0,
    ownerFacingDecisionReachabilityPercent: 0,
    artifactsFailing: 0,
  };
}
