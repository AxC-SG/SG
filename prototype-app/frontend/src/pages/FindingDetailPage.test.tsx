import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { Finding } from '../features/findings/types';
import { renderWithProviders } from '../test/test-utils';
import { fixIntelligenceApi } from '../features/fix-intelligence/api';
import { FindingDetailPage } from './FindingDetailPage';

const FINDING: Finding = {
  id: '11111111-1111-1111-1111-111111111111',
  displayId: 'F-001',
  componentId: 'cmp-1',
  assetName: 'web-prod-01',
  assetIdentifier: 'web-prod-01.example.com',
  assetType: 'HOST',
  packageName: 'openssl',
  packageVersion: '1.1.1k',
  vulnerabilityId: 'CVE-2026-1234',
  source: 'NVD',
  creationSource: 'AUTOMATIC',
  severity: 'CRITICAL',
  inKev: true,
  epss: 0.42,
  riskScore: 9.1,
  confidenceScore: 0.95,
  matchedBy: 'CPE',
  evidence: '{}',
  firstObservedAt: '2026-04-01T00:00:00Z',
  lastObservedAt: '2026-04-25T00:00:00Z',
  decisionState: 'AFFECTED',
  status: 'OPEN',
  updatedAt: '2026-04-25T00:00:00Z',
};

function renderWithFinding(finding: Finding) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[{ pathname: '/findings/F-001', state: { finding } }]}>
        <FindingDetailPage />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('FindingDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the "Finding not available" panel when no finding state is passed', () => {
    renderWithProviders(<FindingDetailPage />);

    expect(screen.getByText('Finding not available')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Back to Findings/ })).toBeInTheDocument();
  });

  it('renders core finding details when navigated with a finding in location state', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue({
      summary: {
        externalId: 'CVE-2026-1234',
        title: 'OpenSSL buffer overflow',
        description: 'A buffer overflow in openssl',
        severity: 'CRITICAL',
        cvssScore: 9.1,
        epssScore: 0.42,
        cweIds: 'CWE-119',
        source: 'NVD',
        inKev: true,
      },
      signals: {
        exploitAvailable: false,
        exploitReason: '',
        systemsImpacted: true,
        componentCount: 1,
        softwareCount: 1,
        assetCount: 1,
        patchAvailable: true,
        patchVersions: '1.1.1l',
      },
      investigations: [],
      assessments: [],
      matchedSoftware: [],
      vendorIntelligence: [],
    });
    vi.spyOn(cveWorkbenchApi, 'getSavedAiSolution').mockResolvedValue(null as never);
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue({
      criticalThreshold: 9, highThreshold: 7,
      criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60,
      assetCriticalSlaMultiplier: 0.5, assetHighSlaMultiplier: 0.75,
      assetMediumSlaMultiplier: 1, assetLowSlaMultiplier: 1.25,
      autoCloseEnabled: false, autoCloseAfterDays: 30, findingGenerationMode: 'AUTO',
      autoCloseRequiredConsecutiveMisses: 2,
      autoCloseNotObservedEnabled: true,
      autoCloseComponentRemovedEnabled: true,
      autoCloseAssetRetiredEnabled: true,
      autoCloseSourceDisabledEnabled: false,
      autoCloseDuplicateEnabled: true,
      autoCloseRunIntervalDays: 1,
      triageExploitabilityWeight: 1, triageBlastRadiusWeight: 1, triageEolRiskWeight: 1,
      triageSlaBreachWeight: 1, triageMissingOwnerBoost: 1, triagePatchGapBoost: 1,
    });

    renderWithFinding(FINDING);

    // The displayId is rendered in the topbar
    expect(screen.getByText('F-001')).toBeInTheDocument();
    // Status pill (text appears in both topbar and a status panel)
    expect(screen.getAllByText('Open').length).toBeGreaterThan(0);
    // Action buttons for OPEN findings
    expect(screen.getByRole('button', { name: /Create Incident/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Resolve/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Defer' })).toBeInTheDocument();
    // CVE ID surfaces from the finding
    expect(await screen.findByText(/CVE-2026-1234/)).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('hides workflow action buttons when the finding is already RESOLVED', () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockResolvedValue(undefined as never);
    vi.spyOn(cveWorkbenchApi, 'getSavedAiSolution').mockResolvedValue(null as never);
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);

    renderWithFinding({ ...FINDING, status: 'RESOLVED' });

    // Resolved findings only show "Create Incident", not Defer/Resolve/FP/Under Investigation
    expect(screen.getByRole('button', { name: /Create Incident/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Defer' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Under Investigation/ })).not.toBeInTheDocument();
    expect(screen.getAllByText('Resolved').length).toBeGreaterThan(0);
  });
  it('loads the finding directly when opened by URL without router state', async () => {
    const lookup = vi.spyOn(api, 'getFinding').mockResolvedValue(FINDING);
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('skip'));
    vi.spyOn(cveWorkbenchApi, 'getSavedAiSolution').mockRejectedValue(new Error('skip'));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);

    renderWithProviders(<FindingDetailPage findingRef={FINDING.id} />);

    expect(screen.getByRole('heading', { name: 'Loading finding' })).toBeInTheDocument();
    expect((await screen.findAllByText('F-001')).length).toBeGreaterThan(0);
    expect(lookup).toHaveBeenCalledWith(FINDING.id);
  });

  it('explains a missing finding without claiming the link works', async () => {
    vi.spyOn(api, 'getFinding').mockRejectedValue(new ApiError('Not found', 404));

    renderWithProviders(<FindingDetailPage findingRef="F-10420" />);

    expect(await screen.findByRole('heading', { name: 'Finding not found' })).toBeInTheDocument();
    expect(screen.getByText(/No finding matches F-10420/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retry finding' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Back to Findings/ })).toBeInTheDocument();
  });

  it('shows a denied state for a finding outside the actor scope', async () => {
    vi.spyOn(api, 'getFinding').mockRejectedValue(new ApiError('Forbidden', 403));

    renderWithProviders(<FindingDetailPage findingRef={FINDING.id} />);

    expect(await screen.findByRole('heading', { name: 'Finding not accessible' })).toBeInTheDocument();
    expect(screen.getByText('You do not have access to this finding in the current workspace.')).toBeInTheDocument();
  });

  it('offers retry when the finding lookup fails for another reason', async () => {
    const lookup = vi.spyOn(api, 'getFinding').mockRejectedValue(new ApiError('Server error', 500));

    renderWithProviders(<FindingDetailPage findingRef={FINDING.id} />);

    expect(await screen.findByRole('heading', { name: 'Finding could not be loaded' }, { timeout: 5000 })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry finding' }));
    await waitFor(() => expect(lookup.mock.calls.length).toBeGreaterThan(1));
  });
  it('keeps the finding visible when the remediation options panel fails', async () => {
    vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('skip'));
    vi.spyOn(cveWorkbenchApi, 'getSavedAiSolution').mockRejectedValue(new Error('skip'));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(fixIntelligenceApi, 'context').mockRejectedValue(new Error('down'));

    renderWithFinding(FINDING);

    expect(await screen.findByText('Fix Intelligence is unavailable right now.')).toBeInTheDocument();
    expect(screen.getAllByText('F-001').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Retry remediation options' })).toBeInTheDocument();
  });
});
