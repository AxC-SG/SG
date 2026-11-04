import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { ApiError, api } from '../api/client';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { Finding } from '../features/findings/types';
import { renderWithProviders } from '../test/test-utils';
import { fixIntelligenceApi } from '../features/fix-intelligence/api';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { FindingDetailPage } from './FindingDetailPage';

const ANALYST: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

const TENANT_ADMIN: ActorContext = {
  ...ANALYST,
  principal: 'admin@example.com',
  userId: 'admin-1',
  roles: ['ROLE_TENANT_ADMIN'],
};

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

function renderWithFinding(finding: Finding, actor: ActorContext | null = ANALYST) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } }
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[{ pathname: '/findings/F-001', state: { finding } }]}>
        <ActorContextState.Provider value={actor}>
          <FindingDetailPage />
        </ActorContextState.Provider>
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

  it('shows a read-only explanation instead of workflow actions for an auditor', () => {
    renderWithFinding(FINDING, { ...ANALYST, roles: ['ROLE_READ_ONLY_AUDITOR'] });
    expect(screen.getByText('Read-only access: workflow actions are not available.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Create Incident/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: '← Back to Findings' })).toBeInTheDocument();
  });

  it('opens workflow actions in a named dialog with labelled fields', () => {
    renderWithFinding(FINDING);
    fireEvent.click(screen.getByRole('button', { name: 'Defer' }));
    const dialog = screen.getByRole('dialog', { name: 'Defer Finding' });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByLabelText('Reason')).toBeInTheDocument();
    expect(screen.getByLabelText('Expires')).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
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

  it('shows a crypto finding as its own panel and never looks its rule id up as a CVE', async () => {
    const cveDetail = vi.spyOn(cveWorkbenchApi, 'getCveDetail').mockRejectedValue(new Error('skip'));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);

    renderWithFinding({
      ...FINDING,
      findingKind: 'CRYPTO',
      vulnerabilityId: 'CBOM-WEAK-HASH',
      packageName: 'SHA-1',
      evidence: JSON.stringify({ detail: 'SHA-1 collisions are practical', recommendation: 'Move to SHA-256' }),
    });

    expect(await screen.findByText('Crypto finding')).toBeInTheDocument();
    expect(screen.getByText('SHA-1 collisions are practical')).toBeInTheDocument();
    expect(screen.getByText('Move to SHA-256')).toBeInTheDocument();
    expect(screen.queryByText('Vulnerability')).not.toBeInTheDocument();
    expect(cveDetail).not.toHaveBeenCalled();
  });

  it('routes crypto suppression through a time-bounded request with a compensating control', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);
    const requestSuppression = vi.spyOn(api, 'requestFindingSuppression').mockResolvedValue({
      id: 'request-1',
      findingId: FINDING.id,
      findingKind: 'CRYPTO',
      severityAtRequest: 'CRITICAL',
      requestedBy: ANALYST.principal,
      requestedAt: '2026-11-02T00:00:00Z',
      decisionDueAt: '2026-11-16T00:00:00Z',
      reason: 'COMPENSATING_CONTROL',
      compensatingControl: 'TLS termination rejects SHA-1 certificates',
      proposedSuppressedUntil: '2099-01-01T00:00:00.000Z',
      status: 'PENDING',
    });

    renderWithFinding({
      ...FINDING,
      findingKind: 'CRYPTO',
      vulnerabilityId: 'CBOM-WEAK-HASH',
    });

    expect(await screen.findByText('No suppression requests exist for this cryptographic finding.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'False Positive' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Request Suppression' }));
    expect(screen.getByRole('dialog', { name: 'Request Cryptographic Suppression' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'COMPENSATING_CONTROL' } });
    fireEvent.change(screen.getByLabelText('Compensating control'), { target: { value: 'TLS termination rejects SHA-1 certificates' } });
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: '2099-01-01' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit Request' }));

    await waitFor(() => expect(requestSuppression).toHaveBeenCalledWith(FINDING.id, expect.objectContaining({
      reason: 'COMPENSATING_CONTROL',
      compensatingControl: 'TLS termination rejects SHA-1 certificates',
    })));
    expect(await screen.findByText('Suppression request submitted for tenant-admin review.')).toBeInTheDocument();
  });

  it('lets a tenant admin decide a pending crypto suppression request', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([{
      id: 'request-1', findingId: FINDING.id, findingKind: 'CRYPTO', severityAtRequest: 'HIGH',
      requestedBy: 'analyst@example.com', requestedAt: '2026-11-02T00:00:00Z',
      decisionDueAt: '2026-11-16T00:00:00Z', reason: 'PENDING_PATCH',
      compensatingControl: 'Restricted network access', proposedSuppressedUntil: '2026-12-01T00:00:00Z',
      status: 'PENDING',
    }]);
    const decide = vi.spyOn(api, 'decideFindingSuppression').mockResolvedValue({
      id: 'request-1', findingId: FINDING.id, findingKind: 'CRYPTO', severityAtRequest: 'HIGH',
      requestedBy: 'analyst@example.com', requestedAt: '2026-11-02T00:00:00Z',
      decisionDueAt: '2026-11-16T00:00:00Z', reason: 'PENDING_PATCH',
      compensatingControl: 'Restricted network access', proposedSuppressedUntil: '2026-12-01T00:00:00Z',
      status: 'REJECTED', decidedBy: TENANT_ADMIN.principal, decidedAt: '2026-11-03T00:00:00Z',
    });

    renderWithFinding({ ...FINDING, findingKind: 'CRYPTO', vulnerabilityId: 'CBOM-WEAK-HASH' }, TENANT_ADMIN);

    fireEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    await waitFor(() => expect(decide).toHaveBeenCalledWith('request-1', { decision: 'REJECT' }));
  });

  it('lets a tenant admin directly suppress a noncritical crypto finding', async () => {
    const cryptoFinding = { ...FINDING, findingKind: 'CRYPTO', severity: 'HIGH', vulnerabilityId: 'CBOM-WEAK-HASH' };
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);
    const suppress = vi.spyOn(api, 'suppressFindingDirectly').mockResolvedValue(undefined);
    vi.spyOn(api, 'getFinding').mockResolvedValue({ ...cryptoFinding, status: 'SUPPRESSED' });

    renderWithFinding(cryptoFinding, TENANT_ADMIN);

    fireEvent.click(await screen.findByRole('button', { name: 'Suppress Directly' }));
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'PENDING_PATCH' } });
    fireEvent.change(screen.getByLabelText('Compensating control'), { target: { value: 'Isolated network segment' } });
    fireEvent.change(screen.getByLabelText('Expires'), { target: { value: '2099-01-01' } });
    fireEvent.click(screen.getByRole('button', { name: 'Suppress' }));

    await waitFor(() => expect(suppress).toHaveBeenCalledWith(FINDING.id, expect.objectContaining({ reason: 'PENDING_PATCH' })));
    expect(await screen.findByText('Finding suppressed under the tenant policy.')).toBeInTheDocument();
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

  it('requests and accepts crypto verification through labelled dialogs instead of browser prompts', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingTicketAttempts').mockResolvedValue([]);
    const prompt = vi.spyOn(window, 'prompt');
    const crypto: Finding = { ...FINDING, findingKind: 'CRYPTO', vulnerabilityId: 'CBOM-RSA-SMALL-KEY' };
    const update = vi.spyOn(api, 'updateFindingVerification').mockRejectedValueOnce(new Error('Verification store unavailable'))
      .mockResolvedValue({} as never);
    vi.spyOn(api, 'getFinding').mockResolvedValue({ ...crypto, verificationStatus: 'REQUESTED', targetState: 'RSA-3072' });
    renderWithFinding(crypto);

    fireEvent.click(await screen.findByRole('button', { name: 'Request Verification' }));
    const dialog = screen.getByRole('dialog', { name: 'Request remediation verification' });
    expect(screen.getByRole('button', { name: 'Request verification' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Target cryptographic state'), { target: { value: 'RSA-3072' } });
    fireEvent.click(screen.getByRole('button', { name: 'Request verification' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Verification store unavailable');
    expect(screen.getByLabelText('Target cryptographic state')).toHaveValue('RSA-3072');
    expect(dialog).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Request verification' }));
    await waitFor(() => expect(update).toHaveBeenLastCalledWith(FINDING.id, { action: 'REQUEST', targetState: 'RSA-3072' }));
    expect(await screen.findByText('Verification requested. The finding remains open until evidence is accepted.')).toBeInTheDocument();

    fireEvent.click(await screen.findByRole('button', { name: 'Accept Verification' }));
    expect(screen.getByText('Target state: RSA-3072')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Verification evidence'), { target: { value: 'Assessment shows RSA-3072' } });
    expect(screen.getByRole('button', { name: 'Accept and resolve' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Assessment run ID that proves the target state'), { target: { value: 'run-9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Accept and resolve' }));
    await waitFor(() => expect(update).toHaveBeenLastCalledWith(FINDING.id,
      { action: 'ACCEPT', evidence: 'Assessment shows RSA-3072', assessmentRunId: 'run-9' }));
    expect(prompt).not.toHaveBeenCalled();
  });

  it('shows a failed crypto ticket push and retries it', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingTicketAttempts').mockResolvedValue([{
      id: 'attempt-1', provider: 'jira', template: 'CRYPTO', outcome: 'FAILED', ticketKey: null,
      errorMessage: 'Jira rejected the request', attemptedBy: 'user-1', attemptedAt: '2026-11-02T00:00:00Z',
    }]);
    const create = vi.spyOn(api, 'createFindingTicket').mockResolvedValue({} as never);
    const finding = { ...FINDING, findingKind: 'CRYPTO' as const, vulnerabilityId: 'CBOM-RSA-SMALL-KEY' };
    vi.spyOn(api, 'getFinding').mockResolvedValue({ ...finding, incidentId: 'JIRA-123' });
    renderWithFinding(finding);

    expect(await screen.findByText('Jira rejected the request')).toBeInTheDocument();
    expect(screen.getByText(/crypto template/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry ticket' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith(FINDING.id, {}));
    await waitFor(() => expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument());
  });

  it('opens the CBOM component page from a crypto finding\'s affected asset instead of a host page', async () => {
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingSuppressionRequests').mockResolvedValue([]);
    vi.spyOn(api, 'listFindingTicketAttempts').mockResolvedValue([]);
    renderWithFinding({
      ...FINDING, findingKind: 'CRYPTO', vulnerabilityId: 'CBOM-MISSING-USAGE', packageName: 'Active credential encryption key slot',
      assetType: 'APPLICATION', evidence: JSON.stringify({ cbomFindingId: 'cf-9', cbomComponentId: 'cbom-comp-1' }),
    });

    fireEvent.click(await screen.findByRole('button', { name: /Affected Assets/ }));
    const link = screen.getByRole('link', { name: 'Active credential encryption key slot' });
    expect(link).toHaveAttribute('href', '/inventory/bom-components/cbom/cbom-comp-1?returnTo=%2Ffindings%2FF-001');
  });
});
