import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiArtifactSummary } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiInventoryAssetsPage } from './AiInventoryAssetsPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

function buildArtifact(overrides: Partial<AiArtifactSummary> = {}): AiArtifactSummary {
  return {
    id: 'artifact-1',
    name: 'Production Guardrail',
    nativeKind: 'AWS_BEDROCK_GUARDRAIL',
    provider: 'AWS',
    accountId: '123456789012',
    region: 'us-east-1',
    criticalFindings: 0,
    highFindings: 1,
    totalFindings: 2,
    policiesFailed: 1,
    policiesTotal: 5,
    ...overrides,
  };
}

function mockBaseline() {
  vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
}

describe('AiInventoryAssetsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('shows every deployment state together and sends roster search/provider/pagination filters', async () => {
    mockBaseline();
    const list = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({ items: [
      buildArtifact({ id: 'served', name: 'Served agent', nativeKind: 'AWS_BEDROCK_AGENT', deployment: {
        status: 'SERVED', reasonCode: 'VERIFIED_SERVING_ROUTE', observedAt: null, expiresAt: null, evidenceReferences: [], lastVerifiedObservation: null,
      } }),
      buildArtifact({ id: 'unserved', name: 'Unserved agent', nativeKind: 'AWS_BEDROCK_AGENT', deployment: {
        status: 'NOT_CURRENTLY_SERVED', reasonCode: 'NO_ALIAS_ROUTE', observedAt: null, expiresAt: null, evidenceReferences: [], lastVerifiedObservation: null,
      } }),
      buildArtifact({ id: 'unverified', name: 'Unverified agent', nativeKind: 'AWS_BEDROCK_AGENT', deployment: {
        status: 'UNVERIFIED', reasonCode: 'PERMISSION_DENIED', observedAt: null, expiresAt: null, evidenceReferences: [], lastVerifiedObservation: null,
      } }),
    ], page: 0, size: 50, total: 101 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());
    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/agents?provider=AWS&subscription=account' });
    expect(await screen.findByText('Served')).toBeInTheDocument();
    expect(screen.getByText('Not currently served')).toBeInTheDocument();
    expect(screen.getByText('Deployment unverified')).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Artifact kind' })).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Search agents' }), { target: { value: 'Support' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(undefined, 0, 50, 'AWS', 'account', undefined, undefined, undefined, undefined, 'AGENTS', 'Support'));
    const next = await screen.findByRole('button', { name: 'Next' });
    await waitFor(() => expect(next).toBeEnabled());
    fireEvent.click(next);
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(undefined, 1, 50, 'AWS', 'account', undefined, undefined, undefined, undefined, 'AGENTS', 'Support'));
  });

  it('opens with all discovered AI assets instead of hiding non-agent artifacts', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({
      items: [buildArtifact()],
      page: 0,
      size: 50,
      total: 1,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: { AI_GUARDRAIL: 1 },
      nativeKindCounts: { AWS_BEDROCK_GUARDRAIL: 1 },
      providerCounts: { AWS: 1 },
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: '2026-07-29T09:05:00Z',
    });

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets' });

    expect(await screen.findByText('Production Guardrail')).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Artifact kind' })).toHaveValue('ALL');
    await waitFor(() => expect(listArtifacts).toHaveBeenCalledWith(
      undefined,
      0,
      50,
      undefined,
      undefined,
      undefined,
      undefined,
    ));
  });

  it('paginates AI artifacts using the inventory pagination controls', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries')
      .mockResolvedValueOnce({ items: [buildArtifact()], page: 0, size: 50, total: 51 })
      .mockResolvedValueOnce({ items: [buildArtifact({ id: 'artifact-51', name: 'Page two artifact' })], page: 1, size: 50, total: 51 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets' });

    expect(await screen.findByText('Page 1 of 2')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    expect(await screen.findByText('Page two artifact')).toBeInTheDocument();
    expect(screen.getByText('Page 2 of 2')).toBeInTheDocument();
    await waitFor(() => expect(listArtifacts).toHaveBeenLastCalledWith(
      undefined,
      1,
      50,
      undefined,
      undefined,
      undefined,
      undefined,
    ));
  });

  it('excludes dedicated native types from the Others inventory view', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({ items: [], page: 0, size: 50, total: 0 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets?view=others' });

    expect(await screen.findByText('No AI assets discovered')).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Artifact kind' })).not.toBeInTheDocument();
    await waitFor(() => expect(listArtifacts).toHaveBeenCalledWith(
      undefined,
      0,
      50,
      undefined,
      undefined,
      undefined,
      undefined,
      expect.stringContaining('AZURE_IDENTITY'),
      'DATA_STORE,MCP_SERVER',
      'OTHERS',
    ));
  });

  it('shows the name without the provider ARN, a provider logo, colored findings chips, and a failed/total policy count', async () => {
    mockBaseline();
    vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({
      items: [buildArtifact({
        name: 'claims-triage-agent',
        provider: 'AWS',
        accountId: '919221584905',
        region: 'us-east-1',
        criticalFindings: 1,
        highFindings: 2,
        totalFindings: 4,
        policiesFailed: 2,
        policiesTotal: 5,
      })],
      page: 0,
      size: 50,
      total: 1,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />);

    const row = (await screen.findByText('claims-triage-agent')).closest('tr');
    expect(row).not.toBeNull();
    // No ARN/providerResourceId shown alongside the name.
    expect(row).not.toHaveTextContent('arn:');

    // Provider renders as a logo (accessible by name), not the raw "AWS" string.
    expect(screen.getByRole('img', { name: 'AWS' })).toBeInTheDocument();

    // Findings render as three colored chips: critical, high, and medium+low ("other" = 4 - 1 - 2 = 1).
    expect(screen.getByTitle('Critical')).toHaveTextContent('1');
    expect(screen.getByTitle('High')).toHaveTextContent('2');
    expect(screen.getByTitle('Medium / Low')).toHaveTextContent('1');

    // Policies column shows only the failed/total count — no "failed / total" caption text.
    expect(row).toHaveTextContent('2/5');
    expect(row).not.toHaveTextContent('failed / total');

    // Header names the failed/total convention; Owner/State/Last observed columns are gone.
    expect(screen.getByText('Policies (Failed/Total)')).toBeInTheDocument();
    expect(screen.queryByText('Owner')).not.toBeInTheDocument();
    expect(screen.queryByText('State')).not.toBeInTheDocument();
    expect(screen.queryByText('Last observed')).not.toBeInTheDocument();
  });

  it('navigates to the AI asset detail page when a row is clicked', async () => {
    mockBaseline();
    vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({
      items: [buildArtifact()],
      page: 0,
      size: 50,
      total: 1,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets' });

    fireEvent.click(await screen.findByText('Production Guardrail'));

    expect(navigateMock).toHaveBeenCalledWith('/inventory/ai/artifact-1?returnTo=%2Finventory%2Fai%2Fassets');
  });

  it('combines cross-provider kinds into one category option and filters by the combined set', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({
      items: [],
      page: 0,
      size: 50,
      total: 0,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: { AI_AGENT: 3, OTHER_AI_ARTIFACT: 12 },
      nativeKindCounts: {
        AWS_BEDROCK_INFERENCE_PROFILE: 8,
        AWS_BEDROCK_GUARDRAIL: 2,
        AZURE_RAI_POLICIES: 3,
        AZURE_BOT_CHANNELS: 2,
        AWS_BEDROCK_AGENT: 3,
      },
      providerCounts: { AWS: 10, AZURE: 5 },
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: '2026-07-29T09:05:00Z',
    });

    renderWithProviders(<AiInventoryAssetsPage />);

    // Guardrails combines AWS Bedrock Guardrail (2) + Azure RAI Policies (3) into a single option.
    await screen.findByRole('option', { name: /^Guardrails \(5\)$/ });
    const kindSelect = screen.getByRole('combobox', { name: 'Artifact kind' });
    fireEvent.change(kindSelect, { target: { value: 'AWS_BEDROCK_GUARDRAIL,AZURE_RAI_POLICIES' } });

    await waitFor(() => expect(listArtifacts).toHaveBeenLastCalledWith(
      undefined,
      0,
      50,
      undefined,
      undefined,
      'AWS_BEDROCK_GUARDRAIL,AZURE_RAI_POLICIES',
      undefined,
    ));
  });

  it('gives an uncategorized native kind its own provider-free dropdown option', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({
      items: [],
      page: 0,
      size: 50,
      total: 0,
    });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({
      artifactCounts: { OTHER_AI_ARTIFACT: 8 },
      nativeKindCounts: { AWS_BEDROCK_INFERENCE_PROFILE: 8 },
      providerCounts: { AWS: 8 },
      openFindings: 0,
      incompleteScopes: 0,
      lastCompleteSnapshotAt: '2026-07-29T09:05:00Z',
    });

    renderWithProviders(<AiInventoryAssetsPage />);

    await screen.findByRole('option', { name: /^BEDROCK INFERENCE PROFILE \(8\)$/ });
    const kindSelect = screen.getByRole('combobox', { name: 'Artifact kind' });
    fireEvent.change(kindSelect, { target: { value: 'AWS_BEDROCK_INFERENCE_PROFILE' } });

    await waitFor(() => expect(listArtifacts).toHaveBeenLastCalledWith(
      undefined,
      0,
      50,
      undefined,
      undefined,
      'AWS_BEDROCK_INFERENCE_PROFILE',
      undefined,
    ));
  });

  it('reads nativeKind, provider, and severity filters from the URL when arriving from the dashboard', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({ items: [], page: 0, size: 50, total: 0 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, {
      route: '/inventory/ai/assets?nativeKind=AWS_BEDROCK_GUARDRAIL%2CAZURE_RAI_POLICIES&severity=HIGH&provider=AWS',
    });

    expect(await screen.findByText('Severity: HIGH')).toBeInTheDocument();
    await waitFor(() => expect(listArtifacts).toHaveBeenCalledWith(
      undefined,
      0,
      50,
      'AWS',
      undefined,
      'AWS_BEDROCK_GUARDRAIL,AZURE_RAI_POLICIES',
      'HIGH',
    ));
  });

  it('clears the severity filter chip', async () => {
    mockBaseline();
    const listArtifacts = vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({ items: [], page: 0, size: 50, total: 0 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets?severity=HIGH' });

    await screen.findByText('Severity: HIGH');
    fireEvent.click(screen.getByRole('button', { name: 'Clear severity filter' }));

    expect(screen.queryByText('Severity: HIGH')).not.toBeInTheDocument();
    await waitFor(() => expect(listArtifacts).toHaveBeenLastCalledWith(
      undefined,
      0,
      50,
      undefined,
      undefined,
      undefined,
      undefined,
    ));
  });

  it('routes empty inventory CTA to the connectors landing page', async () => {
    mockBaseline();
    vi.spyOn(api, 'listAiArtifactSummaries').mockResolvedValue({ items: [], page: 0, size: 50, total: 0 });
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue(emptySummary());

    renderWithProviders(<AiInventoryAssetsPage />, { route: '/inventory/ai/assets' });

    expect(await screen.findByText('No AI assets discovered')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Configure AI connector' }));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/connect/connectors'));
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
