import { screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityFinding } from '../features/ai-security/types';
import { buildFinding as buildVulnerabilityFinding, findingPageOf } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { AiFindingsPage } from './AiFindingsPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

function buildFinding(overrides: Partial<AiSecurityFinding> = {}): AiSecurityFinding {
  return {
    id: 'finding-1',
    displayId: 'AIF-101B8AF0',
    policyId: 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER',
    policyVersion: '1.0.0',
    artifactId: 'artifact-1',
    artifactName: 'Guardrails73',
    severity: 'HIGH',
    status: 'OPEN',
    title: 'Azure RAI policy contains a non-blocking filter',
    evidence: {},
    reviewDisposition: 'UNREVIEWED',
    firstObservedAt: '2026-08-04T15:22:15Z',
    lastObservedAt: '2026-08-05T15:22:15Z',
    resolvedAt: null,
    ...overrides,
  };
}

describe('AiFindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('combines provider, state and trimmed subscription with existing deep-link scope', async () => {
    const list = vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [buildFinding()], page: 0, size: 100, total: 1 });
    vi.spyOn(api, 'listAiActionQueue').mockResolvedValue([]);
    const route = '/findings/ai?policyId=policy-1&severity=HIGH&nativeKind=AZURE_RAI_POLICY';
    renderWithProviders(<AiFindingsPage />, { route });
    await screen.findByText('AIF-101B8AF0');
    fireEvent.change(screen.getByLabelText('Cloud provider'), { target: { value: 'AZURE' } });
    fireEvent.change(screen.getByLabelText('Finding status'), { target: { value: 'SUPPRESSED_BY_POLICY' } });
    fireEvent.change(screen.getByLabelText('Azure subscription'), { target: { value: '  subscription-123  ' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith('policy-1', 'SUPPRESSED_BY_POLICY', 0, 100, 'AZURE', 'subscription-123', 'HIGH', 'AZURE_RAI_POLICY'));
    fireEvent.click(await screen.findByText('AIF-101B8AF0'));
    expect(navigateMock).toHaveBeenCalledWith(`/findings/ai/finding-1?returnTo=${encodeURIComponent(route)}`);
  });

  it('uses undefined for All states and All providers without clearing URL scope', async () => {
    const list = vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 100, total: 0 });
    vi.spyOn(api, 'listAiActionQueue').mockResolvedValue([]);
    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai?policyId=policy-1' });
    await screen.findByText('No matching AI findings');
    fireEvent.change(screen.getByLabelText('Finding status'), { target: { value: '' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith('policy-1', undefined, 0, 100, undefined, undefined, undefined, undefined));
  });

  it('retains the vulnerability kind and AI-resource constraint when selecting All states', async () => {
    const list = vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([]));
    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai/vulnerabilities' });
    await screen.findByText('No matching software vulnerabilities');
    fireEvent.change(screen.getByLabelText('Finding status'), { target: { value: '' } });
    await waitFor(() => expect(list).toHaveBeenLastCalledWith({ findingKind: ['VULNERABILITY'], hasAffectedAiResource: true, status: undefined, size: 100 }));
    expect(screen.queryByLabelText('Cloud provider')).not.toBeInTheDocument();
  });

  it('navigates to the AI finding detail page when a row is clicked', async () => {
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding()],
      page: 0,
      size: 100,
      total: 1,
    });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai' });

    fireEvent.click(await screen.findByText('AIF-101B8AF0'));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/findings/ai/finding-1?returnTo=%2Ffindings%2Fai'));
  });

  it('reads severity and nativeKind filters from the URL when arriving from the severity grid', async () => {
    const listFindings = vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({
      items: [buildFinding()],
      page: 0,
      size: 100,
      total: 1,
    });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai?severity=HIGH&nativeKind=AWS_BEDROCK_GUARDRAIL' });

    await screen.findByText('AIF-101B8AF0');

    await waitFor(() => expect(listFindings).toHaveBeenCalledWith(
      undefined,
      'OPEN',
      0,
      100,
      undefined,
      undefined,
      'HIGH',
      'AWS_BEDROCK_GUARDRAIL',
    ));
  });

  it('shows an empty state when no findings match the filters', async () => {
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 100, total: 0 });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai' });

    expect(await screen.findByText('No matching AI findings')).toBeInTheDocument();
  });

  it('navigates to the Software Vulnerabilities tab route when clicked', async () => {
    vi.spyOn(api, 'listAiSecurityFindings').mockResolvedValue({ items: [], page: 0, size: 100, total: 0 });

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai' });

    fireEvent.click(await screen.findByText('Software Vulnerabilities'));

    expect(navigateMock).toHaveBeenCalledWith('/findings/ai/vulnerabilities');
  });

  it('renders findings affecting a declared AI resource on the Software Vulnerabilities tab', async () => {
    const listFindings = vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([
      buildVulnerabilityFinding({
        id: 'finding-2',
        displayId: 'F-000002',
        affectedAiResources: [{ id: 'resource-1', name: 'llama-3', resourceKind: 'MODEL' }],
      }),
    ]));

    renderWithProviders(<AiFindingsPage />, { route: '/findings/ai/vulnerabilities' });

    expect(await screen.findByText('F-000002')).toBeInTheDocument();
    expect(screen.getByText('llama-3')).toBeInTheDocument();
    expect(listFindings).toHaveBeenCalledWith(expect.objectContaining({
      findingKind: ['VULNERABILITY'],
      hasAffectedAiResource: true,
    }));
  });
});
