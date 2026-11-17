import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequest } from '../api/client';
import { CatalogPolicyPreviewPage } from './CatalogPolicyPreviewPage';

vi.mock('../api/client', () => ({ apiRequest: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
function mount() {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })}>
    <CatalogPolicyPreviewPage tenantId="tenant-a" />
  </QueryClientProvider>);
}
const batch = { generation: 8, overrideState: '3:1', sourceState: 'nvd', scanned: 100, matched: 0, nextAfterId: 'next-id', complete: false, matches: [] };

describe('CatalogPolicyPreviewPage', () => {
  it('previews source-present CVEs without submitting threshold predicates', async () => {
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path === '/connectors/vulnerability-sources') return [{ sourceSystem: 'nvd', enabledForCorrelation: true }];
      if (options?.method === 'POST') return { ...batch, matched: 1, complete: true, matches: [{
        id: 'record-source-present', externalId: 'CVE-2026-1234', reason: 'POLICY',
        facts: { publicationYear: null, cvss: null, epss: null, cisaKev: null },
        attribution: { sourcePresence: { observationId: 'obs-nvd', sourceSystem: 'nvd',
          sourceRecordId: 'NVD-1234', payloadHash: 'fingerprint', cvssVersion: null },
        publicationYear: null, cvss: null, epss: null, cisaKev: null }
      }] };
      return [];
    });
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview from start' })).toBeEnabled());
    fireEvent.change(screen.getByLabelText('Selection mode'), { target: { value: 'SOURCE_PRESENT' } });
    expect(screen.queryByLabelText('CVSS threshold')).not.toBeInTheDocument();
    expect(screen.getByText(/does not preserve legacy source-specific filters/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Preview from start' }));
    await screen.findByText(/This batch: 1 matched/);
    fireEvent.click(screen.getByText('Fact sources'));
    expect(screen.getByText(/Selected-source evidence: nvd \/ NVD-1234/)).toBeInTheDocument();
    const call = vi.mocked(apiRequest).mock.calls.find(item => item[1]?.method === 'POST');
    expect(JSON.parse(call?.[1]?.body as string).policy.rule).toEqual({ op: 'SOURCE_PRESENT' });
  });
  it('sends an explicit version-scoped score mode without changing the legacy default', async () => {
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path === '/connectors/vulnerability-sources') return [{ sourceSystem: 'nvd', enabledForCorrelation: true }];
      if (options?.method === 'POST') return { ...batch, complete: true };
      return [];
    });
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview from start' })).toBeEnabled());
    fireEvent.change(screen.getByLabelText('CVSS score mode'), { target: { value: 'MAX_ALLOWED_CVSS_V3_1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Preview from start' }));
    await screen.findByText(/This batch: 0 matched/);
    const call = vi.mocked(apiRequest).mock.calls.find(item => item[1]?.method === 'POST');
    expect(JSON.parse(call?.[1]?.body as string).policy.scoreResolution).toBe('MAX_ALLOWED_CVSS_V3_1');
  });
  it('shows allowed current-row fact attribution without a historical-version claim', async () => {
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path === '/connectors/vulnerability-sources') return [{ sourceSystem: 'nvd', enabledForCorrelation: true }];
      if (options?.method === 'POST') return { ...batch, matched: 1, complete: true, matches: [{
        id: 'record-1', externalId: 'CVE-2026-1234', reason: 'POLICY',
        facts: { publicationYear: 2026, cvss: 8.1, epss: null, cisaKev: null },
        attribution: { publicationYear: { observationId: 'obs-1', sourceSystem: 'nvd',
          sourceRecordId: 'NVD-1234', payloadHash: 'fingerprint-1' },
        cvss: { observationId: 'obs-1', sourceSystem: 'nvd', sourceRecordId: 'NVD-1234', payloadHash: 'fingerprint-1', cvssVersion: '3.1' },
        epss: null, cisaKev: null }
      }] };
      return [];
    });
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview from start' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Preview from start' }));
    expect(await screen.findByText(/CVE-2026-1234/)).toBeInTheDocument();
    fireEvent.click(screen.getByText('Fact sources'));
    expect(screen.getByText(/cvss: nvd \/ NVD-1234/)).toBeInTheDocument();
    expect(screen.getByText(/cvss: nvd \/ NVD-1234/)).toHaveTextContent('CVSS v3.1');
    expect(screen.getByText(/not immutable source-version history/)).toBeInTheDocument();
  });

  it('saves with the latest version and rejects invalid numeric input', async () => {
    const saved = { version: 4, sha256: 'digest', createdAt: '2026-01-01T00:00:00Z', policy: {} };
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path === '/connectors/vulnerability-sources') return [{ sourceSystem: 'nvd', enabledForCorrelation: true }];
      if (options?.method === 'POST') return { ...saved, version: 5 };
      return [saved];
    });
    mount();
    const button = screen.getByRole('button', { name: 'Save new policy version' });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.change(screen.getByLabelText('CVSS threshold'), { target: { value: '' } });
    fireEvent.click(button);
    expect(vi.mocked(apiRequest).mock.calls.filter(call => call[1]?.method === 'POST')).toHaveLength(0);
    fireEvent.change(screen.getByLabelText('CVSS threshold'), { target: { value: '7' } });
    fireEvent.click(button);
    expect(await screen.findByText('Saved policy version 5. It is not active.')).toBeInTheDocument();
    const call = vi.mocked(apiRequest).mock.calls.find(call => call[1]?.method === 'POST');
    const body = JSON.parse(call?.[1]?.body as string);
    expect(body.expectedVersion).toBe(4);
    expect(body.policy.rule.children[1].number).toBe(7);
  });

  it('blocks saving when version history is unavailable', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path === '/connectors/vulnerability-sources') return [{ sourceSystem: 'nvd', enabledForCorrelation: true }];
      throw new Error('History unavailable');
    });
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('History unavailable');
    expect(screen.getByRole('button', { name: 'Save new policy version' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reload saved versions' })).toBeEnabled();
  });

  it('submits typed rules, continues the same generation, and invalidates results on edits', async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce([{ sourceSystem: 'nvd', enabledForCorrelation: true }])
      .mockResolvedValueOnce([])
      .mockResolvedValue(batch);
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview from start' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Preview from start' }));
    expect(await screen.findByText(/This batch: 0 matched out of 100/)).toBeInTheDocument();
    const first = JSON.parse(vi.mocked(apiRequest).mock.calls[2][1]?.body as string);
    expect(first.policy.rule.children[1]).toEqual({ op: 'GT', field: 'CVSS', number: 6 });
    expect(first.policy.scoreResolution).toBe('MAX_ALLOWED_OBSERVATION_V1');
    fireEvent.click(screen.getByRole('button', { name: 'Preview next batch' }));
    await waitFor(() => expect(apiRequest).toHaveBeenCalledTimes(4));
    const next = JSON.parse(vi.mocked(apiRequest).mock.calls[3][1]?.body as string);
    expect(next.afterId).toBe('next-id'); expect(next.expectedGeneration).toBe(8);
    expect(next.expectedOverrideState).toBe('3:1');
    expect(next.expectedSourceState).toBe('nvd');
    await waitFor(() => expect(screen.getByLabelText('CVSS threshold')).toBeEnabled());
    fireEvent.change(screen.getByLabelText('CVSS threshold'), { target: { value: '7' } });
    expect(screen.queryByText(/This batch:/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Preview next batch' })).not.toBeInTheDocument();
  });

  it('clears stale results and requires restart on a continuation conflict', async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce([{ sourceSystem: 'nvd', enabledForCorrelation: true }])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce(batch).mockRejectedValueOnce(new Error('Published intelligence changed'));
    mount();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Preview from start' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Preview from start' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Preview next batch' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Published intelligence changed');
    expect(screen.queryByText(/This batch:/)).not.toBeInTheDocument();
  });
});
