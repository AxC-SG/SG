import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequest } from '../api/client';
import { CentralCatalogPage } from './CentralCatalogPage';

vi.mock('../api/client', () => ({ apiRequest: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } });
  render(<QueryClientProvider client={client}><MemoryRouter><CentralCatalogPage /></MemoryRouter></QueryClientProvider>);
}

describe('CentralCatalogPage', () => {
  it('pages NVD scopes and clears a selection when returning to the first page', async () => {
    const first = `nvd:${'a'.repeat(32)}`;
    const second = `nvd:${'b'.repeat(32)}`;
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.includes('/nvd-observed-scopes')) {
        const next = path.includes('afterFeedKey=');
        return { items: [{ feedKey: next ? second : first, observedWindowCount: 1,
          firstObservedIntervalStart: '2026-01-01T00:00:00Z', latestObservedIntervalEnd: '2026-01-02T00:00:00Z' }],
          hasMore: !next, nextAfterFeedKey: next ? null : first };
      }
      return { items: [], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null };
    });
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'Load NVD filter scopes' }));
    await screen.findByRole('option', { name: new RegExp(first) });
    fireEvent.change(screen.getByLabelText('NVD filter scope'), { target: { value: first } });
    expect(screen.getByRole('button', { name: 'Inspect observed intervals' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Next NVD scopes' }));
    await screen.findByRole('option', { name: new RegExp(second) });
    expect(screen.getByRole('button', { name: 'Inspect observed intervals' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Load NVD filter scopes' }));
    await screen.findByRole('option', { name: new RegExp(first) });
    expect(screen.getByRole('button', { name: 'Inspect observed intervals' })).toBeDisabled();
  });
  it('inspects NVD observed windows without claiming historical completeness', async () => {
    const scope = `nvd:${'a'.repeat(32)}`;
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.includes('/nvd-observed-scopes')) return { items: [{ feedKey: scope, observedWindowCount: 2,
        firstObservedIntervalStart: '2026-01-01T00:00:00Z', latestObservedIntervalEnd: '2026-01-03T00:00:00Z' }],
        hasMore: false, nextAfterFeedKey: null };
      if (path.includes('/nvd-observed-gaps')) return { feedKey: scope, from: '2026-01-01T00:00:00Z',
        to: '2026-01-04T00:00:00Z', observedWindowCount: 2,
        unobservedIntervals: [{ from: '2026-01-02T00:00:00Z', to: '2026-01-03T00:00:00Z' }],
        historicalCoverageStatus: 'UNKNOWN' };
      return { items: [], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null };
    });
    renderPage();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].includes('nvd-observed-scopes'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Load NVD filter scopes' }));
    await screen.findByRole('option', { name: /2 observed windows/ });
    fireEvent.change(screen.getByLabelText('NVD filter scope'), { target: { value: scope } });
    fireEvent.change(screen.getByLabelText('From date (UTC, inclusive)'), { target: { value: '2026-01-01' } });
    fireEvent.change(screen.getByLabelText('To date (UTC, exclusive)'), { target: { value: '2026-01-04' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect observed intervals' }));
    expect(await screen.findByText(/2 overlapping observed windows/)).toHaveTextContent('no completeness proof');
    expect(screen.getByText(/No successful interval observation from/)).toHaveTextContent('2026-01-02T00:00:00Z');
    expect(vi.mocked(apiRequest).mock.calls.some(call => decodeURIComponent(call[0]).includes(`feedKey=${scope}`))).toBe(true);
    fireEvent.change(screen.getByLabelText('To date (UTC, exclusive)'), { target: { value: '2026-01-01' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect observed intervals' }));
    expect(screen.getByRole('alert')).toHaveTextContent('positive UTC interval');
    expect(screen.queryByText(/2 overlapping observed windows/)).not.toBeInTheDocument();
  });
  it('plans bounded NVD baseline windows without presenting them as certified coverage', async () => {
    const scope = `nvd:${'a'.repeat(32)}`;
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.includes('/nvd-observed-scopes')) return { items: [{ feedKey: scope, observedWindowCount: 1,
        firstObservedIntervalStart: '2025-01-01T00:00:00Z', latestObservedIntervalEnd: '2025-05-01T00:00:00Z' }],
        hasMore: false, nextAfterFeedKey: null };
      if (path.includes('/nvd-baseline-plan')) return { feedKey: scope, from: '2025-01-01T00:00:00Z',
        to: '2025-05-02T00:00:00Z', historicalCoverageStatus: 'UNKNOWN', partitions: [
          { from: '2025-01-01T00:00:00Z', to: '2025-05-01T00:00:00Z', observedWindowCount: 1, unobservedIntervals: [] },
          { from: '2025-05-01T00:00:00Z', to: '2025-05-02T00:00:00Z', observedWindowCount: 0,
            unobservedIntervals: [{ from: '2025-05-01T00:00:00Z', to: '2025-05-02T00:00:00Z' }] }
        ] };
      return { items: [], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null };
    });
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: 'Load NVD filter scopes' }));
    await screen.findByRole('option', { name: /1 observed windows/ });
    fireEvent.change(screen.getByLabelText('NVD filter scope'), { target: { value: scope } });
    fireEvent.change(screen.getByLabelText('From date (UTC, inclusive)'), { target: { value: '2025-01-01' } });
    fireEvent.change(screen.getByLabelText('To date (UTC, exclusive)'), { target: { value: '2025-05-02' } });
    fireEvent.click(screen.getByRole('button', { name: 'Plan baseline windows' }));
    expect(await screen.findByText(/2 bounded windows/)).toHaveTextContent('completeness remains unknown');
    expect(screen.getByText(/1 unobserved interval\(s\)/)).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].includes('/nvd-baseline-plan'))).toBe(true);
  });
  it('shows central records without tenant exposure fields and sends typed filters', async () => {
    vi.mocked(apiRequest).mockResolvedValue({ items: [{
      id: '1', externalId: 'GHSA-test', kind: 'OTHER', status: 'ACTIVE', title: 'An advisory',
      severity: 'HIGH', cvssScore: 7, epssScore: null, inKev: false, sourceSystems: ['ghsa', 'nvd']
    }], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null });
    renderPage();
    expect(await screen.findByRole('link', { name: 'GHSA-test' })).toBeInTheDocument();
    expect(screen.queryByText('Open findings')).not.toBeInTheDocument();
    expect(screen.getByText('ghsa, nvd')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Record kind'), { target: { value: 'OTHER' } });
    fireEvent.change(screen.getByLabelText('Publication status'), { target: { value: 'WITHDRAWN' } });
    await waitFor(() => expect(apiRequest).toHaveBeenLastCalledWith(expect.stringContaining('kind=OTHER&status=WITHDRAWN&size=25')));
  });

  it('distinguishes a failed request from an empty catalog and supports retry', async () => {
    vi.mocked(apiRequest).mockRejectedValueOnce(new Error('Unavailable')).mockResolvedValue({
      items: [], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null
    });
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('Unavailable');
    expect(screen.queryByText('No published records match these filters.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No published records match these filters.')).toBeInTheDocument();
    expect(screen.getByText('Page 1')).toBeInTheDocument();
  });

  it('follows a keyset cursor and returns to the first page', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => path.includes('afterExternalId=')
      ? { items: [{ id: '2', externalId: 'CVE-2098-2', kind: 'CVE', status: 'ACTIVE', title: 'Second', severity: 'HIGH', cvssScore: 8, epssScore: null, inKev: false, sourceSystems: [] }],
          size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null }
      : { items: [{ id: '1', externalId: 'CVE-2098-1', kind: 'CVE', status: 'ACTIVE', title: 'First', severity: 'HIGH', cvssScore: 8, epssScore: null, inKev: false, sourceSystems: [] }],
          size: 25, hasMore: true, nextAfterExternalId: 'CVE-2098-1', nextAfterId: '1' });
    renderPage();
    expect(await screen.findByRole('link', { name: 'CVE-2098-1' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByRole('link', { name: 'CVE-2098-2' })).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].includes('afterExternalId=CVE-2098-1&afterId=1'))).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    expect(await screen.findByRole('link', { name: 'CVE-2098-1' })).toBeInTheDocument();
  });

  it('keeps acquisition, publication and tenant delivery counts separate', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => path.endsWith('/platform/intelligence/progress')
      ? { acquisition: { source: 'NVD', status: 'completed', fetchedRecords: 4000, failedRecords: 0 },
          publication: { activeGeneration: 3, pendingReviewCandidates: 1, pendingPublicationJobs: 0 },
          tenantDelivery: { activeTenants: 5, currentTenants: 2, updatingTenants: 2, failedTenants: 1, staleCheckpoints: 1 },
          catalogInventory: { canonicalRecords: 120, activeCanonicalRecords: 115, withdrawnCanonicalRecords: 5, sourceObservationRows: 180 },
          sources: [{ source: 'NVD', latestRunId: 'run-1', latestRunStatus: 'completed', latestFetchedRecords: 4000, historicalCoverageStatus: 'UNKNOWN', observedWindowCount: 2, observedFilterScopeCount: 1, latestObservedIntervalEnd: null, evidenceRole: 'VULNERABILITY', acquisitionScope: 'FILTERED_PAGINATED_API', tenantPolicySelectable: true },
            { source: 'EUVD', latestRunId: null, latestRunStatus: null, latestFetchedRecords: 0, historicalCoverageStatus: 'UNKNOWN', observedWindowCount: 0, observedFilterScopeCount: 0, latestObservedIntervalEnd: null, evidenceRole: 'VULNERABILITY', acquisitionScope: 'BOUNDED_PAGINATED_API', tenantPolicySelectable: true }],
          assetEvaluationStatus: 'NOT_SEPARATELY_TRACKED' }
      : { items: [], size: 25, hasMore: false, nextAfterExternalId: null, nextAfterId: null });
    renderPage();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].endsWith('/platform/intelligence/progress'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Load pipeline status' }));
    expect(await screen.findByText(/4000 fetched source records/)).toBeInTheDocument();
    expect(screen.getByText(/active generation 3/)).toBeInTheDocument();
    expect(screen.getByText(/120 canonical records \(115 active, 5 withdrawn\); 180 source-observation rows/)).toBeInTheDocument();
    expect(screen.getByText(/2 current, 2 updating, 1 failed of 5 active tenants/)).toBeInTheDocument();
    expect(screen.getByText(/stale partial-scan checkpoints: 1 \(will restart\)/)).toBeInTheDocument();
    expect(screen.getByText(/not separately tracked yet/)).toBeInTheDocument();
    expect(screen.getByText('2 across 1 filter scope')).toBeInTheDocument();
    expect(screen.getByText('FILTERED PAGINATED API')).toBeInTheDocument();
    expect(screen.getAllByText('Unknown — no completeness proof')).toHaveLength(2);
    expect(screen.getByText('No run recorded')).toBeInTheDocument();
  });
});
