import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiRequest } from '../api/client';
import { TenantCatalogPage } from './TenantCatalogPage';

vi.mock('../api/client', () => ({ apiRequest: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });
function mount() {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })}>
    <TenantCatalogPage tenantId="tenant-a" />
  </QueryClientProvider>);
}
const recordId = '00000000-0000-0000-0000-000000000001';
describe('TenantCatalogPage', () => {
  it('checks legacy filter gaps on demand without creating or activating a policy', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [];
      if (path.endsWith('/legacy-compatibility')) return { enabledSources: ['nvd', 'kev'],
        gaps: [{ source: 'nvd', reason: 'FILTER_NOT_REPRESENTABLE', fields: ['cpeName', 'hasKev'] }] };
      return [];
    });
    mount();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].endsWith('/legacy-compatibility'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Check legacy settings' }));
    expect(await screen.findByText(/nvd — FILTER_NOT_REPRESENTABLE \(cpeName, hasKev\)/)).toBeInTheDocument();
    expect(screen.getByText(/Enabled source preferences: nvd, kev/)).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[1]?.method === 'POST')).toBe(false);
    expect(screen.queryByRole('button', { name: /^activate catalog$/i })).not.toBeInTheDocument();
  });

  it('explains that a saved source alias does not change the canonical preference', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [];
      if (path.endsWith('/legacy-compatibility')) return { enabledSources: ['jvn'],
        gaps: [{ source: 'jvndb', reason: 'SOURCE_ALIAS_NOT_APPLIED', canonicalSource: 'jvn', fields: [] }] };
      return [];
    });
    mount();
    fireEvent.click(screen.getByRole('button', { name: 'Check legacy settings' }));
    expect(await screen.findByText(/jvndb — saved alias is not applied to the jvn preference/)).toBeInTheDocument();
    expect(screen.getByText(/Enabled source preferences: jvn/)).toBeInTheDocument();
  });

  it('reuses a build request ID after uncertain failure', async () => {
    let attempts = 0;
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path.endsWith('/versions')) return [{ version: 2 }];
      if (options?.method === 'POST') {
        attempts++;
        if (attempts === 1) throw new Error('Network interrupted');
        return { id: 'build-1', policyVersion: 2, status: 'QUEUED' };
      }
      return [];
    });
    mount();
    const button = screen.getByRole('button', { name: 'Build review catalog' });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
    expect(await screen.findByRole('alert')).toHaveTextContent('Network interrupted');
    fireEvent.click(button);
    await waitFor(() => expect(attempts).toBe(2));
    const posts = vi.mocked(apiRequest).mock.calls.filter(call => call[1]?.method === 'POST');
    expect(JSON.parse(posts[0][1]?.body as string)).toEqual(JSON.parse(posts[1][1]?.body as string));
    expect(JSON.parse(posts[0][1]?.body as string).policyVersion).toBe(2);
    expect(screen.queryByRole('button', { name: /^activate catalog$/i })).not.toBeInTheDocument();
  });

  it('loads override history and submits its expected revision without deleting records', async () => {
    vi.mocked(apiRequest).mockImplementation(async (path, options) => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.includes('/overrides/')) {
        if (options?.method === 'POST') return { revision: 3 };
        return [{ revision: 2, operation: 'EXCLUDE', reason: 'Prior reason', createdAt: '2026-01-01T00:00:00Z', expiresAt: null }];
      }
      return [];
    });
    mount();
    fireEvent.change(screen.getByLabelText('Central record UUID'), { target: { value: recordId } });
    fireEvent.click(screen.getByRole('button', { name: 'Load override history' }));
    await waitFor(() => expect(screen.getByLabelText('Reason')).toBeEnabled());
    fireEvent.change(screen.getByLabelText('Operation'), { target: { value: 'RESTORE' } });
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Relevant again' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save override' }));
    expect(await screen.findByText(/Override saved/)).toBeInTheDocument();
    const call = vi.mocked(apiRequest).mock.calls.find(call => call[1]?.method === 'POST');
    expect(call?.[0]).toContain(recordId);
    expect(JSON.parse(call?.[1]?.body as string)).toEqual({ expectedRevision: 2, operation: 'RESTORE', reason: 'Relevant again', expiresAt: null });
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[1]?.method === 'DELETE')).toBe(false);
  });

  it('blocks new builds while a worker build is active', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      return [{ id: 'build-1', policyVersion: 1, generation: 1, status: 'BUILDING', scanned: 100, matched: 12, lastError: null }];
    });
    mount();
    expect(await screen.findByText(/100 scanned, 12 selected/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Build review catalog' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel policy 1 build' })).toBeEnabled();
  });

  it('blocks new builds when build history cannot be loaded', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      throw new Error('History unavailable');
    });
    mount();
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load catalog workspace');
    expect(screen.getByRole('button', { name: 'Build review catalog' })).toBeDisabled();
  });

  it('loads a finding comparison only when requested for a completed build', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.endsWith('/finding-comparison')) return { selectedRecords: 2, existingFindingRows: 3, unlinkedFindingRows: 1,
        findingRowsOutsideSelection: 1, distinctRecordsOutsideSelection: 1,
        openOutsideSelection: 1, suppressedOutsideSelection: 0, resolvedOutsideSelection: 0, autoClosedOutsideSelection: 0 };
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 2, matched: 2, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].endsWith('/finding-comparison'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Compare with existing findings' }));
    expect(await screen.findByText(/1 rows across 1 records are outside this selection/)).toBeInTheDocument();
    expect(screen.getByText(/1 other finding rows have no central vulnerability link/)).toBeInTheDocument();
    expect(screen.getByText(/Status: 1 open, 0 suppressed, 0 resolved, 0 auto-closed/)).toBeInTheDocument();
    expect(vi.mocked(apiRequest).mock.calls.filter(call => call[0].endsWith('/finding-comparison'))).toHaveLength(1);
  });

  it('labels organization CVE overlap as observed rows, not legacy eligibility parity', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.endsWith('/org-cve-comparison')) return { selectedRecords: 5, existingOrgCveRecords: 2,
        overlappingRecords: 1, orgCveRecordsOutsideSelection: 1, selectedWithoutOrgCveRecord: 4 };
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 5, matched: 5, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].endsWith('/org-cve-comparison'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Compare organization CVE records' }));
    expect(await screen.findByText(/2 existing organization CVE records; 1 overlap this selection/)).toBeInTheDocument();
    expect(screen.getByText(/not a complete legacy eligibility baseline/)).toBeInTheDocument();
  });

  it('loads bounded difference pages only on demand and uses a keyset cursor', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.includes('/org-cve-differences')) {
        if (path.includes('afterId=')) return { direction: 'SELECTED_WITHOUT_ORG', records: [], nextAfterId: null, complete: true };
        return { direction: 'SELECTED_WITHOUT_ORG', records: [{ vulnerabilityId: recordId, externalId: 'CVE-2026-TEST' }],
          nextAfterId: recordId, complete: false };
      }
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 1, matched: 1, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].includes('/org-cve-differences'))).toBe(false);
    fireEvent.change(screen.getByLabelText('Difference type'), { target: { value: 'SELECTED_WITHOUT_ORG' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect differences' }));
    expect(await screen.findByText(/CVE-2026-TEST/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next differences' }));
    await waitFor(() => expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].includes(`afterId=${recordId}`))).toBe(true));
    expect(screen.queryByText(/CVE-2026-TEST/)).not.toBeInTheDocument();
  });

  it('hides a previously successful comparison when a recheck fails', async () => {
    let checks = 0;
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.endsWith('/finding-comparison')) {
        if (++checks > 1) throw new Error('Build inputs changed');
        return { selectedRecords: 2, existingFindingRows: 3, unlinkedFindingRows: 0,
          findingRowsOutsideSelection: 1, distinctRecordsOutsideSelection: 1,
          openOutsideSelection: 1, suppressedOutsideSelection: 0, resolvedOutsideSelection: 0, autoClosedOutsideSelection: 0 };
      }
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 2, matched: 2, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    fireEvent.click(screen.getByRole('button', { name: 'Compare with existing findings' }));
    expect(await screen.findByText(/1 rows across 1 records are outside this selection/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Compare with existing findings' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Build inputs changed');
    expect(screen.queryByText(/1 rows across 1 records are outside this selection/)).not.toBeInTheDocument();
  });

  it('checks READY build inputs on demand without offering activation', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.endsWith('/input-status')) return { buildId: 'build-ready', current: false, reason: 'INPUTS_CHANGED',
        policyVersion: 1, latestPolicyVersion: 1, latestPolicy: true };
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 2, matched: 2, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    expect(vi.mocked(apiRequest).mock.calls.some(call => call[0].endsWith('/input-status'))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Check build inputs' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('build inputs had changed');
    expect(screen.queryByRole('button', { name: /^activate catalog$/i })).not.toBeInTheDocument();
  });

  it('warns that a matching READY build uses an older saved policy version', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 2 }];
      if (path.endsWith('/input-status')) return { buildId: 'build-ready', current: true, reason: 'INPUTS_MATCH',
        policyVersion: 1, latestPolicyVersion: 2, latestPolicy: false };
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 2, matched: 2, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    fireEvent.click(screen.getByRole('button', { name: 'Check build inputs' }));
    expect(await screen.findByText(/build inputs matched/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('version 1, but version 2 is now latest');
    expect(screen.queryByRole('button', { name: /^activate catalog$/i })).not.toBeInTheDocument();
  });

  it('shows fail-closed activation review without an activation action', async () => {
    vi.mocked(apiRequest).mockImplementation(async path => {
      if (path.endsWith('/versions')) return [{ version: 1 }];
      if (path.endsWith('/activation-readiness')) return { buildId: 'build-ready', localChecksPass: true,
        activationEnabled: false, blockers: ['RELEASE_GATES_UNQUALIFIED'] };
      if (path.endsWith('/members')) return [];
      return [{ id: 'build-ready', policyVersion: 1, generation: 1, status: 'READY', scanned: 2, matched: 2, lastError: null }];
    });
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect policy 1 build' }));
    fireEvent.click(screen.getByRole('button', { name: 'Check activation readiness' }));
    expect(await screen.findByText(/Local build checks pass, but release qualification remains open/)).toBeInTheDocument();
    expect(screen.getByText(/RELEASE_GATES_UNQUALIFIED/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^activate catalog$/i })).not.toBeInTheDocument();
  });
});
