import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { ApiError, api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { cveWorkbenchApi } from '../cve-workbench/api';
import { CampaignDetailPage } from './CampaignDetailPage';
import type { CampaignDetail, CampaignSummary } from './types';

const ACTOR: ActorContext = {
  creator: false, principal: 'a@example.com', userId: 'u', tenantId: 't', tenantName: 'Acme', roles: ['ROLE_SECURITY_ANALYST'],
};

function summary(overrides: Partial<CampaignSummary> = {}): CampaignSummary {
  return {
    id: 'c1', name: 'Kernel sprint', summary: null, status: 'ACTIVE', scopeKind: 'CVE', membershipState: 'COMPLETE',
    assigneePrincipalId: null, coordinatingTeamId: null, dueAt: null, startedAt: null, updatedAt: '2026-11-01T00:00:00Z',
    cveIds: ['CVE-2026-1111'], totalFindings: 2, remediatedCount: 0, activeRemainingCount: 2,
    outcomes: { OPEN: 2, REOPENED: 0, CAMPAIGN_EXCEPTED: 0, REMEDIATED: 0, SUPPRESSED: 0, FALSE_POSITIVE: 0, ACCEPTED_RISK: 0, CLOSED_OTHER: 0 },
    assetCount: 1, exceptionCount: 0, notifyGroupCount: 0, watchlistCount: 0, completionPercent: 0, ...overrides,
  };
}

function detail(overrides: Partial<CampaignDetail> = {}, summaryOverrides: Partial<CampaignSummary> = {}): CampaignDetail {
  return {
    summary: summary(summaryOverrides),
    vulnerabilities: [{ externalId: 'CVE-2026-1111', title: 'Kernel issue', severity: 'HIGH' }],
    notifyGroups: [], watchlist: [], notes: [], exceptions: [], activity: [], deliveryAttempts: [], findings: [],
    assets: [{ assetId: 'a1', assetName: 'web-01', assetIdentifier: 'web-01', environment: null, activeFindings: 1, remediatedFindings: 0, members: 1 }],
    evidence: [], softwareItems: [{ id: 'sw-0', displayName: 'Existing app', vendor: null, assetCount: 1, openFindingCount: 0 }],
    ...overrides,
  };
}

const CVE_PAGE = {
  summary: { reviewQueueCount: 0, applicableCount: 0, impactedCount: 0, underInvestigationCount: 0, resolvedCount: 0 },
  items: [{ recordId: 'r', vulnerabilityId: 'v', externalId: 'CVE-2026-2222', title: 'OpenSSL', descriptionSnippet: 'Heap overflow' }],
  page: 0, size: 10, totalItems: 1, totalPages: 1,
};
const SOFTWARE_PAGE = {
  content: [{ id: 'sw-1', displayName: 'OpenSSL', vendor: 'OpenSSL', assetCount: 3, openFindingCount: 2 }],
  number: 0, size: 10, totalElements: 1, totalPages: 1,
};

function render(d: CampaignDetail) {
  vi.spyOn(api, 'getCampaign').mockResolvedValue(d);
  vi.spyOn(api, 'listCampaignMembers').mockResolvedValue({ items: [], nextCursor: null });
  vi.spyOn(api, 'listCampaignOwnerBuckets').mockResolvedValue([]);
  vi.spyOn(api, 'getCampaignReconciliation').mockRejectedValue(new Error('n/a'));
  vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue(CVE_PAGE as never);
  vi.spyOn(api, 'listSoftwareIdentities').mockResolvedValue(SOFTWARE_PAGE as never);
  return renderWithProviders(
    <ActorContextState.Provider value={ACTOR}>
      <Routes><Route path="/vuln-repo/campaigns/:id" element={<CampaignDetailPage />} /></Routes>
    </ActorContextState.Provider>,
    { route: '/vuln-repo/campaigns/c1' },
  );
}

afterEach(() => vi.restoreAllMocks());

describe('saved CVE and software scope', () => {
  it('saves a CVE and replaces the detail from the response without a local-edit notice', async () => {
    const updated = detail({
      vulnerabilities: [{ externalId: 'CVE-2026-1111', title: 'Kernel issue', severity: 'HIGH' }, { externalId: 'CVE-2026-2222', title: 'OpenSSL', severity: 'CRITICAL' }],
    }, { cveIds: ['CVE-2026-1111', 'CVE-2026-2222'], membershipState: 'MATERIALIZING', totalFindings: 40 });
    const add = vi.spyOn(api, 'addCampaignCves').mockResolvedValue(updated);
    render(detail());
    await openTab(/Vulnerabilities/);
    fireEvent.click(await screen.findByRole('button', { name: '+ Add CVE' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('checkbox'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 CVE' }));
    await waitFor(() => expect(add).toHaveBeenCalledWith('c1', ['CVE-2026-2222']));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByText(/Scope changes on this page are not saved/)).not.toBeInTheDocument();
    expect(await screen.findByText('CVE-2026-2222')).toBeInTheDocument();
  });

  it('keeps the CVE modal open and shows the server message on 400 and 409', async () => {
    const add = vi.spyOn(api, 'addCampaignCves')
      .mockRejectedValueOnce(new ApiError('Unknown CVE CVE-2026-2222', 400))
      .mockRejectedValue(new ApiError('Campaign is closed', 409));
    render(detail());
    await openTab(/Vulnerabilities/);
    fireEvent.click(await screen.findByRole('button', { name: '+ Add CVE' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('checkbox'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 CVE' }));
    expect(await within(dialog).findByText('Unknown CVE CVE-2026-2222')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 CVE' }));
    expect(await within(dialog).findByText('Campaign is closed')).toBeInTheDocument();
    expect(add).toHaveBeenCalledTimes(2);
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('saves software and shows a busy state while saving', async () => {
    let resolve: (value: CampaignDetail) => void = () => undefined;
    const add = vi.spyOn(api, 'addCampaignSoftware').mockImplementation(() => new Promise((r) => { resolve = r; }));
    render(detail());
    await openTab(/Impacted Products/);
    fireEvent.click(await screen.findByRole('button', { name: '+ Add Software' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('checkbox'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 Item' }));
    expect(await within(dialog).findByRole('button', { name: 'Saving…' })).toBeDisabled();
    await waitFor(() => expect(add).toHaveBeenCalledWith('c1', ['sw-1']));
    resolve(detail({ softwareItems: [{ id: 'sw-1', displayName: 'OpenSSL', vendor: 'OpenSSL', assetCount: 3, openFindingCount: 2 }] }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByText(/Scope changes on this page are not saved/)).not.toBeInTheDocument();
    expect((await screen.findAllByText('OpenSSL')).length).toBeGreaterThan(0);
  });

  it('shows the server message when saving software fails', async () => {
    vi.spyOn(api, 'addCampaignSoftware').mockRejectedValue(new ApiError('Campaign is not CVE-scoped', 409));
    render(detail());
    await openTab(/Impacted Products/);
    fireEvent.click(await screen.findByRole('button', { name: '+ Add Software' }));
    const dialog = await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('checkbox'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 Item' }));
    expect(await within(dialog).findByText('Campaign is not CVE-scoped')).toBeInTheDocument();
  });

  it('hides the add buttons for a findings-scoped campaign and a closed campaign', async () => {
    const { unmount } = render(detail({}, { scopeKind: 'FINDINGS' }));
    await openTab(/Vulnerabilities/);
    expect(screen.queryByRole('button', { name: '+ Add CVE' })).not.toBeInTheDocument();
    await openTab(/Impacted Products/);
    expect(screen.queryByRole('button', { name: '+ Add Software' })).not.toBeInTheDocument();
    unmount();
    render(detail({}, { status: 'CLOSED' }));
    await openTab(/Vulnerabilities/);
    expect(screen.queryByRole('button', { name: '+ Add CVE' })).not.toBeInTheDocument();
  });

  it('keeps deletes local-only with the not-saved notice', async () => {
    render(detail());
    await openTab(/Assets/);
    fireEvent.click(await screen.findByRole('button', { name: 'Remove web-01' }));
    expect(screen.getByText(/Scope changes on this page are not saved/)).toBeInTheDocument();
  });
});

async function openTab(name: RegExp) {
  await screen.findByRole('tablist');
  const tab = screen.getAllByRole('tab').find((t) => name.test(t.textContent ?? ''));
  if (!tab) throw new Error(`no tab ${name}`);
  fireEvent.click(tab);
}
