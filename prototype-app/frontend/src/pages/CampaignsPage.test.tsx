import React from 'react';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { CampaignDetailPage } from '../features/campaigns/CampaignDetailPage';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { CampaignDetail, CampaignSummary } from '../features/campaigns/types';
import { renderWithProviders } from '../test/test-utils';
import { CampaignsPage } from './CampaignsPage';

const ACTOR: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

function buildSummary(overrides: Partial<CampaignSummary> = {}): CampaignSummary {
  return {
    id: 'campaign-1',
    name: 'Kernel patch sprint',
    summary: 'Coordinate resolver rollout',
    status: 'ACTIVE',
    dueAt: '2026-07-01T00:00:00Z',
    startedAt: '2026-06-10T00:00:00Z',
    updatedAt: '2026-06-10T12:00:00Z',
    cveIds: ['CVE-2026-1111'],
    totalFindings: 4,
    resolvedFindings: 1,
    openFindings: 3,
    assetCount: 2,
    exceptionCount: 0,
    notifyGroupCount: 1,
    watchlistCount: 1,
    completionPercent: 25,
    ...overrides,
  };
}

function buildDetail(overrides: Partial<CampaignDetail> = {}): CampaignDetail {
  const summary = buildSummary();
  return {
    summary,
    vulnerabilities: [{ externalId: 'CVE-2026-1111', title: 'Kernel issue', severity: 'HIGH' }],
    notifyGroups: [{
      id: 'group-1',
      groupName: 'Platform Ops',
      groupEmail: 'platform.ops@example.com',
      roleLabel: 'Owner group',
      triggerSummary: 'Status changes',
      notificationsPaused: false,
    }],
    watchlist: [{
      id: 'watch-1',
      entryType: 'USER',
      label: 'Alex Analyst',
      email: 'alex@example.com',
      triggerPolicy: 'ALL_EVENTS',
      active: true,
    }],
    notes: [],
    exceptions: [],
    activity: [{
      id: 'activity-1',
      activityType: 'CREATED',
      actor: 'analyst@example.com',
      body: 'Campaign created.',
      createdAt: '2026-06-10T00:00:00Z',
    }],
    deliveryAttempts: [],
    findings: [{
      findingId: 'uuid-f-100',
      displayId: 'F-100',
      vulnerabilityId: null,
      assetName: 'web-prod-01',
      assetIdentifier: 'asset-1',
      packageName: 'openssl',
      severity: 'HIGH',
      ownerGroup: 'Platform Ops',
      status: 'IMPACTED',
      dueAt: '2026-06-20T00:00:00Z',
      incidentId: 'INC-100',
    }],
    assets: [{
      assetId: 'uuid-asset-1',
      assetName: 'web-prod-01',
      assetIdentifier: 'asset-1',
      environment: 'prod',
      supportGroup: 'Platform Ops',
      openFindings: 1,
      resolvedFindings: 0,
    }],
    evidence: [],
    ...overrides,
  };
}

function cvePageOf(...externalIds: string[]) {
  return {
    summary: { reviewQueueCount: 0, applicableCount: 0, impactedCount: 0, underInvestigationCount: 0, resolvedCount: 0 },
    items: externalIds.map((externalId, index) => ({
      recordId: `record-${index}`,
      vulnerabilityId: `vuln-${index}`,
      externalId,
      title: `${externalId} title`,
      descriptionSnippet: 'Target CVE',
      applicability: 'APPLICABLE' as const,
      impacted: true,
      impactState: 'IMPACTED' as const,
      severity: 'CRITICAL',
      cvssScore: 9.8,
      epssScore: 0.7,
      inKev: true,
      matchedComponentCount: 1,
      matchedSoftwareCount: 1,
      matchedAssetCount: 1,
      applicableComponentCount: 1,
      impactedComponentCount: 1,
      notAffectedComponentCount: 0,
      fixedComponentCount: 0,
      noPatchComponentCount: 0,
      underInvestigationComponentCount: 0,
      unknownComponentCount: 0,
      openFindings: 1,
      eolComponentCount: 0,
      eosComponentCount: 0,
      hasInvestigationSummary: false,
      hasAiSolution: false,
    })),
    page: 0,
    size: 10,
    totalItems: externalIds.length,
    totalPages: 1,
  };
}

function renderCampaignsPage() {
  return renderWithProviders(
    <ActorContextState.Provider value={ACTOR}>
      <Routes>
        <Route path="/vuln-repo/campaigns" element={<CampaignsPage />} />
        <Route path="/vuln-repo/campaigns/:id" element={<CampaignDetailPage />} />
      </Routes>
    </ActorContextState.Provider>,
    { route: '/vuln-repo/campaigns' }
  );
}

function renderCampaignDetailPage(route = '/vuln-repo/campaigns/campaign-1') {
  return renderWithProviders(
    <ActorContextState.Provider value={ACTOR}>
      <Routes>
        <Route path="/vuln-repo/campaigns/:id" element={<CampaignDetailPage />} />
      </Routes>
    </ActorContextState.Provider>,
    { route }
  );
}

describe('CampaignsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders an existing campaign and transitions status from the detail actions', async () => {
    const activeSummary = buildSummary();
    const pausedSummary = buildSummary({ status: 'PAUSED', completionPercent: 30 });
    const activeDetail = buildDetail({ summary: activeSummary });
    const pausedDetail = buildDetail({ summary: pausedSummary });

    vi.spyOn(api, 'listCampaigns')
      .mockResolvedValueOnce([activeSummary])
      .mockResolvedValue([pausedSummary]);
    vi.spyOn(api, 'getCampaign')
      .mockResolvedValueOnce(activeDetail)
      .mockResolvedValue(pausedDetail);
    vi.spyOn(api, 'updateCampaignStatus').mockResolvedValue(pausedDetail);

    renderCampaignsPage();

    fireEvent.click(await screen.findByRole('link', { name: 'Kernel patch sprint' }));
    await screen.findByRole('button', { name: 'More actions' });
    expect(screen.getAllByText('CVE-2026-1111').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'More actions' }));
    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

    await waitFor(() => {
      expect(api.updateCampaignStatus).toHaveBeenCalledWith('campaign-1', 'PAUSED');
    });
    await waitFor(() => {
      expect(screen.getAllByText('Paused').length).toBeGreaterThan(0);
    });
    expect(screen.getByText('Campaign moved to Paused.')).toBeInTheDocument();
  });

  it('launches a campaign from the mock-aligned wizard using live CVE and watchlist data sources', async () => {
    const createdSummary = buildSummary({ id: 'campaign-2', name: 'Resolver runway' });
    const createdDetail = buildDetail({
      summary: createdSummary,
      watchlist: [{
        id: 'watch-2',
        entryType: 'USER',
        label: 'Jordan Resolver',
        email: 'jordan@example.com',
        triggerPolicy: 'STATUS_CHANGES',
        active: true,
      }],
    });

    vi.spyOn(api, 'listCampaigns')
      .mockResolvedValueOnce([])
      .mockResolvedValue([createdSummary]);
    vi.spyOn(api, 'getCampaign').mockResolvedValueOnce(createdDetail);
    vi.spyOn(api, 'listAssignmentGroups').mockResolvedValue(['Platform Ops', 'Server Team']);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([{
      id: 'member-1',
      userId: 'user-2',
      subject: 'jordan',
      email: 'jordan@example.com',
      displayName: 'Jordan Resolver',
      role: 'SECURITY_ANALYST',
      status: 'ACTIVE',
      createdAt: '2026-06-10T00:00:00Z',
    }]);
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue({
      summary: {
        reviewQueueCount: 1,
        applicableCount: 1,
        impactedCount: 0,
        underInvestigationCount: 0,
        resolvedCount: 0,
      },
      items: [{
        recordId: 'record-1',
        vulnerabilityId: 'vuln-1',
        externalId: 'CVE-2026-2222',
        title: 'OpenSSL resolver effort',
        descriptionSnippet: 'Target CVE',
        applicability: 'APPLICABLE',
        impacted: true,
        impactState: 'IMPACTED',
        severity: 'CRITICAL',
        cvssScore: 9.8,
        epssScore: 0.7,
        inKev: true,
        matchedComponentCount: 2,
        matchedSoftwareCount: 1,
        matchedAssetCount: 3,
        applicableComponentCount: 2,
        impactedComponentCount: 1,
        notAffectedComponentCount: 0,
        fixedComponentCount: 0,
        noPatchComponentCount: 0,
        underInvestigationComponentCount: 0,
        unknownComponentCount: 0,
        openFindings: 5,
        eolComponentCount: 0,
        eosComponentCount: 0,
        hasInvestigationSummary: true,
        hasAiSolution: true,
      }],
      page: 0,
      size: 100,
      totalItems: 1,
      totalPages: 1,
    });
    vi.spyOn(api, 'createCampaign').mockResolvedValue(createdDetail);

    renderCampaignsPage();

    await screen.findByText('No campaigns yet');
    fireEvent.click(screen.getByRole('button', { name: 'New Campaign' }));

    fireEvent.change(screen.getByLabelText('Campaign Name'), { target: { value: 'Resolver runway' } });
    fireEvent.change(screen.getByLabelText('Summary'), { target: { value: 'Coordinate the cross-team patch train.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await screen.findByText('CVE-2026-2222');
    fireEvent.click(screen.getByRole('checkbox', { name: /CVE-2026-2222/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    await screen.findByRole('button', { name: 'Platform Ops' });
    fireEvent.click(screen.getByRole('button', { name: 'Platform Ops' }));
    fireEvent.change(screen.getByLabelText('Trigger Policy'), { target: { value: 'STATUS_CHANGES' } });
    fireEvent.click(screen.getByRole('button', { name: /Jordan Resolver/i }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    fireEvent.change(screen.getByPlaceholderText(/Describe the urgency, context, or initial guidance for this campaign/i), { target: { value: 'Start outreach immediately.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Launch Campaign' }));

    await waitFor(() => {
      expect(api.createCampaign).toHaveBeenCalledWith(expect.objectContaining({
        name: 'Resolver runway',
        summary: 'Coordinate the cross-team patch train.',
        cveIds: ['CVE-2026-2222'],
        launchNote: 'Start outreach immediately.',
        notifyGroups: [expect.objectContaining({ groupName: 'Platform Ops' })],
        watchlist: [expect.objectContaining({
          label: 'Jordan Resolver',
          email: 'jordan@example.com',
          triggerPolicy: 'STATUS_CHANGES',
        })],
      }));
    });

    await waitFor(() => {
      expect(api.getCampaign).toHaveBeenCalledWith('campaign-2');
    });
    await screen.findByRole('heading', { name: 'Resolver runway' });
  });

  it('opens the wizard as a named modal that stays open while launching and keeps input on failure', async () => {
    vi.spyOn(api, 'listCampaigns').mockResolvedValue([]);
    vi.spyOn(api, 'listAssignmentGroups').mockResolvedValue([]);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([]);
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue(cvePageOf('CVE-2026-2222'));
    let rejectCreate: (reason: Error) => void = () => undefined;
    vi.spyOn(api, 'createCampaign').mockImplementation(() => new Promise((_, reject) => { rejectCreate = reject; }));

    renderCampaignsPage();
    await screen.findByText('No campaigns yet');
    const trigger = screen.getByRole('button', { name: 'New Campaign' });
    trigger.focus();
    fireEvent.click(trigger);

    const wizard = screen.getByRole('dialog', { name: 'New Campaign' });
    fireEvent.change(screen.getByLabelText('Campaign Name'), { target: { value: 'Resolver runway' } });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /CVE-2026-2222/i }));
    for (let step = 0; step < 2; step += 1) fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    fireEvent.click(screen.getByRole('button', { name: 'Launch Campaign' }));

    expect(await screen.findByText(/Launching the campaign/)).toBeInTheDocument();
    fireEvent.keyDown(wizard, { key: 'Escape' });
    expect(screen.getByRole('dialog', { name: 'New Campaign' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Close' })).toBeDisabled();

    rejectCreate(new Error('Campaign service unavailable'));
    expect(await screen.findByText('Campaign service unavailable')).toBeInTheDocument();
    fireEvent.keyDown(wizard, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('walks the campaign detail tabs, approves an existing exception, and adds a note', async () => {
    const detailWithPendingException = buildDetail({
      exceptions: [{
        id: 'exception-1',
        findingDisplayId: 'F-100',
        assetName: 'web-prod-01',
        packageName: 'openssl',
        title: 'Existing exception',
        reason: 'Waiting on coordinated patch window.',
        status: 'PENDING_DECISION',
        requestedBy: 'analyst@example.com',
        requestedAt: '2026-06-11T00:00:00Z',
        decisionDueAt: '2026-06-18T00:00:00Z',
        decisionedBy: null,
        decisionedAt: null,
      }],
      evidence: [{
        cveId: 'CVE-2026-1111',
        displayId: 'F-100',
        assetName: 'web-prod-01',
        assetIdentifier: 'asset-1',
        packageName: 'openssl',
        severity: 'HIGH',
        ownerGroup: 'Platform Ops',
        status: 'OPEN',
        incidentId: 'INC-100',
        dueAt: '2026-06-20T00:00:00Z',
      }],
    });
    const detailWithApprovedException = buildDetail({
      ...detailWithPendingException,
      exceptions: [{ ...detailWithPendingException.exceptions[0]!, status: 'APPROVED', decisionedBy: 'lead@example.com', decisionedAt: '2026-06-12T00:00:00Z' }],
      evidence: detailWithPendingException.evidence,
    });
    const detailWithNote = buildDetail({
      ...detailWithApprovedException,
      notes: [{
        id: 'note-1',
        author: 'analyst@example.com',
        body: 'Need resolver confirmation.',
        createdAt: '2026-06-12T00:00:00Z',
      }],
      evidence: detailWithPendingException.evidence,
    });

    vi.spyOn(api, 'getCampaign')
      .mockResolvedValueOnce(detailWithPendingException)
      .mockResolvedValueOnce(detailWithNote);
    const updateExceptionSpy = vi.spyOn(api, 'updateCampaignExceptionStatus').mockResolvedValue(detailWithApprovedException);
    const addNoteSpy = vi.spyOn(api, 'addCampaignNote').mockResolvedValue(detailWithNote.notes[0]!);

    renderCampaignDetailPage();

    await screen.findByRole('heading', { name: 'Kernel patch sprint' });

    fireEvent.click(screen.getByRole('tab', { name: /^Assets/ }));
    expect(screen.getByRole('columnheader', { name: /SUPPORT GROUP/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /^Findings/ }));
    expect(screen.getAllByText('F-100').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('tab', { name: /^Vulnerabilities/ }));
    expect(screen.getByText('CVE-2026-1111')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('tab', { name: /Exceptions/i }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Approve' })[0]!);

    await waitFor(() => {
      expect(updateExceptionSpy).toHaveBeenCalledWith('campaign-1', 'exception-1', 'APPROVED');
    });

    fireEvent.click(screen.getByRole('tab', { name: /Activity/i }));
    fireEvent.change(screen.getByPlaceholderText(/Add a note for resolvers and stakeholders/i), {
      target: { value: 'Need resolver confirmation.' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Add Note/i }));

    await waitFor(() => {
      expect(addNoteSpy).toHaveBeenCalledWith('campaign-1', 'Need resolver confirmation.');
    });
    await screen.findByText('Need resolver confirmation.');
  });
});

describe('CampaignsPage list and wizard states (U13)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows a load failure with retry instead of an empty list, and no zero counts', async () => {
    const listSpy = vi.spyOn(api, 'listCampaigns')
      .mockRejectedValueOnce(new Error('Gateway timeout'))
      .mockResolvedValue([buildSummary()]);

    renderCampaignsPage();

    expect(await screen.findByText(/Campaigns could not be loaded: Gateway timeout/)).toBeInTheDocument();
    expect(screen.queryByText('No campaigns yet')).not.toBeInTheDocument();
    expect(document.querySelectorAll('.campaign-tab-count')).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('link', { name: 'Kernel patch sprint' })).toHaveAttribute('href', '/vuln-repo/campaigns/campaign-1');
    expect(listSpy).toHaveBeenCalledTimes(2);
  });

  it('separates a status tab with no campaigns from an empty workspace and hides counts it did not load', async () => {
    vi.spyOn(api, 'listCampaigns').mockImplementation(async (status) => (status === 'PAUSED' ? [] : [buildSummary()]));

    renderCampaignsPage();
    await screen.findByRole('link', { name: 'Kernel patch sprint' });
    expect(screen.getByRole('button', { name: /All Campaigns/ })).toHaveTextContent('All Campaigns1');
    expect(screen.getByText('Showing 1–1 of 1 campaign')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Paused/ }));
    expect(await screen.findByText('No campaigns in Paused.')).toBeInTheDocument();
    expect(screen.queryByText('No campaigns yet')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^Paused/ })).toHaveAttribute('aria-pressed', 'true');
    // Only the requested status is counted; the others are unknown, not zero.
    expect(screen.getByRole('button', { name: /^Paused/ })).toHaveTextContent('Paused0');
    expect(screen.getByRole('button', { name: /All Campaigns/ })).toHaveTextContent(/^All Campaigns$/);

    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByRole('link', { name: 'Kernel patch sprint' })).toBeInTheDocument();
  });

  it('reports a search with no match as filtered-empty with a removable chip', async () => {
    vi.spyOn(api, 'listCampaigns').mockResolvedValue([buildSummary()]);
    renderCampaignsPage();
    await screen.findByRole('link', { name: 'Kernel patch sprint' });

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search campaigns' }), { target: { value: 'nomatch' } });
    expect(screen.getByText('No campaigns match the search.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter Search: nomatch' }));
    expect(screen.getByRole('link', { name: 'Kernel patch sprint' })).toBeInTheDocument();
  });

  it('blocks launch without CVE scope, previews launch recipients in place and reports recorded deliveries without claiming sent', async () => {
    const created = buildDetail({
      summary: buildSummary({ id: 'campaign-9', name: 'Resolver runway' }),
      deliveryAttempts: [
        { id: 'd-1', targetType: 'WATCHLIST', targetLabel: 'Jordan Resolver', targetAddress: 'jordan@example.com', subject: '[Campaign launched] Resolver runway', deliveryState: 'QUEUED', detail: null, createdAt: '2026-06-10T00:00:00Z' },
        { id: 'd-2', targetType: 'GROUP', targetLabel: 'Platform Ops', targetAddress: null, subject: '[Campaign launched] Resolver runway', deliveryState: 'SKIPPED', detail: 'No email configured for watchlist entry', createdAt: '2026-06-10T00:00:00Z' },
      ],
    });
    vi.spyOn(api, 'listCampaigns').mockResolvedValue([]);
    vi.spyOn(api, 'getCampaign').mockResolvedValue(created);
    vi.spyOn(api, 'listAssignmentGroups').mockResolvedValue(['Platform Ops']);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([{
      id: 'member-1', userId: 'user-2', subject: 'jordan', email: 'jordan@example.com', displayName: 'Jordan Resolver',
      role: 'SECURITY_ANALYST', status: 'ACTIVE', createdAt: '2026-06-10T00:00:00Z',
    }]);
    vi.spyOn(cveWorkbenchApi, 'listOrgSpecificCves').mockResolvedValue(cvePageOf('CVE-2026-2222'));
    const createSpy = vi.spyOn(api, 'createCampaign').mockResolvedValue(created);

    renderCampaignsPage();
    await screen.findByText('No campaigns yet');
    fireEvent.click(screen.getByRole('button', { name: 'New Campaign' }));
    fireEvent.change(screen.getByLabelText('Campaign Name'), { target: { value: 'Resolver runway' } });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByRole('checkbox', { name: /CVE-2026-2222/i });
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    // The notification compose no longer opens a second modal above the wizard.
    expect(screen.queryByRole('button', { name: /Compose Notification/ })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole('button', { name: 'Platform Ops' }));
    expect(screen.getByRole('button', { name: 'Platform Ops' })).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(screen.getByRole('button', { name: /Jordan Resolver/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));

    expect(screen.getByRole('button', { name: /^4\s*Launch$/ })).toHaveAttribute('aria-current', 'step');
    expect(screen.getByRole('alert')).toHaveTextContent('Select at least one CVE on the Scope step');
    expect(screen.getByRole('button', { name: 'Launch Campaign' })).toBeDisabled();
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    const preview = screen.getByRole('region', { name: 'Launch notifications' });
    expect(preview).toHaveTextContent('[Campaign launched] Resolver runway');
    expect(preview).toHaveTextContent('Platform Ops');
    expect(preview).toHaveTextContent('Watchlist · jordan@example.com');

    fireEvent.click(screen.getByRole('button', { name: 'Choose CVEs' }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /CVE-2026-2222/i }));
    fireEvent.click(screen.getByRole('button', { name: /^4\s*Launch$/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Launch Campaign' }));

    await waitFor(() => expect(createSpy).toHaveBeenCalledWith(expect.objectContaining({ cveIds: ['CVE-2026-2222'] })));
    expect(await screen.findByText(/2 launch notifications recorded: queued 1, skipped 1\./)).toBeInTheDocument();
    expect(screen.queryByText(/Notifications sent/i)).not.toBeInTheDocument();
  });
});

describe('CampaignDetailPage lifecycle, feedback and notifications (U13)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('offers one primary next action per status and keeps the other transitions in a secondary menu', async () => {
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail({ summary: buildSummary({ status: 'PAUSED' }) }));
    renderCampaignDetailPage();

    const primary = await screen.findByRole('button', { name: 'Resume' });
    expect(primary).toHaveClass('btn-primary');
    const menuButton = screen.getByRole('button', { name: 'More actions' });
    expect(menuButton).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(menuButton);
    expect(menuButton).toHaveAttribute('aria-expanded', 'true');
    const menu = screen.getByRole('list', { name: 'Lifecycle actions' });
    // The current status is not offered as a transition, and the primary action is not repeated.
    expect(Array.from(menu.querySelectorAll('button')).map((b) => b.textContent)).toEqual(['Move to Review', 'Mark Blocked', 'Close Campaign']);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(menuButton).toHaveAttribute('aria-expanded', 'false');
    expect(menuButton).toHaveFocus();
  });

  it('reports a failed transition next to the actions and keeps the campaign on screen', async () => {
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'updateCampaignStatus').mockRejectedValue(new Error('Conflict'));
    renderCampaignDetailPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Move to Review' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Move to Review failed: Conflict');
    expect(screen.getByRole('heading', { name: 'Kernel patch sprint' })).toBeInTheDocument();
    expect(screen.getByRole('tablist', { name: 'Campaign sections' })).toBeInTheDocument();
  });

  it('confirms closing in a named dialog that stays open and explains a failure', async () => {
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail({ summary: buildSummary({ status: 'IN_REVIEW' }) }));
    let rejectClose: (reason: Error) => void = () => undefined;
    const statusSpy = vi.spyOn(api, 'updateCampaignStatus').mockImplementation(() => new Promise((_, reject) => { rejectClose = reject; }));
    renderCampaignDetailPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Close Campaign' }));
    const dialog = screen.getByRole('dialog', { name: 'Close this campaign?' });
    expect(statusSpy).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close Campaign' }));
    expect(statusSpy).toHaveBeenCalledWith('campaign-1', 'CLOSED');
    expect(await within(dialog).findByText('Closing the campaign…')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Keep open' })).toBeDisabled();

    rejectClose(new Error('Server error'));
    expect(await within(dialog).findByText(/The campaign was not closed/)).toBeInTheDocument();
    expect(screen.getByRole('dialog', { name: 'Close this campaign?' })).toBeInTheDocument();
  });

  it('shows recorded deliveries in the notifications dialog without a send action or sent claim', async () => {
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail({
      deliveryAttempts: [{
        id: 'd-1', targetType: 'GROUP', targetLabel: 'Platform Ops', targetAddress: 'platform.ops@example.com',
        subject: '[Campaign update] Kernel patch sprint', deliveryState: 'QUEUED', detail: null, createdAt: '2026-06-11T00:00:00Z',
      }],
    }));
    renderCampaignDetailPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Notifications' }));
    const dialog = screen.getByRole('dialog', { name: /Notify Teams/ });
    expect(within(dialog).getByText('[Campaign update] Kernel patch sprint')).toBeInTheDocument();
    expect(within(dialog).getByText('Queued')).toBeInTheDocument();
    expect(within(dialog).getByText('platform.ops@example.com')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: /Send/ })).not.toBeInTheDocument();
    expect(within(dialog).queryByText(/sent/i)).not.toBeInTheDocument();
  });

  it('drafts a templated message and copies it without claiming it was sent', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail());
    renderCampaignDetailPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Notifications' }));
    const dialog = screen.getByRole('dialog', { name: /Notify Teams/ });
    fireEvent.change(within(dialog).getByLabelText('Template'), { target: { value: 'escalation' } });
    expect(within(dialog).getByLabelText('Subject')).toHaveValue('ESCALATION: Remediation Overdue — {{cve_id}} Requires Immediate Attention');
    const message = within(dialog).getByLabelText('Message') as HTMLTextAreaElement;
    fireEvent.change(message, { target: { value: 'Please patch.' } });
    message.setSelectionRange(0, 0);
    fireEvent.click(within(dialog).getByRole('button', { name: '{{cve_id}}' }));
    expect(message).toHaveValue('{{cve_id}}Please patch.');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Copy draft' }));
    expect(await within(dialog).findByText('Draft copied to the clipboard. Nothing was sent.')).toBeInTheDocument();
    expect(writeText).toHaveBeenCalledWith(expect.stringContaining('Subject: ESCALATION: Remediation Overdue'));
    expect(writeText.mock.calls[0][0]).toContain('Please patch.');

    writeText.mockRejectedValueOnce(new Error('denied'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Copy draft' }));
    expect(await within(dialog).findByText(/could not be copied/)).toBeInTheDocument();
  });

  it('uses real links for findings and CVEs and labels local-only scope edits', async () => {
    vi.spyOn(api, 'getCampaign').mockResolvedValue(buildDetail());
    renderCampaignDetailPage();

    fireEvent.click(await screen.findByRole('tab', { name: /^Findings/ }));
    expect(screen.getByRole('tab', { name: /^Findings/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('link', { name: 'F-100' })).toHaveAttribute('href', '/findings/uuid-f-100?returnTo=%2Fvuln-repo%2Fcampaigns%2Fcampaign-1');
    expect(screen.getByRole('link', { name: 'CVE-2026-1111' })).toHaveAttribute('href', expect.stringContaining('CVE-2026-1111'));

    fireEvent.click(screen.getByRole('tab', { name: /^Assets/ }));
    expect(screen.getByRole('link', { name: 'web-prod-01' })).toHaveAttribute('href', expect.stringContaining('uuid-asset-1'));
    fireEvent.click(screen.getByRole('button', { name: 'Remove web-prod-01' }));
    expect(screen.getByText(/Scope changes on this page are not saved/)).toBeInTheDocument();
  });

  it('shows a load failure with retry and a real link back to the list', async () => {
    const getSpy = vi.spyOn(api, 'getCampaign')
      .mockRejectedValueOnce(new Error('Gateway timeout'))
      .mockResolvedValue(buildDetail());
    renderCampaignDetailPage();

    expect(await screen.findByText(/The campaign could not be loaded: Gateway timeout/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to Campaigns' })).toHaveAttribute('href', '/vuln-repo/campaigns');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('heading', { name: 'Kernel patch sprint' })).toBeInTheDocument();
    expect(getSpy).toHaveBeenCalledTimes(2);
  });
});
