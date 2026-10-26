import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
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

    fireEvent.click(await screen.findByText('Kernel patch sprint'));
    await screen.findByRole('button', { name: 'Pause' });
    expect(screen.getAllByText('CVE-2026-1111').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

    await waitFor(() => {
      expect(api.updateCampaignStatus).toHaveBeenCalledWith('campaign-1', 'PAUSED');
    });
    await waitFor(() => {
      expect(screen.getAllByText('Paused').length).toBeGreaterThan(0);
    });
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

    fireEvent.click(screen.getByRole('button', { name: /^Assets/ }));
    expect(screen.getByRole('columnheader', { name: /SUPPORT GROUP/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /^Findings/ }));
    expect(screen.getAllByText('F-100').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole('button', { name: /^Vulnerabilities/ }));
    expect(screen.getByText('CVE-2026-1111')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /Exceptions/i }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Approve' })[0]!);

    await waitFor(() => {
      expect(updateExceptionSpy).toHaveBeenCalledWith('campaign-1', 'exception-1', 'APPROVED');
    });

    fireEvent.click(screen.getByRole('button', { name: /Activity/i }));
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
