import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { buildFinding, findingPageOf } from '../../test/fixtures';
import { renderWithProviders } from '../../test/test-utils';
import { AddFindingsDialog } from './AddFindingsDialog';
import { CampaignExceptionForm } from './CampaignExceptionForm';
import { CampaignMembersPanel } from './CampaignMembersPanel';
import { CampaignMembershipStatus } from './CampaignMembershipStatus';
import { CampaignOwnerBucketsPanel } from './CampaignOwnerBucketsPanel';
import { OwnerChangeIndicator } from './OwnerChangeIndicator';
import { ownerAtAddLabel, outcomeLabel, type OwnerBucket } from './ownership';
import type { CampaignMember, CampaignReconciliation } from './types';

function member(overrides: Partial<CampaignMember> = {}): CampaignMember {
  return {
    findingId: 'f-1', displayId: 'F-100', title: 'OpenSSL overflow', findingKind: 'VULNERABILITY', severity: 'HIGH',
    findingStatus: 'OPEN', closedReason: null, outcome: 'OPEN', suppressedUntil: null, dueAt: null, assetId: null, assetName: null,
    addedAt: '2026-11-01T00:00:00Z', addedBy: 'system', addSource: 'CREATE',
    ownerAtAdd: { teamId: 'team-1', teamName: 'Payments', status: 'OWNED', assignmentId: 'a-1' },
    currentOwnership: {
      objectId: 'f-1', authorityDomain: 'CORE', authorityState: 'CANONICAL', ownerTeamId: 'team-2', ownerTeamName: 'Identity',
      ownershipStatus: 'OWNED', sourceKind: 'MANUAL', resolvedAt: null, legacyOwnerLabel: null,
    },
    ownershipChanged: false, ownerAssignedSinceLaunch: false, campaignExceptionStatus: null,
    ...overrides,
  };
}

afterEach(() => vi.restoreAllMocks());

describe('owner labels and indicator', () => {
  it('never reports a legacy or unrecorded owner at add as Unowned', () => {
    expect(ownerAtAddLabel({ teamId: null, teamName: null, status: 'LEGACY_PENDING_MIGRATION', assignmentId: null })).toBe('Pending migration');
    expect(ownerAtAddLabel({ teamId: null, teamName: null, status: null, assignmentId: null })).toBe('Not recorded');
    expect(ownerAtAddLabel({ teamId: null, teamName: null, status: 'UNOWNED', assignmentId: null })).toBe('Unowned');
    expect(ownerAtAddLabel({ teamId: null, teamName: null, status: 'CONFLICT', assignmentId: null })).toBe('Conflict');
    expect(ownerAtAddLabel({ teamId: 't', teamName: null, status: 'OWNED', assignmentId: null })).toBe('Owned');
    expect(outcomeLabel('FALSE_POSITIVE')).toBe('False positive');
  });

  it('flags a change but shows a calm note when an owner was assigned since launch', () => {
    const { rerender } = renderWithProviders(<OwnerChangeIndicator member={{ ownershipChanged: true, ownerAssignedSinceLaunch: false }} />);
    expect(screen.getByText('Owner changed')).toBeInTheDocument();
    rerender(<OwnerChangeIndicator member={{ ownershipChanged: false, ownerAssignedSinceLaunch: true }} />);
    expect(screen.getByText('Owner assigned since launch')).toBeInTheDocument();
    expect(screen.queryByText('Owner changed')).not.toBeInTheDocument();
    rerender(<OwnerChangeIndicator member={{ ownershipChanged: false, ownerAssignedSinceLaunch: false }} />);
    expect(screen.queryByText(/Owner/)).not.toBeInTheDocument();
  });
});

describe('CampaignOwnerBucketsPanel', () => {
  it('switches between current owner and owner at add', async () => {
    const list = vi.spyOn(api, 'listCampaignOwnerBuckets').mockImplementation(async (_id, groupBy): Promise<OwnerBucket[]> => groupBy === 'atAdd'
      ? [{ bucket: 'NOT_RECORDED', teamId: null, teamName: null, members: 4, activeRemaining: 4, outcomes: {} }]
      : [{ bucket: 'TEAM', teamId: 't1', teamName: 'Payments', members: 6, activeRemaining: 5, outcomes: { REMEDIATED: 1 } },
        { bucket: 'PENDING_MIGRATION', teamId: null, teamName: null, members: 2, activeRemaining: 2, outcomes: {} }]);
    renderWithProviders(<CampaignOwnerBucketsPanel campaignId="c1" />);
    expect(await screen.findByText('Payments')).toBeInTheDocument();
    expect(screen.getByText('Pending migration')).toBeInTheDocument();
    expect(screen.queryByText('Unowned')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Owner at add' }));
    expect(await screen.findByText('Not recorded')).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith('c1', 'atAdd');
  });

  it('shows an error with retry', async () => {
    vi.spyOn(api, 'listCampaignOwnerBuckets').mockRejectedValue(new Error('boom'));
    renderWithProviders(<CampaignOwnerBucketsPanel campaignId="c1" />);
    expect(await screen.findByText('Owner buckets could not be loaded.')).toBeInTheDocument();
  });
});

describe('CampaignMembersPanel', () => {
  it('pages with a cursor, filters by outcome and can include hidden members', async () => {
    const list = vi.spyOn(api, 'listCampaignMembers').mockImplementation(async (_id, params) => {
      if (params?.cursor === 'next-1') return { items: [member({ findingId: 'f-2', displayId: 'F-200', title: 'Second' })], nextCursor: null };
      return { items: [member({ ownershipChanged: true }), member({ findingId: 'f-3', displayId: 'F-300', title: 'Legacy', ownerAtAdd: { teamId: null, teamName: null, status: 'LEGACY_PENDING_MIGRATION', assignmentId: null },
        currentOwnership: null, ownerAssignedSinceLaunch: true })], nextCursor: 'next-1' };
    });
    renderWithProviders(<CampaignMembersPanel campaignId="c1" />);
    expect(await screen.findByText('F-100')).toBeInTheDocument();
    expect(screen.getByText('Owner changed')).toBeInTheDocument();
    expect(screen.getByText('Owner assigned since launch')).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith('c1', expect.objectContaining({ includeHidden: false, outcome: undefined, limit: 50 }));

    fireEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('F-200')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Outcome'), { target: { value: 'SUPPRESSED' } });
    await waitFor(() => expect(list).toHaveBeenCalledWith('c1', expect.objectContaining({ outcome: 'SUPPRESSED' })));
    fireEvent.click(screen.getByLabelText(/Include hidden/));
    await waitFor(() => expect(list).toHaveBeenCalledWith('c1', expect.objectContaining({ includeHidden: true })));
  });

  it('reports a filtered-empty result and a load failure', async () => {
    const list = vi.spyOn(api, 'listCampaignMembers').mockResolvedValue({ items: [], nextCursor: null });
    renderWithProviders(<CampaignMembersPanel campaignId="c1" />);
    expect(await screen.findByText('No members yet')).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/Include hidden/));
    expect(await screen.findByText('No members match this outcome.')).toBeInTheDocument();
    list.mockRejectedValue(new Error('down'));
    fireEvent.change(screen.getByLabelText('Outcome'), { target: { value: 'OPEN' } });
    expect(await screen.findByText('Campaign members could not be loaded.')).toBeInTheDocument();
  });
});

describe('CampaignMembershipStatus', () => {
  const base: CampaignReconciliation = {
    campaignId: 'c1', scopeKind: 'CVE', membershipState: 'COMPLETE', reconciledAt: '2026-11-02T00:00:00Z', watermark: null,
    lastAdded: 3, lastError: null, consecutiveFailures: 0, members: 40,
  };

  it('shows the materializing banner and the last reconciliation with failures', async () => {
    vi.spyOn(api, 'getCampaignReconciliation').mockResolvedValue({ ...base, membershipState: 'MATERIALIZING', consecutiveFailures: 2, lastError: 'timeout' });
    renderWithProviders(<CampaignMembershipStatus campaignId="c1" summary={{ membershipState: 'MATERIALIZING', totalFindings: 5000 }} />);
    expect(screen.getByText(/still adding members: 5000 so far/)).toBeInTheDocument();
    expect(await screen.findByText(/2 consecutive failures/)).toHaveTextContent('last error: timeout');
    expect(screen.getByText(/3 added in the last run/)).toBeInTheDocument();
  });

  it('describes a findings campaign as fixed scope and tolerates a failed read', async () => {
    const read = vi.spyOn(api, 'getCampaignReconciliation').mockResolvedValue({ ...base, scopeKind: 'FINDINGS', consecutiveFailures: 1 });
    const { unmount } = renderWithProviders(<CampaignMembershipStatus campaignId="c1" summary={{ membershipState: 'COMPLETE', totalFindings: 40 }} />);
    expect(await screen.findByText(/fixed scope, no automatic additions/)).toBeInTheDocument();
    expect(screen.getByText(/1 consecutive failure$/)).toBeInTheDocument();
    expect(screen.queryByText(/still adding members/)).not.toBeInTheDocument();
    unmount();
    read.mockRejectedValue(new Error('x'));
    renderWithProviders(<CampaignMembershipStatus campaignId="c1" summary={{ membershipState: 'COMPLETE', totalFindings: 40 }} />);
    expect(await screen.findByText('Reconciliation status could not be loaded.')).toBeInTheDocument();
  });
});

describe('CampaignExceptionForm', () => {
  it('requests an exception for a chosen member finding and labels it campaign-only', async () => {
    vi.spyOn(api, 'listCampaignMembers').mockResolvedValue({ items: [member()], nextCursor: 'more' });
    const add = vi.spyOn(api, 'addCampaignException').mockResolvedValue({ id: 'e1' } as never);
    const onCreated = vi.fn();
    renderWithProviders(<CampaignExceptionForm campaignId="c1" onCreated={onCreated} />);
    expect(screen.getByText(/Campaign-only exception, does not change the finding/)).toBeInTheDocument();
    const submit = screen.getByRole('button', { name: 'Request exception' });
    expect(submit).toBeDisabled();
    await screen.findByRole('option', { name: /F-100/ });
    expect(screen.getByText(/Showing the first 1 members/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Member finding'), { target: { value: 'f-1' } });
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Vendor patch pending' } });
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'Waiting on vendor' } });
    fireEvent.change(screen.getByLabelText('Decision due (optional)'), { target: { value: '2026-12-01' } });
    fireEvent.click(submit);
    await waitFor(() => expect(add).toHaveBeenCalledWith('c1', expect.objectContaining({ findingId: 'f-1', title: 'Vendor patch pending', reason: 'Waiting on vendor' })));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(screen.getByLabelText('Title')).toHaveValue('');
  });

  it('shows a refused exception without clearing the draft', async () => {
    vi.spyOn(api, 'listCampaignMembers').mockResolvedValue({ items: [member()], nextCursor: null });
    vi.spyOn(api, 'addCampaignException').mockRejectedValue(new Error('Finding is not a member of this campaign'));
    renderWithProviders(<CampaignExceptionForm campaignId="c1" onCreated={vi.fn()} />);
    await screen.findByRole('option', { name: /F-100/ });
    fireEvent.change(screen.getByLabelText('Member finding'), { target: { value: 'f-1' } });
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'T' } });
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'R' } });
    fireEvent.click(screen.getByRole('button', { name: 'Request exception' }));
    expect(await screen.findByText('Finding is not a member of this campaign')).toBeInTheDocument();
    expect(screen.getByLabelText('Title')).toHaveValue('T');
  });

  it('reports members that could not be loaded', async () => {
    vi.spyOn(api, 'listCampaignMembers').mockRejectedValue(new Error('x'));
    renderWithProviders(<CampaignExceptionForm campaignId="c1" onCreated={vi.fn()} />);
    expect(await screen.findByText('Campaign members could not be loaded.')).toBeInTheDocument();
  });
});

describe('AddFindingsDialog', () => {
  it('searches, selects across searches and saves through the members endpoint', async () => {
    const list = vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([buildFinding({ id: 'f-9', displayId: 'F-009' })]));
    const add = vi.spyOn(api, 'addCampaignMembers').mockResolvedValue({ summary: { id: 'c1' } } as never);
    const onAdded = vi.fn();
    const onClose = vi.fn();
    renderWithProviders(<AddFindingsDialog campaignId="c1" isOpen onClose={onClose} onAdded={onAdded} />);
    const dialog = screen.getByRole('dialog', { name: 'Add findings to campaign' });
    expect(within(dialog).getByRole('button', { name: 'Add 0 findings' })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Search findings'), { target: { value: 'CVE-2026-1234' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Search' }));
    fireEvent.click(await within(dialog).findByLabelText('Select F-009'));
    expect(list).toHaveBeenCalledWith(expect.objectContaining({ vulnerabilityId: 'CVE-2026-1234' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add 1 finding' }));
    await waitFor(() => expect(add).toHaveBeenCalledWith('c1', ['f-9']));
    await waitFor(() => expect(onAdded).toHaveBeenCalled());
    expect(onClose).toHaveBeenCalled();
  });

  it('keeps the selection and shows the server reason when the campaign is closed', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([buildFinding({ id: 'f-9', displayId: 'F-009' })]));
    vi.spyOn(api, 'addCampaignMembers').mockRejectedValue(new Error('Campaign is closed'));
    renderWithProviders(<AddFindingsDialog campaignId="c1" isOpen onClose={vi.fn()} onAdded={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Search by'), { target: { value: 'assetName' } });
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'web' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    fireEvent.click(await screen.findByLabelText('Select F-009'));
    fireEvent.click(screen.getByRole('button', { name: 'Add 1 finding' }));
    expect(await screen.findByText('Campaign is closed')).toBeInTheDocument();
    expect(screen.getByLabelText('Select F-009')).toBeChecked();
  });

  it('reports an empty search and a failed search', async () => {
    const list = vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([]));
    renderWithProviders(<AddFindingsDialog campaignId="c1" isOpen onClose={vi.fn()} onAdded={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'nothing' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    expect(await screen.findByText('No findings match.')).toBeInTheDocument();
    list.mockRejectedValue(new Error('x'));
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'again' } });
    fireEvent.click(screen.getByRole('button', { name: 'Search' }));
    expect(await screen.findByText('Findings could not be searched.')).toBeInTheDocument();
  });
});
