import React from 'react';
import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { canAddCustomCampaignRecipient, canCreateTickets } from '../auth/roles';
import type { ActorContext } from '../auth/types';
import type { OwnershipTeam } from '../ownership/types';
import { CampaignLaunchPreview } from './CampaignLaunchPreview';
import { CampaignLaunchOptions, CampaignRecipientsPicker } from './CampaignRecipients';
import { notifyDraftsToRequest, type NotifyDraft } from './notifyDrafts';
import { useCampaignPreview } from './useCampaignPreview';
import type { CampaignPreview } from './types';

const team = (id: string, name: string, notificationChannel = true): OwnershipTeam => ({
  id, name, parentTeamId: null, ticketAssignmentGroup: null, status: 'ACTIVE', notificationChannel, version: 1,
});

afterEach(() => vi.restoreAllMocks());

function Harness({ canAddCustom, withoutChannel = [] }: { canAddCustom: boolean; withoutChannel?: string[] }) {
  const [value, setValue] = React.useState<NotifyDraft[]>([]);
  return (
    <>
      <CampaignRecipientsPicker
        teams={[team('t1', 'Payments'), team('t2', 'Identity', false)]} teamsLoading={false} teamsError={false}
        value={value} onChange={setValue} canAddCustom={canAddCustom} teamsWithoutChannel={new Set(withoutChannel)}
      />
      <pre data-testid="request">{JSON.stringify(notifyDraftsToRequest(value))}</pre>
    </>
  );
}

describe('CampaignRecipientsPicker', () => {
  it('sends TEAM recipients by ID without an address and warns about a team with no channel', () => {
    renderWithProviders(<Harness canAddCustom={false} />);
    fireEvent.click(screen.getByRole('button', { name: 'Payments' }));
    fireEvent.click(screen.getByRole('button', { name: 'Identity' }));
    expect(screen.getByText(/Identity has no notification channel/)).toBeInTheDocument();
    expect(screen.queryByText(/Payments has no notification channel/)).not.toBeInTheDocument();
    const request = JSON.parse(screen.getByTestId('request').textContent ?? '[]') as Array<Record<string, unknown>>;
    expect(request).toHaveLength(2);
    expect(request[0]).toMatchObject({ recipientType: 'TEAM', teamId: 't1' });
    expect(request[0]).not.toHaveProperty('groupEmail');
    fireEvent.click(screen.getByRole('button', { name: 'Payments' }));
    expect(JSON.parse(screen.getByTestId('request').textContent ?? '[]')).toHaveLength(1);
  });

  it('uses the preview to flag a team without a channel', () => {
    renderWithProviders(<Harness canAddCustom={false} withoutChannel={['t1']} />);
    fireEvent.click(screen.getByRole('button', { name: 'Payments' }));
    expect(screen.getByText(/Payments has no notification channel/)).toBeInTheDocument();
  });

  it('offers custom recipients only to permitted roles and labels them as not owner recipients', () => {
    const { unmount } = renderWithProviders(<Harness canAddCustom={false} />);
    expect(screen.queryByText(/Custom recipient \(not an owner recipient\)/)).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<Harness canAddCustom />);
    expect(screen.getByText('Custom recipient (not an owner recipient)')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Recipient label'), { target: { value: 'Vendor desk' } });
    fireEvent.change(screen.getByLabelText('Recipient email'), { target: { value: 'desk@example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add custom recipient' }));
    expect(screen.getByText(/Vendor desk · desk@example.com · not an owner recipient/)).toBeInTheDocument();
    expect(JSON.parse(screen.getByTestId('request').textContent ?? '[]')[0]).toMatchObject({
      recipientType: 'CUSTOM', groupEmail: 'desk@example.com',
    });
    fireEvent.click(screen.getByRole('button', { name: 'Remove Vendor desk' }));
    expect(screen.queryByText(/Vendor desk ·/)).not.toBeInTheDocument();
  });

  it('shows team load states', () => {
    renderWithProviders(<CampaignRecipientsPicker teams={[]} teamsLoading teamsError={false} value={[]} onChange={vi.fn()} canAddCustom={false} teamsWithoutChannel={new Set()} />);
    expect(screen.getByText('Loading teams…')).toBeInTheDocument();
  });

  it('shows an error and an empty state for teams', () => {
    const { unmount } = renderWithProviders(<CampaignRecipientsPicker teams={[]} teamsLoading={false} teamsError value={[]} onChange={vi.fn()} canAddCustom={false} teamsWithoutChannel={new Set()} />);
    expect(screen.getByText('Teams could not be loaded.')).toBeInTheDocument();
    unmount();
    renderWithProviders(<CampaignRecipientsPicker teams={[]} teamsLoading={false} teamsError={false} value={[]} onChange={vi.fn()} canAddCustom={false} teamsWithoutChannel={new Set()} />);
    expect(screen.getByText(/No active teams yet/)).toBeInTheDocument();
  });
});

describe('CampaignLaunchOptions', () => {
  it('reports the coordinating team and includeExcepted choices', () => {
    const onTeam = vi.fn();
    const onExcepted = vi.fn();
    renderWithProviders(<CampaignLaunchOptions teams={[team('t1', 'Payments')]} coordinatingTeamId="" includeExcepted={false} onCoordinatingTeam={onTeam} onIncludeExcepted={onExcepted} />);
    fireEvent.change(screen.getByLabelText('Coordinating team (optional)'), { target: { value: 't1' } });
    fireEvent.click(screen.getByLabelText(/Include suppressed/));
    expect(onTeam).toHaveBeenCalledWith('t1');
    expect(onExcepted).toHaveBeenCalledWith(true);
  });
});

function PreviewHarness({ enabled = true }: { enabled?: boolean }) {
  const preview = useCampaignPreview({ name: 'n', cveIds: ['CVE-1'] }, enabled);
  return <CampaignLaunchPreview preview={preview} />;
}

describe('CampaignLaunchPreview', () => {
  const data: CampaignPreview = {
    memberCount: 5200, exceedsCreateBound: true, excluded: { CLOSED: 4, SUPPRESSED: 0 },
    teamsWithoutChannel: [{ teamId: 't2', teamName: 'Identity' }],
    distribution: [{ bucket: 'UNOWNED', teamId: null, teamName: null, members: 1, activeRemaining: 1, outcomes: {} },
      { bucket: 'CONFLICT', teamId: null, teamName: null, members: 2, activeRemaining: 2, outcomes: {} }],
  };

  it('shows counts, distribution, exclusions, the over-bound warning and teams without a channel', async () => {
    vi.spyOn(api, 'previewCampaign').mockResolvedValue(data);
    renderWithProviders(<PreviewHarness />);
    expect(screen.getByText(/Checking what this campaign would contain/)).toBeInTheDocument();
    expect(await screen.findByText(/5200/)).toBeInTheDocument();
    expect(screen.getByText(/larger than the launch limit/)).toBeInTheDocument();
    expect(screen.getByText('Unowned: 1')).toBeInTheDocument();
    expect(screen.getByText('Conflict: 2')).toBeInTheDocument();
    expect(screen.getByText('Left out: 4 closed.')).toBeInTheDocument();
    expect(screen.getByText(/No notification channel: Identity/)).toBeInTheDocument();
  });

  it('shows a failure with retry', async () => {
    const preview = vi.spyOn(api, 'previewCampaign').mockRejectedValueOnce(new Error('preview down')).mockResolvedValue({ ...data, exceedsCreateBound: false, excluded: {}, teamsWithoutChannel: [], distribution: [] });
    renderWithProviders(<PreviewHarness />);
    expect(await screen.findByText(/preview down/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry preview' }));
    expect(await screen.findByText(/5200/)).toBeInTheDocument();
    expect(preview).toHaveBeenCalledTimes(2);
  });
});

describe('role helpers for tickets and custom recipients', () => {
  const actor = (roles: string[], platformScope = false): ActorContext => ({ creator: false, principal: 'p', userId: 'u', tenantId: 't', tenantName: 'T', roles, platformScope });
  it('allows only the roles the server accepts', () => {
    expect(canCreateTickets(actor(['ROLE_SECURITY_ANALYST']))).toBe(true);
    expect(canCreateTickets(actor(['ROLE_PLATFORM_OWNER']))).toBe(true);
    expect(canCreateTickets(actor(['ROLE_PLATFORM_OWNER'], true))).toBe(false);
    expect(canCreateTickets(actor(['ROLE_READ_ONLY_AUDITOR']))).toBe(false);
    expect(canAddCustomCampaignRecipient(actor(['ROLE_TENANT_ADMIN']))).toBe(true);
    expect(canAddCustomCampaignRecipient(actor(['ROLE_INVENTORY_ADMIN']))).toBe(false);
  });
});
