import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, ticketRoutingChangedPreview } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import type { TicketPreview } from '../connect/types';
import { FindingTicketDialog } from './FindingTicketDialog';
import { OwnerChangedSinceTicketNote } from './OwnerChangedSinceTicketNote';
import { CryptoTicketAttempts } from './CryptoTicketAttempts';
import { ownerChangedSinceTicket, routingSourceLabel } from './ticketRouting';
import type { FindingTicketAttempt } from '../cbom/types';

const canonical = (overrides: Partial<TicketPreview> = {}): TicketPreview => ({
  canonical: true,
  batches: [{ bucket: 'TEAM', teamId: 't1', teamName: 'Payments', assignmentGroup: 'SN-PAY', routingSource: 'TEAM_MAPPING', findingIds: ['f1'] }],
  unroutable: [], excluded: [], tenantDefaultGroup: null, routingHash: 'hash-1', expiresAt: '2026-11-16T10:00:00Z', ...overrides,
});

const attempt = (overrides: Partial<FindingTicketAttempt> = {}): FindingTicketAttempt => ({
  id: 'a1', provider: 'jira', template: 'DEFAULT', outcome: 'SUCCEEDED', ticketKey: 'SEC-1', errorMessage: null,
  attemptedBy: 'u', attemptedAt: '2026-11-10T00:00:00Z', ownerTeamId: 't1', ...overrides,
});

afterEach(() => vi.restoreAllMocks());

function open() {
  const onCreated = vi.fn();
  const onClose = vi.fn();
  renderWithProviders(<FindingTicketDialog findingId="f1" isOpen onClose={onClose} onCreated={onCreated} />);
  return { onCreated, onClose };
}

describe('FindingTicketDialog', () => {
  it('shows the owner team and the assignment group separately and sends the preview hash', async () => {
    vi.spyOn(api, 'previewTickets').mockResolvedValue(canonical());
    const create = vi.spyOn(api, 'createFindingTicket').mockResolvedValue({} as never);
    const { onCreated } = open();
    expect(await screen.findByText('Payments')).toBeInTheDocument();
    expect(screen.getByText('SN-PAY')).toBeInTheDocument();
    expect(screen.getByText('Team mapping')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create ticket' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('f1', { routingHash: 'hash-1' }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
  });

  it('keeps today\'s behaviour when routing is not canonical', async () => {
    vi.spyOn(api, 'previewTickets').mockResolvedValue({ ...canonical(), canonical: false, batches: [], routingHash: null });
    const create = vi.spyOn(api, 'createFindingTicket').mockResolvedValue({} as never);
    open();
    expect(await screen.findByText(/follows the existing behaviour/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create ticket' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('f1', {}));
  });

  it('requires a reason for an override and sends the applied override', async () => {
    const preview = vi.spyOn(api, 'previewTickets').mockResolvedValue(canonical());
    const create = vi.spyOn(api, 'createFindingTicket').mockResolvedValue({} as never);
    open();
    await screen.findByText('Payments');
    fireEvent.click(screen.getByLabelText('Override group'));
    expect(screen.getByRole('button', { name: 'Create ticket' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Override assignment group'), { target: { value: 'SOC' } });
    expect(screen.getByRole('button', { name: 'Apply override' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Reason for the override'), { target: { value: 'Incident bridge' } });
    fireEvent.click(screen.getByRole('button', { name: 'Apply override' }));
    await waitFor(() => expect(preview).toHaveBeenCalledWith(expect.objectContaining({ assignmentGroupOverride: 'SOC', overrideReason: 'Incident bridge' })));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Create ticket' })).toBeEnabled());
    fireEvent.click(screen.getByRole('button', { name: 'Create ticket' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith('f1', expect.objectContaining({
      routingHash: 'hash-1', assignmentGroupOverride: 'SOC', overrideReason: 'Incident bridge',
    })));
  });

  it('replaces the preview on a 409 and asks to confirm again without retrying', async () => {
    vi.spyOn(api, 'previewTickets').mockResolvedValue(canonical());
    const fresh = canonical({ routingHash: 'hash-2', batches: [{ bucket: 'TEAM', teamId: 't2', teamName: 'Identity', assignmentGroup: 'SN-ID', routingSource: 'TEAM_MAPPING', findingIds: ['f1'] }] });
    const create = vi.spyOn(api, 'createFindingTicket').mockRejectedValueOnce(
      new ApiError('Routing changed', 409, { code: 'TICKET_ROUTING_CHANGED', error: 'Routing changed', preview: fresh }),
    ).mockResolvedValue({} as never);
    open();
    await screen.findByText('Payments');
    fireEvent.click(screen.getByRole('button', { name: 'Create ticket' }));
    expect(await screen.findByText(/changed since this preview/)).toBeInTheDocument();
    expect(screen.getByText('Identity')).toBeInTheDocument();
    expect(screen.queryByText('Payments')).not.toBeInTheDocument();
    expect(create).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Confirm updated routing' }));
    await waitFor(() => expect(create).toHaveBeenLastCalledWith('f1', { routingHash: 'hash-2' }));
  });

  it('lists unroutable and excluded findings, and offers a group selection when nothing is routed', async () => {
    const preview = vi.spyOn(api, 'previewTickets').mockResolvedValue(canonical({
      batches: [], routingHash: 'h',
      unroutable: [{ findingId: 'f1', displayId: 'F-001', bucket: 'CONFLICT', teamId: null, reason: 'Ownership conflict' }],
      excluded: [{ findingId: 'f2', displayId: 'F-002', reason: 'Already ticketed' }],
    }));
    open();
    expect(await screen.findByText(/F-001: Ownership conflict/)).toBeInTheDocument();
    expect(screen.getByText(/Excluded F-002: Already ticketed/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create ticket' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Assignment group'), { target: { value: 'Ops' } });
    fireEvent.click(screen.getByRole('button', { name: 'Use this group' }));
    await waitFor(() => expect(preview).toHaveBeenCalledWith(expect.objectContaining({ selectedAssignmentGroup: 'Ops' })));
  });

  it('shows other create failures', async () => {
    vi.spyOn(api, 'previewTickets').mockResolvedValue(canonical());
    vi.spyOn(api, 'createFindingTicket').mockRejectedValue(new Error('Jira unavailable'));
    const { onClose } = open();
    await screen.findByText('Payments');
    fireEvent.click(screen.getByRole('button', { name: 'Create ticket' }));
    expect(await screen.findByText('Jira unavailable')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('reports a preview that cannot be loaded', async () => {
    vi.spyOn(api, 'previewTickets').mockRejectedValue(new Error('x'));
    open();
    expect(await screen.findByText('The routing preview could not be loaded.')).toBeInTheDocument();
  });
});

describe('ticketRoutingChangedPreview', () => {
  it('returns the fresh preview only for a 409 TICKET_ROUTING_CHANGED body', () => {
    const fresh = canonical();
    expect(ticketRoutingChangedPreview(new ApiError('x', 409, { code: 'TICKET_ROUTING_CHANGED', preview: fresh }))).toBe(fresh);
    expect(ticketRoutingChangedPreview(new ApiError('x', 409, { code: 'OTHER', preview: fresh }))).toBeNull();
    expect(ticketRoutingChangedPreview(new ApiError('x', 400, { code: 'TICKET_ROUTING_CHANGED', preview: fresh }))).toBeNull();
    expect(ticketRoutingChangedPreview(new ApiError('x', 409))).toBeNull();
    expect(ticketRoutingChangedPreview(new Error('x'))).toBeNull();
  });
});

describe('owner changed since ticket', () => {
  const owned = { authorityState: 'CANONICAL', ownershipStatus: 'OWNED', ownerTeamId: 't2' };
  it('compares canonical owners only', () => {
    expect(ownerChangedSinceTicket([attempt()], owned)).toBe(true);
    expect(ownerChangedSinceTicket([attempt({ ownerTeamId: 't2' })], owned)).toBe(false);
    expect(ownerChangedSinceTicket([attempt({ ownerTeamId: null })], owned)).toBe(false);
    expect(ownerChangedSinceTicket([attempt({ outcome: 'FAILED' })], owned)).toBe(false);
    expect(ownerChangedSinceTicket([attempt()], { ...owned, authorityState: 'LEGACY_PENDING_MIGRATION' })).toBe(false);
    expect(ownerChangedSinceTicket([attempt()], { ...owned, ownershipStatus: 'UNOWNED' })).toBe(false);
    expect(ownerChangedSinceTicket(undefined, undefined)).toBe(false);
    expect(ownerChangedSinceTicket([attempt({ id: 'old', ownerTeamId: 't2', attemptedAt: '2026-11-01T00:00:00Z' }), attempt()], owned)).toBe(true);
  });

  it('labels routing sources', () => {
    expect(routingSourceLabel('OVERRIDE')).toBe('Override');
    expect(routingSourceLabel('TENANT_DEFAULT')).toBe('Tenant default group');
    expect(routingSourceLabel('USER_SELECTED')).toBe('Selected by a user');
    expect(routingSourceLabel('LEGACY')).toBe('Existing routing');
    expect(routingSourceLabel(undefined)).toBe('Not recorded');
  });

  it('renders the note on finding detail only when the owner changed', async () => {
    vi.spyOn(api, 'listFindingTicketAttempts').mockResolvedValue([attempt()]);
    const { unmount } = renderWithProviders(<OwnerChangedSinceTicketNote findingId="f1" ownership={{ displayName: 'x', ...owned }} />);
    expect(await screen.findByText(/Owner changed since ticket/)).toBeInTheDocument();
    unmount();
    renderWithProviders(<OwnerChangedSinceTicketNote findingId="f1" ownership={{ displayName: 'x', ...owned, ownerTeamId: 't1' }} />);
    await waitFor(() => expect(api.listFindingTicketAttempts).toHaveBeenCalledTimes(2));
    expect(screen.queryByText(/Owner changed since ticket/)).not.toBeInTheDocument();
  });
});

describe('CryptoTicketAttempts routing fields', () => {
  it('shows the group, routing source and override reason of an attempt', async () => {
    vi.spyOn(api, 'listFindingTicketAttempts').mockResolvedValue([
      attempt({ assignmentGroup: 'SOC', routingSource: 'OVERRIDE', overrideReason: 'Incident bridge' }),
    ]);
    renderWithProviders(<CryptoTicketAttempts findingId="f1" ticketed canRetry onTicketed={vi.fn()} />);
    const list = await screen.findByRole('list');
    expect(within(list).getByText(/group SOC \(Override\)/)).toBeInTheDocument();
    expect(within(list).getByText('Override reason: Incident bridge')).toBeInTheDocument();
  });
});
