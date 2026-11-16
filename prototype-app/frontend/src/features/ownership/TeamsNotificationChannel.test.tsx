import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { TeamsPanel } from './TeamsPanel';
import type { OwnershipTeam } from './types';

const team = (overrides: Partial<OwnershipTeam> = {}): OwnershipTeam => ({
  id: 'team-1', name: 'Payments', parentTeamId: null, ticketAssignmentGroup: null, status: 'ACTIVE', notificationChannel: false, version: 3, ...overrides,
});

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe('Teams notification channel', () => {
  it('shows channel state without ever showing an address', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team(), team({ id: 'team-2', name: 'Identity', notificationChannel: true })]);
    renderWithProviders(<TeamsPanel canWrite />);
    expect(await screen.findByText('Channel configured')).toBeInTheDocument();
    expect(screen.getByText('No channel')).toBeInTheDocument();
  });

  it('sets a notification email write-only on save', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team()]);
    const update = vi.spyOn(api, 'updateOwnershipTeam').mockResolvedValue(team({ notificationChannel: true, version: 4 }));
    renderWithProviders(<TeamsPanel canWrite />);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit team' });
    fireEvent.change(within(dialog).getByLabelText('Notification email (optional)'), { target: { value: ' pay@example.com ' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save team' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('team-1', expect.objectContaining({ notificationEmail: 'pay@example.com', version: 3 })));
  });

  it('keeps the stored channel when the field is left empty and clears it on request', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team({ notificationChannel: true })]);
    const update = vi.spyOn(api, 'updateOwnershipTeam').mockResolvedValue(team());
    renderWithProviders(<TeamsPanel canWrite />);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    let dialog = await screen.findByRole('dialog', { name: 'Edit team' });
    expect(within(dialog).getByLabelText('Notification email (optional)')).toHaveAttribute('placeholder', expect.stringContaining('Channel configured'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save team' }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update.mock.calls[0][1].notificationEmail).toBeUndefined();

    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    dialog = await screen.findByRole('dialog', { name: 'Edit team' });
    fireEvent.click(within(dialog).getByLabelText('Clear the notification channel'));
    expect(within(dialog).getByLabelText('Notification email (optional)')).toBeDisabled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save team' }));
    await waitFor(() => expect(update).toHaveBeenCalledTimes(2));
    expect(update.mock.calls[1][1].notificationEmail).toBe('');
  });

  it('shows the server reason when tenant encryption is not ready', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team()]);
    vi.spyOn(api, 'updateOwnershipTeam').mockRejectedValue(new Error('Tenant encryption is not ready'));
    renderWithProviders(<TeamsPanel canWrite />);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit team' });
    fireEvent.change(within(dialog).getByLabelText('Notification email (optional)'), { target: { value: 'a@example.com' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save team' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Tenant encryption is not ready');
    expect(within(dialog).getByLabelText('Notification email (optional)')).toHaveValue('a@example.com');
  });
});
