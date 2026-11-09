import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { OwnershipDirectoryHub } from './OwnershipDirectoryHub';
import type { OwnershipCoverage, OwnershipQualification, OwnershipTeam } from './types';

function actor(role: string): ActorContext {
  return { creator: false, principal: `${role.toLowerCase()}@example.test`, userId: 'u-1', tenantId: 't-1', tenantName: 'Acme', roles: [`ROLE_${role}`] };
}

const coverage = (overrides: Partial<OwnershipCoverage> = {}): OwnershipCoverage => ({
  authorityState: 'LEGACY_PENDING_MIGRATION', owned: 12, unowned: 3, conflict: 1, unlinked: 4, refreshing: 0, ...overrides
});

const team = (overrides: Partial<OwnershipTeam> = {}): OwnershipTeam => ({
  id: 'team-1', name: 'Payments', parentTeamId: null, ticketAssignmentGroup: 'SN-PAY', status: 'ACTIVE', version: 3, ...overrides
});

const qualification = (overrides: Partial<OwnershipQualification> = {}): OwnershipQualification => ({
  domain: 'CORE', state: 'DARK', passed: true, blockers: [], checks: { unlinkedAssets: 0, queuedResolutions: 0 },
  comparison: { match: 10, mismatch: 2, legacyOnly: 1, canonicalOnly: 0, bothEmpty: 5 }, reportHash: 'abcdef0123456789', ...overrides
});

function renderHub(role: string, view?: string) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor(role)}>
      <OwnershipDirectoryHub legacyRules={<p>legacy rule editor</p>} />
    </ActorContextState.Provider>,
    { route: view ? `/configurations/ownership?view=${view}` : '/configurations/ownership' }
  );
}

describe('OwnershipDirectoryHub', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getOwnershipCoverage').mockResolvedValue(coverage());
    vi.spyOn(api, 'getOwnershipEncryption').mockResolvedValue({ ready: true, reason: null });
    vi.spyOn(api, 'getOwnershipQualification').mockResolvedValue(qualification({ state: 'LEGACY', passed: false }));
  });
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows directory views by role and keeps the legacy editor until inventory is canonical', async () => {
    renderHub('TENANT_ADMIN');
    const views = screen.getByRole('group', { name: 'Ownership & Directory views' });
    for (const label of ['Overview', 'Teams', 'People', 'Groups', 'Imports', 'Review']) {
      expect(within(views).getByRole('button', { name: label })).toBeInTheDocument();
    }
    expect(await within(views).findByRole('button', { name: 'Legacy rules' })).toBeInTheDocument();
    expect(await screen.findAllByText('Canonical model (not yet authoritative)')).not.toHaveLength(0);
  });

  it('hides directory and import views from a read-only auditor and the legacy view once canonical', async () => {
    vi.mocked(api.getOwnershipCoverage).mockResolvedValue(coverage({ authorityState: 'CANONICAL' }));
    renderHub('READ_ONLY_AUDITOR');
    const views = screen.getByRole('group', { name: 'Ownership & Directory views' });
    await waitFor(() => expect(within(views).queryByRole('button', { name: 'Legacy rules' })).not.toBeInTheDocument());
    expect(within(views).queryByRole('button', { name: 'People' })).not.toBeInTheDocument();
    expect(within(views).queryByRole('button', { name: 'Imports' })).not.toBeInTheDocument();
    // Auditors see coverage but not tenant-admin readiness or cutover controls.
    expect(screen.queryByRole('region', { name: 'Tenant encryption' })).not.toBeInTheDocument();
    expect(api.getOwnershipQualification).not.toHaveBeenCalled();
  });

  it('creates a team and archives one only after confirmation', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team()]);
    const create = vi.spyOn(api, 'createOwnershipTeam').mockResolvedValue(team({ id: 'team-2', name: 'Identity' }));
    const update = vi.spyOn(api, 'updateOwnershipTeam').mockResolvedValue(team({ status: 'ARCHIVED', version: 4 }));
    renderHub('INVENTORY_ADMIN', 'teams');

    expect(await screen.findByText('Payments')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create team' }));
    const dialog = await screen.findByRole('dialog', { name: 'Create team' });
    fireEvent.change(within(dialog).getByLabelText('Team name'), { target: { value: ' Identity ' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create team' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith({ name: 'Identity', ticketAssignmentGroup: null }));
    expect(await screen.findByText('Team Identity created.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Archive' }));
    expect(update).not.toHaveBeenCalled();
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Archive Payments?' })).getByRole('button', { name: 'Archive team' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('team-1', {
      parentTeamId: null, ticketAssignmentGroup: 'SN-PAY', status: 'ARCHIVED', version: 3
    }));
  });

  it('keeps the team draft and shows the server reason when a name is taken', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([]);
    vi.spyOn(api, 'createOwnershipTeam').mockRejectedValue(new Error('That name is already used by another team or alias'));
    renderHub('TENANT_ADMIN', 'teams');
    expect(await screen.findByText('No teams yet')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Create team' }));
    const dialog = await screen.findByRole('dialog', { name: 'Create team' });
    fireEvent.change(within(dialog).getByLabelText('Team name'), { target: { value: 'Payments' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create team' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('already used by another team or alias');
    expect(within(dialog).getByLabelText('Team name')).toHaveValue('Payments');
  });

  it('searches people only from two letters and shows contact fields masked', async () => {
    const search = vi.spyOn(api, 'searchDirectoryPeople').mockResolvedValue([
      { id: 'p-1', displayName: 'Ada Lovelace', emailMasked: 'a***@example.test', employeeIdMasked: '***42', managerUserId: null, status: 'ACTIVE', version: 1 }
    ]);
    renderHub('SECURITY_ANALYST', 'people');
    expect(screen.getByText('Search the directory')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search people by name'), { target: { value: 'a' } });
    expect(search).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('Search people by name'), { target: { value: 'ad' } });
    expect(await screen.findByText('Ada Lovelace')).toBeInTheDocument();
    expect(screen.getByText('a***@example.test')).toBeInTheDocument();
    expect(search).toHaveBeenCalledWith('ad', 50);
    // Analysts can view but not change the directory.
    expect(screen.queryByRole('button', { name: 'Add person' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deactivate' })).not.toBeInTheDocument();
  });

  it('runs a dry run that changes nothing, then commits the same file with the preview token', async () => {
    const preview = vi.spyOn(api, 'previewDirectoryImport').mockResolvedValue({
      runId: 'token-1', kind: 'USERS', state: 'VALIDATED', counts: { CREATE: 2, REJECTED: 1 },
      rows: [{ row: 4, outcome: 'REJECTED', message: 'display_name is required' }], warnings: []
    });
    const commit = vi.spyOn(api, 'commitDirectoryImport').mockResolvedValue({
      runId: 'run-1', kind: 'USERS', state: 'COMPLETED', counts: { CREATE: 2, REJECTED: 1 }, rows: [], warnings: []
    });
    renderHub('TENANT_ADMIN', 'imports');
    const file = new File(['external_id,display_name\n'], 'users.csv', { type: 'text/csv' });
    fireEvent.change(screen.getByLabelText('CSV file (UTF-8)'), { target: { files: [file] } });
    fireEvent.click(screen.getByRole('button', { name: 'Run dry run' }));

    expect(await screen.findByText(/Dry run complete — nothing has been changed yet/)).toBeInTheDocument();
    expect(preview).toHaveBeenCalledWith('USERS', file);
    expect(screen.getByText('display_name is required')).toBeInTheDocument();
    expect(commit).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: 'Import valid rows' }));
    await waitFor(() => expect(commit).toHaveBeenCalledWith('token-1', file));
    expect(await screen.findByText(/Import finished \(completed\)/)).toBeInTheDocument();
  });

  it('resolves a review item with a note', async () => {
    vi.spyOn(api, 'listOwnershipReviewItems').mockResolvedValue([{
      id: 'r-1', itemType: 'UNMAPPED_VALUE', subjectId: 's-1', sourceKind: 'SERVICENOW', details: '{"field":"support_group"}',
      state: 'OPEN', occurrenceCount: 7, firstSeenAt: '2026-11-01T00:00:00Z', lastSeenAt: '2026-11-08T00:00:00Z', resolvedAt: null, resolvedBy: null
    }]);
    const close = vi.spyOn(api, 'closeOwnershipReviewItem').mockResolvedValue(undefined);
    renderHub('TENANT_ADMIN', 'review');
    // Wait for the row itself: the type filter's <option> also says "Unmapped value".
    expect(await screen.findByText('field: support_group')).toBeInTheDocument();
    expect(screen.getAllByText('Unmapped value').length).toBeGreaterThan(1);
    fireEvent.click(screen.getByRole('button', { name: 'Resolve' }));
    const dialog = await screen.findByRole('dialog', { name: 'Resolve review item' });
    fireEvent.change(within(dialog).getByLabelText('Note (optional)'), { target: { value: 'Alias added on Payments' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Mark resolved' }));
    await waitFor(() => expect(close).toHaveBeenCalledWith('r-1', 'RESOLVED', 'Alias added on Payments'));
  });

  it('blocks the canonical switch while qualification fails and binds an accepted switch to the report hash', async () => {
    vi.mocked(api.getOwnershipQualification).mockResolvedValue(qualification({ passed: false, blockers: ['unlinkedAssets must be 0 (is 4)'] }));
    const transition = vi.spyOn(api, 'transitionOwnershipAuthority').mockResolvedValue(qualification({ state: 'CANONICAL' }));
    const view = renderHub('TENANT_ADMIN');
    expect(await screen.findByText('unlinkedAssets must be 0 (is 4)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Accept and switch to canonical' })).toBeDisabled();
    view.unmount();

    vi.mocked(api.getOwnershipQualification).mockResolvedValue(qualification());
    renderHub('TENANT_ADMIN');
    fireEvent.click(await screen.findByRole('button', { name: 'Accept and switch to canonical' }));
    const dialog = await screen.findByRole('dialog', { name: 'Switch core ownership to canonical?' });
    expect(dialog).toHaveTextContent('abcdef012345');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Switch to canonical' }));
    await waitFor(() => expect(transition).toHaveBeenCalledWith('CORE', 'CANONICAL', 'abcdef0123456789'));
  });
});
