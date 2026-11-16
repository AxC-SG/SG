import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { CbomInventoryPanel } from '../cbom/CbomInventoryPanel';
import { AssignOwnerButton } from './AssignOwnerButton';
import { CutoverPanel } from './CutoverPanel';
import { OwnerFilters } from './OwnerFilters';
import { EMPTY_OWNER_FILTER } from './ownerFilterValue';
import { canManualAssign } from './permissions';
import type { OccurrenceAssignmentPreview } from './occurrenceTypes';
import type { OwnershipQualification, OwnershipTeam } from './types';

const actor = (role: string): ActorContext => ({ creator: false, principal: 'p', userId: 'u', tenantId: 't', tenantName: 'T', roles: [`ROLE_${role}`] });
const team: OwnershipTeam = { id: 'team-1', name: 'Payments', parentTeamId: null, ticketAssignmentGroup: null, status: 'ACTIVE', version: 1 };

const bomReport = (overrides: Partial<OwnershipQualification> = {}): OwnershipQualification => ({
  domain: 'CLOUD_BOM', state: 'DARK', passed: true, blockers: [],
  checks: { coreNotCanonical: 0, unregisteredOccurrences: 0, findingAdapterOwnerChanges: 0, 'evidence.cloudClaims': 42, 'evidence.hostsWhoseOwnerWouldChange': 3 },
  comparison: { match: 1, mismatch: 0, legacyOnly: 0, canonicalOnly: 0, bothEmpty: 0 }, reportHash: 'cafebabe0123456789', ...overrides,
});

afterEach(() => { vi.restoreAllMocks(); localStorage.clear(); });

describe('CutoverPanel for CLOUD_BOM', () => {
  it('shows gates and evidence separately and binds the switch to the report hash', async () => {
    const get = vi.spyOn(api, 'getOwnershipQualification').mockResolvedValue(bomReport());
    const transition = vi.spyOn(api, 'transitionOwnershipAuthority').mockResolvedValue(bomReport({ state: 'CANONICAL' }));
    renderWithProviders(<CutoverPanel domain="CLOUD_BOM" />);
    await screen.findByText('Core ownership not yet canonical');
    const region = screen.getByRole('region', { name: 'BOM ownership cutover' });
    expect(get).toHaveBeenCalledWith('CLOUD_BOM');
    expect(within(region).getByText('Core ownership not yet canonical')).toBeInTheDocument();
    expect(within(region).getByText('Evidence for review (not gates)')).toBeInTheDocument();
    expect(within(region).getByText('Cloud ownership claims')).toBeInTheDocument();
    expect(within(region).getByText('42')).toBeInTheDocument();
    expect(within(region).queryByText('evidence.cloudClaims')).not.toBeInTheDocument();
    fireEvent.click(within(region).getByRole('button', { name: 'Accept and switch to canonical' }));
    const dialog = await screen.findByRole('dialog', { name: 'Switch bom ownership to canonical?' });
    expect(dialog).toHaveTextContent('cafebabe0123');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Switch to canonical' }));
    await waitFor(() => expect(transition).toHaveBeenCalledWith('CLOUD_BOM', 'CANONICAL', 'cafebabe0123456789'));
  });

  it('lists blockers only for gates, never evidence, and disables go', async () => {
    vi.spyOn(api, 'getOwnershipQualification').mockResolvedValue(bomReport({ passed: false, blockers: ['coreNotCanonical must be 0 (is 1)'], checks: { coreNotCanonical: 1, 'evidence.cloudClaims': 9 } }));
    renderWithProviders(<CutoverPanel domain="CLOUD_BOM" />);
    expect(await screen.findByText('coreNotCanonical must be 0 (is 1)')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Accept and switch to canonical' })).toBeDisabled();
  });

  it('starts dark qualification from legacy and shows the rollback-closed message once canonical', async () => {
    const get = vi.spyOn(api, 'getOwnershipQualification').mockResolvedValue(bomReport({ state: 'LEGACY', passed: false }));
    const transition = vi.spyOn(api, 'transitionOwnershipAuthority').mockResolvedValue(bomReport());
    const { unmount } = renderWithProviders(<CutoverPanel domain="CLOUD_BOM" />);
    fireEvent.click(await screen.findByRole('button', { name: 'Start dark qualification' }));
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Start qualification' }));
    await waitFor(() => expect(transition).toHaveBeenCalledWith('CLOUD_BOM', 'DARK', undefined));
    unmount();
    get.mockResolvedValue(bomReport({ state: 'CANONICAL' }));
    renderWithProviders(<CutoverPanel domain="CLOUD_BOM" />);
    expect(await screen.findByText(/automatic rollback window is closed/)).toBeInTheDocument();
  });
});

describe('OwnerFilters', () => {
  it('is hidden until offered, then reports team and status and clears', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    const onChange = vi.fn();
    const { rerender } = renderWithProviders(<OwnerFilters value={EMPTY_OWNER_FILTER} onChange={onChange} offered={false} notCanonical={false} />);
    expect(screen.queryByRole('group', { name: 'Owner filters' })).not.toBeInTheDocument();
    rerender(<OwnerFilters value={EMPTY_OWNER_FILTER} onChange={onChange} offered notCanonical={false} />);
    await screen.findByRole('option', { name: 'Payments' });
    fireEvent.change(screen.getByLabelText('Owner team'), { target: { value: 'team-1' } });
    expect(onChange).toHaveBeenCalledWith({ ownerTeamId: 'team-1', ownershipStatus: '' });
    fireEvent.change(screen.getByLabelText('Ownership status'), { target: { value: 'UNOWNED' } });
    expect(onChange).toHaveBeenCalledWith({ ownerTeamId: '', ownershipStatus: 'UNOWNED' });
    rerender(<OwnerFilters value={{ ownerTeamId: 'team-1', ownershipStatus: '' }} onChange={onChange} offered notCanonical />);
    expect(screen.getByText(/available once BOM ownership is canonical/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear owner filters' }));
    expect(onChange).toHaveBeenLastCalledWith(EMPTY_OWNER_FILTER);
  });
});

const cbomPage = { items: [{
  id: 'cc-1', name: 'TLS cert', assetType: 'CERTIFICATE', primitive: null, keySize: null, curve: null, protocolVersion: null, storageLocation: null,
  notAfter: null, riskScore: null, assetId: null, assetName: 'api', environment: null, sourceBomId: 'b', sourceDocument: null, openFindings: 0,
  highestSeverity: null, evidenceState: null,
}], page: 0, size: 50, total: 1, totalCapped: false, hasNext: false };

function renderCbom(role = 'SECURITY_ANALYST') {
  return renderWithProviders(<ActorContextState.Provider value={actor(role)}><CbomInventoryPanel /></ActorContextState.Provider>);
}

describe('CBOM inventory owner filters', () => {
  it('sends the owner filters to the API', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    const list = vi.spyOn(api, 'listCbomInventory').mockResolvedValue(cbomPage);
    renderCbom();
    await screen.findByText('TLS cert');
    await screen.findByRole('option', { name: 'Payments' });
    fireEvent.change(screen.getByLabelText('Owner team'), { target: { value: 'team-1' } });
    fireEvent.change(screen.getByLabelText('Ownership status'), { target: { value: 'OWNED' } });
    await waitFor(() => expect(list).toHaveBeenCalledWith(expect.objectContaining({ ownerTeamId: 'team-1', ownershipStatus: 'OWNED' }), 0, 50));
  });

  it('shows a plain state, not an error, on a 409', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    vi.spyOn(api, 'listCbomInventory').mockResolvedValueOnce(cbomPage).mockRejectedValue(new ApiError('conflict', 409));
    renderCbom();
    await screen.findByText('TLS cert');
    await screen.findByRole('option', { name: 'Payments' });
    fireEvent.change(screen.getByLabelText('Ownership status'), { target: { value: 'OWNED' } });
    expect(await screen.findAllByText(/available once BOM ownership is canonical/)).not.toHaveLength(0);
    expect(screen.queryByText('The cryptographic inventory could not be loaded.')).not.toBeInTheDocument();
  });
});

describe('Assign owner on an occurrence', () => {
  const preview = (overrides: Partial<OccurrenceAssignmentPreview> = {}): OccurrenceAssignmentPreview => ({
    subjectId: 's', currentTeamId: null, currentStatus: 'UNOWNED', directFindings: 2, wouldChange: true, blockedByDirectClaim: false,
    conflict: false, alreadyEffective: false, affectedFindings: 4, ...overrides,
  });

  function open(role = 'SECURITY_ANALYST', eligible = true) {
    return renderWithProviders(
      <ActorContextState.Provider value={actor(role)}>
        <AssignOwnerButton kind="inventory-components" rowId="ic-1" rowLabel="openssl on web-01" eligible={eligible} />
      </ActorContextState.Provider>,
    );
  }
  async function fill(dialog: HTMLElement) {
    await within(dialog).findByRole('option', { name: 'Payments' });
    fireEvent.change(within(dialog).getByLabelText('Owner team'), { target: { value: 'team-1' } });
    fireEvent.change(within(dialog).getByLabelText('Reason (required)'), { target: { value: 'Verified with the platform lead' } });
  }

  it('previews affected findings, then confirms for this occurrence only', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    const previewSpy = vi.spyOn(api, 'previewOccurrenceAssignment').mockResolvedValue(preview());
    const assign = vi.spyOn(api, 'assignOccurrenceOwner').mockResolvedValue(preview());
    open();
    fireEvent.click(screen.getByRole('button', { name: 'Assign owner for openssl on web-01' }));
    const dialog = await screen.findByRole('dialog', { name: 'Assign owner' });
    expect(dialog).toHaveTextContent('this occurrence only, not every occurrence of this package');
    await fill(dialog);
    expect(within(dialog).getByRole('button', { name: 'Confirm assignment' })).toBeDisabled();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    expect(await within(dialog).findByText(/4 findings on this occurrence would be affected/)).toBeInTheDocument();
    expect(within(dialog).getByText(/effective owner of this occurrence would change/)).toBeInTheDocument();
    expect(previewSpy).toHaveBeenCalledWith('inventory-components', 'ic-1', 'team-1');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm assignment' }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith('inventory-components', 'ic-1',
      { teamId: 'team-1', reason: 'Verified with the platform lead', expiresAt: null }, expect.any(String)));
    expect(await screen.findByText('Owner assigned.')).toBeInTheDocument();
  });

  it('shows plain 404 and 409 states and blocks a no-op assignment', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    const previewSpy = vi.spyOn(api, 'previewOccurrenceAssignment').mockRejectedValueOnce(new ApiError('nf', 404)).mockRejectedValueOnce(new ApiError('c', 409))
      .mockResolvedValue(preview({ alreadyEffective: true, wouldChange: false, blockedByDirectClaim: true, conflict: true, affectedFindings: 1 }));
    open('INVENTORY_ADMIN');
    fireEvent.click(screen.getByRole('button', { name: /Assign owner for/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Assign owner' });
    await fill(dialog);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    expect(await within(dialog).findByText(/no registered occurrence yet/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    expect(await within(dialog).findByText(/available once BOM ownership is canonical/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    expect(await within(dialog).findByText(/already the effective owner/)).toBeInTheDocument();
    expect(within(dialog).getByText(/higher-precedence claim/)).toBeInTheDocument();
    expect(within(dialog).getByText(/conflict between owners/)).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Confirm assignment' })).toBeDisabled();
    expect(previewSpy).toHaveBeenCalledTimes(3);
  });

  it('shows an assignment failure and keeps the draft', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    vi.spyOn(api, 'previewOccurrenceAssignment').mockResolvedValue(preview());
    vi.spyOn(api, 'assignOccurrenceOwner').mockRejectedValue(new Error('Server down'));
    open();
    fireEvent.click(screen.getByRole('button', { name: /Assign owner for/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Assign owner' });
    await fill(dialog);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview' }));
    fireEvent.click(await within(dialog).findByRole('button', { name: 'Confirm assignment' }).then(async (b) => { await waitFor(() => expect(b).toBeEnabled()); return b; }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Server down');
    expect(within(dialog).getByLabelText('Reason (required)')).toHaveValue('Verified with the platform lead');
  });

  it('is hidden for read-only actors and ineligible rows', () => {
    const { unmount } = open('READ_ONLY_AUDITOR');
    expect(screen.queryByRole('button', { name: /Assign owner/ })).not.toBeInTheDocument();
    unmount();
    open('SECURITY_ANALYST', false);
    expect(screen.queryByRole('button', { name: /Assign owner/ })).not.toBeInTheDocument();
    expect(canManualAssign(actor('TENANT_ADMIN'))).toBe(true);
    expect(canManualAssign(actor('READ_ONLY_AUDITOR'))).toBe(false);
  });

  it('offers the action on CBOM inventory rows for permitted roles only', async () => {
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([team]);
    vi.spyOn(api, 'listCbomInventory').mockResolvedValue(cbomPage);
    const { unmount } = renderCbom();
    expect(await screen.findByRole('button', { name: 'Assign owner for TLS cert' })).toBeInTheDocument();
    unmount();
    renderCbom('READ_ONLY_AUDITOR');
    await screen.findByText('TLS cert');
    expect(screen.queryByRole('button', { name: 'Assign owner for TLS cert' })).not.toBeInTheDocument();
  });
});
