import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { renderWithProviders } from '../../test/test-utils';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { OwnershipDirectoryHub } from './OwnershipDirectoryHub';
import type { CloudOwnershipSource, ExternalGroupRow, GroupMappingImpact, GroupTeamMapping, IdentitySource, OwnershipCoverage } from './types';

function actor(role: string): ActorContext {
  return { creator: false, principal: `${role.toLowerCase()}@example.test`, userId: 'u-1', tenantId: 't-1', tenantName: 'Acme', roles: [`ROLE_${role}`] };
}

const coverage: OwnershipCoverage = { authorityState: 'LEGACY_PENDING_MIGRATION', owned: 0, unowned: 0, conflict: 0, unlinked: 0, refreshing: 0 };

const source = (overrides: Partial<IdentitySource> = {}): IdentitySource => ({
  id: 'src-1', kind: 'SERVICENOW', displayName: 'Acme ServiceNow', instanceUrl: 'https://acme.service-now.com', authType: 'BASIC',
  hasCredentials: true, filters: {}, schedule: 'PT24H', state: 'DISABLED', health: 'UNKNOWN', lastSuccessAt: null, lastError: null,
  version: 2, ...overrides
});

const cloud = (overrides: Partial<CloudOwnershipSource> = {}): CloudOwnershipSource => ({
  provider: 'AWS', deploymentEnabled: true, configured: true, domainState: 'DARK', paused: false, pauseReason: null, intervalValid: true,
  intervalMinutes: 60, settings: { ownerKey: true, teamKey: true, accountInput: true, intervalMinutes: 60 }, accountTagsConfigured: false,
  activeClaims: 12, openAnomalies: 0, ...overrides
});

const mapping = (overrides: Partial<GroupTeamMapping> = {}): GroupTeamMapping => ({
  id: 'map-1', externalGroupId: 'eg-1', teamId: 'team-1', teamName: 'Payments', state: 'PROPOSED', provenance: 'SUGGESTED',
  reason: 'EXACT_NAME_MATCH', actor: 'system', effectiveFrom: '2026-11-14T00:00:00Z', effectiveTo: null, ...overrides
});

const group = (overrides: Partial<ExternalGroupRow> = {}): ExternalGroupRow => ({
  externalGroupId: 'eg-1', sourceId: 'src-1', sourceName: 'Acme ServiceNow', displayName: 'Payments', status: 'ACTIVE',
  active: null, suggestion: mapping(), ...overrides
});

const impact = (overrides: Partial<GroupMappingImpact> = {}): GroupMappingImpact => ({
  externalGroupId: 'eg-1', currentTeamId: null, targetTeamId: 'team-1', sameInstance: true, affectedCis: 2, affectedSubjects: 2,
  openFindings: 5, sampleSubjectIds: ['s-1', 's-2'], largeChange: false, previewToken: 'impact-token', expiresAt: '2026-11-14T01:00:00Z',
  ...overrides
});

function renderHub(role: string, view: string) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor(role)}>
      <OwnershipDirectoryHub legacyRules={<p>legacy rule editor</p>} />
    </ActorContextState.Provider>,
    { route: `/configurations/ownership?view=${view}` }
  );
}

describe('Ownership Sources and Mappings views', () => {
  beforeEach(() => {
    vi.spyOn(api, 'getOwnershipCoverage').mockResolvedValue(coverage);
    vi.spyOn(api, 'getOwnershipEncryption').mockResolvedValue({ ready: true, reason: null });
    vi.spyOn(api, 'listCloudOwnershipSources').mockResolvedValue([]);
    vi.spyOn(api, 'getOwnershipQualification').mockResolvedValue({
      domain: 'CORE', state: 'LEGACY', passed: false, blockers: [], checks: {},
      comparison: { match: 0, mismatch: 0, legacyOnly: 0, canonicalOnly: 0, bothEmpty: 0 }, reportHash: ''
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('shows Sources to admins only and Mappings to every directory role', async () => {
    renderHub('SECURITY_ANALYST', 'overview');
    const views = screen.getByRole('group', { name: 'Ownership & Directory views' });
    expect(within(views).queryByRole('button', { name: 'Sources' })).not.toBeInTheDocument();
    expect(within(views).getByRole('button', { name: 'Mappings' })).toBeInTheDocument();
  });

  it('previews a disabled source once per click and enables it with the preview token', async () => {
    vi.spyOn(api, 'listIdentitySources').mockResolvedValue([source()]);
    const preview = vi.spyOn(api, 'previewIdentitySource').mockResolvedValue({
      succeeded: true, failure: null, message: 'Preview complete', previewToken: 'preview-token', expiresAt: '2026-11-14T01:00:00Z',
      tables: [
        { table: 'sys_user', outcome: 'READABLE', rowCount: 1200, samples: [{ sys_id: '1', name: 'Ada Lovelace', email: 'ada@acme.test' }] },
        { table: 'sys_user_group', outcome: 'READABLE', rowCount: 80, samples: [] },
        { table: 'sys_user_grmember', outcome: 'READABLE', rowCount: 3000, samples: [] }
      ]
    });
    const enable = vi.spyOn(api, 'enableIdentitySource').mockResolvedValue(source({ state: 'ENABLED' }));
    renderHub('TENANT_ADMIN', 'sources');

    expect(await screen.findByText('Acme ServiceNow')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Preview and enable' }));
    const dialog = await screen.findByRole('dialog', { name: 'Preview: Acme ServiceNow' });
    expect(await within(dialog).findByText('1,200')).toBeInTheDocument();
    expect(within(dialog).getByText(/Ada Lovelace · ada@acme.test/)).toBeInTheDocument();
    expect(preview).toHaveBeenCalledTimes(1);

    fireEvent.click(within(dialog).getByRole('button', { name: 'Enable and run baseline load' }));
    await waitFor(() => expect(enable).toHaveBeenCalledWith('src-1', 'preview-token'));
    expect(await screen.findByText('Source Acme ServiceNow enabled. The baseline load is queued.')).toBeInTheDocument();
    expect(screen.queryByText(/ada@acme.test/)).not.toBeInTheDocument();
  });

  it('shows the cloud producers and resumes one paused by an anomaly after confirmation', async () => {
    vi.spyOn(api, 'listIdentitySources').mockResolvedValue([]);
    vi.spyOn(api, 'listCloudOwnershipSources').mockResolvedValue([
      cloud({ paused: true, pauseReason: 'ANOMALY CLOUD_TAG', openAnomalies: 1 }),
      cloud({ provider: 'GCP', configured: false, settings: null, intervalMinutes: null, activeClaims: 0 })
    ]);
    const resume = vi.spyOn(api, 'resumeCloudOwnershipSource').mockResolvedValue(cloud());
    renderHub('TENANT_ADMIN', 'sources');

    expect(await screen.findByText('AWS resource and account tags')).toBeInTheDocument();
    expect(screen.getByText('Paused: anomaly')).toBeInTheDocument();
    expect(screen.getByText('Not configured')).toBeInTheDocument();
    expect(screen.getByText(/not configured on the connector/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Resume' }));
    const dialog = await screen.findByRole('dialog', { name: 'Resume AWS resource and account tags?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Resume' }));
    await waitFor(() => expect(resume).toHaveBeenCalledWith('AWS'));
    expect(await screen.findByText('Producer resumed.')).toBeInTheDocument();
  });

  it('switches a cloud input off only after confirming that its claims end', async () => {
    vi.spyOn(api, 'listIdentitySources').mockResolvedValue([]);
    vi.spyOn(api, 'listCloudOwnershipSources').mockResolvedValue([cloud()]);
    const update = vi.spyOn(api, 'updateCloudOwnershipSettings').mockResolvedValue(cloud());
    renderHub('INVENTORY_ADMIN', 'sources');

    fireEvent.click(await screen.findByRole('checkbox', { name: /owner tag/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Change AWS resource and account tags inputs?' });
    expect(within(dialog).getByText(/ends its active claims now/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('AWS', { ownerKeyEnabled: false }));
  });

  it('offers no enable button when a table is denied', async () => {
    vi.spyOn(api, 'listIdentitySources').mockResolvedValue([source()]);
    vi.spyOn(api, 'previewIdentitySource').mockResolvedValue({
      succeeded: false, failure: 'PERMISSION_DENIED', message: 'The integration account cannot read every directory table', previewToken: null,
      expiresAt: null, tables: [{ table: 'sys_user', outcome: 'DENIED', rowCount: null, samples: [] }]
    });
    renderHub('TENANT_ADMIN', 'sources');
    fireEvent.click(await screen.findByRole('button', { name: 'Preview and enable' }));
    const dialog = await screen.findByRole('dialog', { name: 'Preview: Acme ServiceNow' });
    expect(await within(dialog).findByText('Access denied')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Enable and run baseline load' })).not.toBeInTheDocument();
  });

  it('adds a source with write-only credentials and queues a complete scan after confirmation', async () => {
    vi.spyOn(api, 'listIdentitySources').mockResolvedValue([source({ state: 'ENABLED', health: 'HEALTHY', lastSuccessAt: '2026-11-14T00:00:00Z' })]);
    const create = vi.spyOn(api, 'createIdentitySource').mockResolvedValue(source({ id: 'src-2', displayName: 'Second' }));
    const sync = vi.spyOn(api, 'syncIdentitySource').mockResolvedValue({ runId: 'run-1', complete: true });
    renderHub('TENANT_ADMIN', 'sources');

    expect(await screen.findByText('Healthy')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Add ServiceNow source' }));
    const form = await screen.findByRole('dialog', { name: 'Add ServiceNow source' });
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: 'Second' } });
    fireEvent.change(within(form).getByLabelText('Instance URL'), { target: { value: 'https://second.service-now.com' } });
    fireEvent.change(within(form).getByLabelText('Integration account username'), { target: { value: 'svc' } });
    fireEvent.change(within(form).getByLabelText('Password'), { target: { value: 's3cret' } });
    fireEvent.change(within(form).getByLabelText('People filter (sys_user)'), { target: { value: 'active=true' } });
    fireEvent.click(within(form).getByRole('button', { name: 'Add source' }));
    await waitFor(() => expect(create).toHaveBeenCalledWith({
      displayName: 'Second', instanceUrl: 'https://second.service-now.com', authType: 'BASIC', username: 'svc', secret: 's3cret',
      filters: { sys_user: 'active=true' }, schedule: 'PT24H'
    }));
    expect(await screen.findByText('Source Second saved.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Complete scan' }));
    expect(sync).not.toHaveBeenCalled();
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Run a complete scan: Acme ServiceNow?' }))
      .getByRole('button', { name: 'Queue complete scan' }));
    await waitFor(() => expect(sync).toHaveBeenCalledWith('src-1', true));
    expect(await screen.findByText('Complete scan queued.')).toBeInTheDocument();
  });

  it('lets an inventory admin pause but not configure, and shows a failed load with retry', async () => {
    const list = vi.spyOn(api, 'listIdentitySources').mockRejectedValueOnce(new Error('Server unavailable'))
      .mockResolvedValue([source({ state: 'ERROR', health: 'FAILING', lastError: 'UNAVAILABLE: ServiceNow did not respond' })]);
    const pause = vi.spyOn(api, 'pauseIdentitySource').mockResolvedValue(source({ state: 'PAUSED' }));
    renderHub('INVENTORY_ADMIN', 'sources');

    expect(await screen.findByText('Server unavailable')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(await screen.findByText('UNAVAILABLE: ServiceNow did not respond')).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
    expect(screen.queryByRole('button', { name: 'Add ServiceNow source' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Pause' }));
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Pause: Acme ServiceNow?' })).getByRole('button', { name: 'Pause source' }));
    await waitFor(() => expect(pause).toHaveBeenCalledWith('src-1'));
  });

  it('confirms a suggestion only after previewing its impact, with the preview token', async () => {
    vi.spyOn(api, 'listGroupMappingGroups').mockResolvedValue([group()]);
    vi.spyOn(api, 'listOwnershipTeams').mockResolvedValue([
      { id: 'team-1', name: 'Payments', parentTeamId: null, ticketAssignmentGroup: null, status: 'ACTIVE', version: 1 }
    ]);
    const preview = vi.spyOn(api, 'previewGroupMapping').mockResolvedValue(impact());
    const activate = vi.spyOn(api, 'activateGroupMapping').mockResolvedValue({
      mapping: mapping({ id: 'map-2', state: 'ACTIVE', provenance: 'MANUAL' }), republishedCis: 2, republishSkipped: null
    });
    renderHub('INVENTORY_ADMIN', 'mappings');

    expect(await screen.findByText('Not mapped')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Review suggestion' }));
    const dialog = await screen.findByRole('dialog', { name: 'Map Payments to a team' });
    await waitFor(() => expect(within(dialog).getByLabelText('Team')).toHaveValue('team-1'));
    expect(within(dialog).queryByRole('button', { name: 'Confirm mapping' })).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview impact' }));
    await waitFor(() => expect(preview).toHaveBeenCalledWith('eg-1', 'team-1'));
    const counts = await within(dialog).findByRole('region', { name: 'Impact' });
    expect(counts).toHaveTextContent('Open findings5');

    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm mapping' }));
    await waitFor(() => expect(activate).toHaveBeenCalledWith({
      externalGroupId: 'eg-1', teamId: 'team-1', reason: undefined, previewToken: 'impact-token', confirmLarge: false
    }));
    expect(await screen.findByText('Mapped to Payments. 2 CI(s) republished.')).toBeInTheDocument();
  });

  it('needs a second confirmation for a large change and retires an active mapping', async () => {
    vi.spyOn(api, 'listGroupMappingGroups').mockResolvedValue([
      group({ suggestion: null, active: mapping({ id: 'map-3', state: 'ACTIVE', provenance: 'MANUAL' }) })
    ]);
    vi.spyOn(api, 'previewGroupMapping').mockResolvedValue(impact({ targetTeamId: null, currentTeamId: 'team-1', affectedCis: 12000, largeChange: true }));
    const retire = vi.spyOn(api, 'retireGroupMapping').mockResolvedValue({
      mapping: mapping({ id: 'map-3', state: 'RETIRED', provenance: 'MANUAL' }), republishedCis: 0, republishSkipped: 'LARGE_CHANGE_NEXT_CMDB_SYNC'
    });
    renderHub('TENANT_ADMIN', 'mappings');

    fireEvent.click(await screen.findByRole('button', { name: 'Retire' }));
    const dialog = await screen.findByRole('dialog', { name: 'Retire the mapping for Payments?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview impact' }));
    const confirm = await within(dialog).findByRole('button', { name: 'Retire mapping' });
    expect(confirm).toBeDisabled();
    fireEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.click(confirm);
    await waitFor(() => expect(retire).toHaveBeenCalledWith('map-3', { reason: undefined, previewToken: 'impact-token', confirmLarge: true }));
    expect(await screen.findByText(/the next CMDB sync applies the change/)).toBeInTheDocument();
  });

  it('shows mappings read-only to an auditor and dismisses a suggestion for an admin', async () => {
    vi.spyOn(api, 'listGroupMappingGroups').mockResolvedValue([group()]);
    const dismiss = vi.spyOn(api, 'dismissGroupMapping').mockResolvedValue(mapping({ state: 'RETIRED' }));
    const auditor = renderHub('READ_ONLY_AUDITOR', 'mappings');
    expect(await screen.findByText('Payments', { selector: 'strong' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Map to team' })).not.toBeInTheDocument();
    auditor.unmount();

    renderHub('TENANT_ADMIN', 'mappings');
    fireEvent.click(await screen.findByRole('button', { name: 'Dismiss' }));
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Dismiss the suggestion for Payments?' }))
      .getByRole('button', { name: 'Dismiss suggestion' }));
    await waitFor(() => expect(dismiss).toHaveBeenCalledWith('map-1'));
    expect(await screen.findByText('Suggestion dismissed.')).toBeInTheDocument();
  });
});
