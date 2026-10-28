import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { grantCommands } from '../features/connect/gcp';
import type { GcpDiscoveryConfig, GcpDiscoveryTarget } from '../features/connect/types';
import { renderWithProviders } from '../test/test-utils';
import { GcpDiscoveryConnectorPage } from './GcpDiscoveryConnectorPage';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'tenant.admin@example.test',
  userId: 'tenant-admin',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

const ROLES = ['roles/browser', 'roles/cloudasset.viewer', 'roles/compute.viewer', 'roles/osconfig.inventoryViewer'];
const TYPES = ['COMPUTE_INSTANCE', 'GKE_CLUSTER', 'STORAGE_BUCKET'];
const EMAIL = 'scout-reader@acme-prod.iam.gserviceaccount.com';
const KEY = '{"type":"service_account","client_email":"scout-reader@acme-prod.iam.gserviceaccount.com"}';

function config(overrides: Partial<GcpDiscoveryConfig> = {}): GcpDiscoveryConfig {
  return {
    id: 'cfg-1',
    configured: true,
    hasCredential: true,
    serviceAccountEmail: EMAIL,
    keyProjectId: 'acme-prod',
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440,
    requiredRoles: ROLES,
    supportedResourceTypes: TYPES,
    ...overrides
  };
}

const TARGET: GcpDiscoveryTarget = { id: 't-1', projectId: 'acme-prod', displayName: 'Production', enabled: true, resourceTypes: TYPES };

function renderPage(actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <GcpDiscoveryConnectorPage />
    </ActorContextState.Provider>
  );
}

describe('GcpDiscoveryConnectorPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('requires the customer key on first save and sends it write-only', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config({ id: undefined, configured: false, hasCredential: false, serviceAccountEmail: undefined, keyProjectId: undefined }));
    const save = vi.spyOn(api, 'saveGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([]);
    renderPage();

    expect(await screen.findByText(/download its JSON key/i)).toBeInTheDocument();
    expect(screen.queryByText(/Scout service account/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save Connector' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Service account key JSON'), { target: { value: KEY } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Connector' }));

    await waitFor(() => expect(save).toHaveBeenCalledWith({ credentialJson: KEY, enabled: true, autoSyncEnabled: false, intervalMinutes: 1440 }));
    await waitFor(() => expect(screen.getByLabelText('Service account key JSON')).toHaveValue(''));
  });

  it('keeps the saved key when saving settings without a new one', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([TARGET]);
    const save = vi.spyOn(api, 'saveGcpDiscoveryConfig').mockResolvedValue(config());
    renderPage();

    expect(await screen.findByText(/Key saved/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Save Connector' }));

    await waitFor(() => expect(save).toHaveBeenCalledWith(expect.objectContaining({ credentialJson: undefined })));
  });

  it('shows the read-only service account with copyable grant commands for the selected project', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([TARGET]);
    renderPage();

    expect(await screen.findByDisplayValue(EMAIL)).toHaveAttribute('readonly');
    const commands = await screen.findByLabelText('Grant commands');
    expect(commands.textContent).toBe(grantCommands(EMAIL, 'acme-prod', ROLES));
    expect(commands.textContent).toContain('--role="roles/cloudasset.viewer"');
  });

  it('adds a project with only the chosen resource types', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([]);
    const create = vi.spyOn(api, 'createGcpDiscoveryTarget').mockResolvedValue({ ...TARGET, resourceTypes: ['COMPUTE_INSTANCE', 'GKE_CLUSTER'] });
    renderPage();

    fireEvent.change(await screen.findByPlaceholderText('my-production-project'), { target: { value: ' acme-prod ' } });
    fireEvent.click(screen.getByLabelText('Cloud Storage buckets'));
    fireEvent.click(screen.getByRole('button', { name: 'Add Project' }));

    await waitFor(() => expect(create).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'acme-prod',
      resourceTypes: ['COMPUTE_INSTANCE', 'GKE_CLUSTER']
    })));
  });

  it('lists every permission the connection test checked', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([TARGET]);
    vi.spyOn(api, 'testGcpDiscoveryConnection').mockResolvedValue({
      status: 'SUCCESS_WITH_WARNINGS',
      message: 'VM packages will not be collected.',
      serviceAccountEmail: EMAIL,
      permissions: [
        { permission: 'acme-prod: compute.instances.list', granted: true, required: true },
        { permission: 'acme-prod: osconfig.inventories.list', granted: false, required: false }
      ],
      testedAt: '2026-10-27T00:00:00Z'
    });
    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Test Connection' }));

    expect(await screen.findByText(/Connection succeeded with warnings/)).toBeInTheDocument();
    const checks = screen.getByLabelText('Permission checks');
    expect(checks).toHaveTextContent('✓ acme-prod: compute.instances.list');
    expect(checks).toHaveTextContent('✗ acme-prod: osconfig.inventories.list (optional)');
  });

  it('queues a project sync and links to the run queue', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([TARGET]);
    const sync = vi.spyOn(api, 'triggerGcpDiscoveryTargetSync').mockResolvedValue({ runId: 'r-1', status: 'queued', message: 'GCP Cloud Discovery project sync queued' });
    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Sync' }));

    await waitFor(() => expect(sync).toHaveBeenCalledWith('t-1'));
    expect(await screen.findByRole('link', { name: 'Integration Run Queue' })).toBeInTheDocument();
  });

  it('disables changes for roles that cannot manage inventory sources', async () => {
    vi.spyOn(api, 'getGcpDiscoveryConfig').mockResolvedValue(config());
    vi.spyOn(api, 'listGcpDiscoveryTargets').mockResolvedValue([TARGET]);
    renderPage({ ...TENANT_ADMIN, roles: ['SECURITY_ANALYST'] });

    expect(await screen.findByRole('button', { name: 'Save Connector' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Test' })).toBeDisabled();
  });
});
