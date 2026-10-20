import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { PlatformConsolePage } from './PlatformConsolePage';
import { createTestQueryClient } from '../test/test-utils';

const PLATFORM_SCOPE_OWNER: ActorContext = {
  creator: true,
  principal: 'owner@example.com',
  userId: 'owner@example.com',
  tenantId: null,
  tenantName: null,
  roles: ['PLATFORM_OWNER'],
  platformScope: true,
  actingAsPlatformOwner: false,
  allowedTenants: [{
    id: 'tenant-a',
    name: 'Tenant A',
    slug: 'tenant-a',
    role: 'PLATFORM_OWNER',
    accessMode: 'READ_ONLY',
    expiresAt: '2026-12-31T00:00:00Z'
  }]
};

describe('PlatformConsolePage tenant privacy boundary', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it('does not expose workspace entry from the global tenant inventory', async () => {
    mockTenantSchemaStatus();
    vi.spyOn(api, 'listTenants').mockResolvedValue([{
      id: 'tenant-a',
      name: 'Tenant A',
      slug: 'tenant-a',
      status: 'ACTIVE',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-06-01T00:00:00Z',
      updatedAt: null
    }]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    vi.spyOn(api, 'selectTenantContext').mockResolvedValue({
      token: 'tenant-context-token',
      tokenType: 'Bearer',
      expiresAt: '2026-06-30T00:00:00Z'
    });

    const queryClient = createTestQueryClient();
    renderPlatformTenants(PLATFORM_SCOPE_OWNER, queryClient);

    await screen.findByText('Tenant A');
    expect(screen.queryByRole('button', { name: 'Enter workspace' })).not.toBeInTheDocument();
    expect(api.selectTenantContext).not.toHaveBeenCalled();
  });

  it('does not expose workspace exit controls from the global tenant inventory', async () => {
    mockTenantSchemaStatus();
    vi.spyOn(api, 'listTenants').mockResolvedValue([{
      id: 'tenant-a',
      name: 'Tenant A',
      slug: 'tenant-a',
      status: 'ACTIVE',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-06-01T00:00:00Z',
      updatedAt: null
    }]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    vi.spyOn(api, 'clearTenantContext').mockResolvedValue({
      token: 'platform-scope-token',
      tokenType: 'Bearer',
      expiresAt: '2026-06-30T00:00:00Z'
    });

    const queryClient = createTestQueryClient();
    renderPlatformTenants({
      ...PLATFORM_SCOPE_OWNER,
      tenantId: 'tenant-a',
      tenantName: 'Tenant A',
      platformScope: false,
      actingAsPlatformOwner: true
    }, queryClient);

    await screen.findByText('Tenant A');
    expect(screen.queryByRole('button', { name: 'Return to platform scope' })).not.toBeInTheDocument();
    expect(api.clearTenantContext).not.toHaveBeenCalled();
  });

  it('shows a platform audit panel with filterable platform-user events', async () => {
    vi.spyOn(api, 'listPlatformUserAuditEvents').mockResolvedValue([{
      id: 'audit-1',
      occurredAt: '2026-07-11T08:00:00Z',
      tenantId: null,
      actorSubject: 'owner@example.com',
      actorRole: 'PLATFORM_OWNER',
      action: 'platform.user.setup_completed',
      targetType: 'app_user',
      targetId: 'user-1',
      outcome: 'SUCCESS',
      detailsJson: '{"mode":"self_service"}'
    }, {
      id: 'audit-2',
      occurredAt: '2026-07-10T08:00:00Z',
      tenantId: null,
      actorSubject: 'owner@example.com',
      actorRole: 'PLATFORM_OWNER',
      action: 'platform.user.role.granted',
      targetType: 'app_user',
      targetId: 'user-2',
      outcome: 'SUCCESS',
      detailsJson: '{"role":"PLATFORM_OWNER"}'
    }]);

    renderPlatformAudit();

    expect(await screen.findByText('Platform User Audit')).toBeInTheDocument();
    expect(await screen.findAllByText('platform.user.setup_completed')).toHaveLength(2);

    fireEvent.change(screen.getByLabelText('Filter audit action'), {
      target: { value: 'platform.user.role.granted' }
    });

    expect(screen.getAllByText('platform.user.role.granted')).toHaveLength(2);
    expect(screen.queryByText('{"mode":"self_service"}')).not.toBeInTheDocument();
  });

  it('renders backend-provided tenant attention and connector issue data in operations overview', async () => {
    mockOperationsApi({
      tenantAttention: [{
        tenantId: 'tenant-a',
        tenantName: 'Tenant A',
        tenantStatus: 'SUSPENDED',
        reasons: ['TENANT_SUSPENDED', 'CONNECTOR_ERROR'],
        affectedConnectors: ['aws'],
        latestRelevantSyncAt: '2026-06-20T10:00:00Z'
      }],
      connectorIssues: [{
        connectorKey: 'aws',
        affectedTenantCount: 1,
        affectedTenants: ['Tenant A']
      }]
    });

    renderPlatformOperations();

    expect(await screen.findByText('Tenant Attention Queue')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
    expect(screen.getAllByText('Tenant A')).toHaveLength(2);
    expect(screen.getByText('Tenant suspended, Connector error')).toBeInTheDocument();
    expect(screen.getAllByText('aws')).toHaveLength(2);
    expect(screen.getByText('Connector Issues')).toBeInTheDocument();
    expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(2);
  });

  it('renders operations empty states when no tenants or connectors need attention', async () => {
    mockOperationsApi();

    renderPlatformOperations();

    expect(await screen.findByText('No tenant currently requires attention')).toBeInTheDocument();
    expect(screen.getByText('No tenants currently impacted')).toBeInTheDocument();
  });

  it('issues a setup link for a platform user from the users panel', async () => {
    vi.spyOn(api, 'listPlatformUsers').mockResolvedValue([{
      userId: 'user-1',
      externalSubject: 'owner-subject',
      email: 'owner@example.com',
      displayName: 'Owner',
      status: 'ACTIVE',
      globalRoles: ['PLATFORM_OWNER'],
      passwordSet: false,
      setupPending: false,
      passwordSetAt: null,
      lastSetupIssuedAt: null,
      lastSetupCompletedAt: null,
      lastSeenAt: null,
      createdAt: '2026-06-01T00:00:00Z'
    }]);
    vi.spyOn(api, 'issuePlatformUserSetupLink').mockResolvedValue({
      userId: 'user-1',
      email: 'owner@example.com',
      setupUrl: 'http://localhost:5173/setup/setup-token-123?email=owner%40example.com'
    });
    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);

    renderPlatformUsers();

    fireEvent.click(await screen.findByRole('button', { name: 'Set Password' }));

    await waitFor(() => {
      expect(api.issuePlatformUserSetupLink).toHaveBeenCalled();
      expect(vi.mocked(api.issuePlatformUserSetupLink).mock.calls[0]?.[0]).toBe('user-1');
      expect(openSpy).toHaveBeenCalledWith(
        'http://localhost:5173/setup/setup-token-123?email=owner%40example.com',
        '_self'
      );
    });
  });

  it('shows platform user activation state in the users panel', async () => {
    vi.spyOn(api, 'listPlatformUsers').mockResolvedValue([{
      userId: 'user-1',
      externalSubject: 'owner-subject',
      email: 'owner@example.com',
      displayName: 'Owner',
      status: 'ACTIVE',
      globalRoles: ['PLATFORM_OWNER'],
      passwordSet: true,
      setupPending: false,
      passwordSetAt: '2026-07-11T08:00:00Z',
      lastSetupIssuedAt: '2026-07-10T08:00:00Z',
      lastSetupCompletedAt: '2026-07-11T08:00:00Z',
      lastSeenAt: null,
      createdAt: '2026-06-01T00:00:00Z'
    }, {
      userId: 'user-2',
      externalSubject: 'pending-owner',
      email: 'pending@example.com',
      displayName: 'Pending Owner',
      status: 'ACTIVE',
      globalRoles: ['PLATFORM_OWNER'],
      passwordSet: false,
      setupPending: true,
      passwordSetAt: null,
      lastSetupIssuedAt: '2026-07-12T08:00:00Z',
      lastSetupCompletedAt: null,
      lastSeenAt: null,
      createdAt: '2026-06-02T00:00:00Z'
    }]);

    renderPlatformUsers();

    expect(await screen.findByText(/Activated/)).toBeInTheDocument();
    expect(screen.getByText(/Setup issued/)).toBeInTheDocument();
    expect(screen.getByText(/completed/)).toBeInTheDocument();
    expect(screen.getByText(/issued/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reset Password' })).toBeInTheDocument();
  });

  it('shows info-icon help text for the new operations overview metrics', async () => {
    mockOperationsApi();

    renderPlatformOperations();

    expect(await screen.findByRole('button', {
      name: /Tenants With Connector Issues: Number of distinct tenants that currently have at least one unhealthy connector\./
    })).toBeInTheDocument();

    expect(screen.getByRole('button', {
      name: /Affected Tenants: The tenants currently impacted by this connector problem\./
    })).toBeInTheDocument();
  });

  it('blocks workspace access while provisioning and offers a retry after failure', async () => {
    vi.spyOn(api, 'listTenants').mockResolvedValue([{
      id: 'tenant-pending',
      name: 'Pending Tenant',
      slug: 'pending-tenant',
      status: 'PROVISIONING',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-07-15T00:00:00Z',
      updatedAt: null
    }, {
      id: 'tenant-failed',
      name: 'Failed Tenant',
      slug: 'failed-tenant',
      status: 'PROVISIONING_FAILED',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-07-15T00:00:00Z',
      updatedAt: null
    }]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    mockTenantSchemaStatus([{
      tenantId: 'tenant-pending',
      tenantName: 'Pending Tenant',
      tenantStatus: 'PROVISIONING',
      schemaName: 'tenant_pending_tenant',
      currentVersion: 0,
      targetVersion: 44,
      status: 'PENDING',
      structuralChecksum: null,
      lastSuccessfulVersion: 0,
      failureCode: null,
      failureMessage: null,
      migrationStartedAt: null,
      migrationCompletedAt: null,
      updatedAt: null,
      migrationRunId: null
    }, {
      tenantId: 'tenant-failed',
      tenantName: 'Failed Tenant',
      tenantStatus: 'PROVISIONING_FAILED',
      schemaName: 'tenant_failed_tenant',
      currentVersion: 0,
      targetVersion: 44,
      status: 'PROVISIONING_FAILED',
      structuralChecksum: null,
      lastSuccessfulVersion: 0,
      failureCode: 'tenant_schema_drift',
      failureMessage: 'Tenant schema does not match the migrated template',
      migrationStartedAt: null,
      migrationCompletedAt: null,
      updatedAt: null,
      migrationRunId: null
    }]);
    vi.spyOn(api, 'retryTenantProvisioning').mockResolvedValue({
      id: 'tenant-failed',
      name: 'Failed Tenant',
      slug: 'failed-tenant',
      status: 'PROVISIONING',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: null,
      maxServiceAccountCount: null,
      maxDailySbomUploads: null,
      maxExportRows: null,
      maxDailyExposureRefreshes: null,
      createdAt: '2026-07-15T00:00:00Z',
      updatedAt: null
    });

    const queryClient = createTestQueryClient();
    renderPlatformTenants({
      ...PLATFORM_SCOPE_OWNER,
      allowedTenants: [
        ...(PLATFORM_SCOPE_OWNER.allowedTenants ?? []),
        { id: 'tenant-pending', name: 'Pending Tenant', slug: 'pending-tenant', role: 'PLATFORM_OWNER' },
        { id: 'tenant-failed', name: 'Failed Tenant', slug: 'failed-tenant', role: 'PLATFORM_OWNER' }
      ]
    }, queryClient);

    await screen.findByText('Awaiting controlled bootstrap');
    expect(screen.queryByRole('button', { name: 'Enter workspace' })).not.toBeInTheDocument();
    expect(screen.getByText('Awaiting controlled bootstrap')).toBeInTheDocument();
    expect(screen.getByText('Tenant schema does not match the migrated template')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Retry provisioning' }));
    await waitFor(() => expect(vi.mocked(api.retryTenantProvisioning).mock.calls[0]?.[0]).toBe('tenant-failed'));
  });

  it('lets platform owners extend, block, restore, and manually delete retained tenants', async () => {
    mockTenantSchemaStatus();
    const activeTenant = {
      id: 'tenant-demo-active',
      name: 'Active Demo',
      slug: 'active-demo',
      status: 'ACTIVE',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: 25,
      maxServiceAccountCount: 0,
      maxDailySbomUploads: 5,
      maxExportRows: 1000,
      maxDailyExposureRefreshes: 3,
      demoExpiresAt: '2099-08-07T00:00:00Z',
      createdAt: '2026-07-20T00:00:00Z',
      updatedAt: null
    };
    const suspendedTenant = {
      ...activeTenant,
      id: 'tenant-demo-suspended',
      name: 'Suspended Demo',
      slug: 'suspended-demo',
      status: 'SUSPENDED'
    };
    vi.spyOn(api, 'listTenants').mockResolvedValue([activeTenant, suspendedTenant]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    const extendTenant = vi.spyOn(api, 'extendTenantDemoExpiry').mockResolvedValue({
      ...activeTenant,
      demoExpiresAt: '2099-09-15T12:30:00Z'
    });
    const updateStatus = vi.spyOn(api, 'updateTenantStatus').mockImplementation(async (tenantId, status) => ({
      ...(tenantId === activeTenant.id ? activeTenant : suspendedTenant),
      status
    }));
    const deleteTenant = vi.spyOn(api, 'deleteTenant').mockResolvedValue(undefined);

    renderPlatformTenants(PLATFORM_SCOPE_OWNER, createTestQueryClient());

    await screen.findByText('Active Demo');
    fireEvent.click(screen.getAllByRole('button', { name: 'Extend' })[0]!);
    fireEvent.change(screen.getByLabelText('New tenant expiration'), {
      target: { value: '2099-09-15T12:30' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Extend Tenant' }));
    await waitFor(() => expect(extendTenant).toHaveBeenCalledWith(
      activeTenant.id,
      expect.objectContaining({ expiresAt: expect.any(String) })
    ));

    fireEvent.click(screen.getByRole('button', { name: 'Block access' }));
    fireEvent.click(screen.getByRole('button', { name: 'Block Access' }));
    await waitFor(() => expect(updateStatus).toHaveBeenCalledWith(activeTenant.id, 'SUSPENDED'));

    fireEvent.click(screen.getByRole('button', { name: 'Restore access' }));
    fireEvent.click(screen.getByRole('button', { name: 'Restore Access' }));
    await waitFor(() => expect(updateStatus).toHaveBeenCalledWith(suspendedTenant.id, 'ACTIVE'));

    const deleteButton = screen.getAllByRole('button', { name: 'Delete' })[0]!;
    expect(deleteButton).toBeDisabled();
    expect(deleteButton).toHaveAttribute('title', expect.stringContaining('temporarily unavailable'));
    fireEvent.click(deleteButton);
    expect(deleteTenant).not.toHaveBeenCalled();
  });

  it('sends demo data only when the provisioning option is selected', async () => {
    mockTenantSchemaStatus();
    vi.spyOn(api, 'listTenants').mockResolvedValue([]);
    vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
    const createTenant = vi.spyOn(api, 'createTenant').mockResolvedValue({
      id: 'tenant-kanra',
      name: 'Kanra',
      slug: 'kanra',
      status: 'PROVISIONING',
      planCode: 'ENTERPRISE',
      billingRef: null,
      maxConnectorCount: 10,
      maxServiceAccountCount: 25,
      maxDailySbomUploads: 100,
      maxExportRows: 50000,
      maxDailyExposureRefreshes: 25,
      demoDataRequested: true,
      demoDataStatus: 'REQUESTED',
      createdAt: '2026-07-23T00:00:00Z',
      updatedAt: null
    });

    renderPlatformTenants(PLATFORM_SCOPE_OWNER, createTestQueryClient());

    fireEvent.change(await screen.findByLabelText('Tenant name'), { target: { value: 'Kanra' } });
    fireEvent.change(screen.getByLabelText('Tenant slug'), { target: { value: 'kanra' } });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Add demo data' }));
    fireEvent.click(screen.getByRole('button', { name: 'Create Tenant' }));

    await waitFor(() => expect(createTenant.mock.calls[0]?.[0]).toEqual({
      name: 'Kanra',
      slug: 'kanra',
      billingRef: '',
      addDemoData: true
    }));
  });

  it('offers demo data during approval and for an existing demo tenant', async () => {
    vi.spyOn(api, 'listDemoRequests').mockResolvedValue([{
      id: 'request-pending',
      email: 'pending@example.com',
      fullName: 'Pending User',
      company: 'Pending Co',
      roleTitle: null,
      companySize: null,
      useCase: 'SBOM validation',
      notes: null,
      status: 'PENDING',
      requestedAt: '2026-07-23T00:00:00Z',
      decidedAt: null,
      decidedBy: null,
      rejectionReason: null,
      bootstrapStatus: null,
      tenantId: null,
      provisionedPlanCode: null,
      latestInvite: null
    }, {
      id: 'request-existing',
      email: 'existing@example.com',
      fullName: 'Existing User',
      company: 'Existing Co',
      roleTitle: null,
      companySize: null,
      useCase: 'SBOM validation',
      notes: null,
      status: 'SENT',
      requestedAt: '2026-07-22T00:00:00Z',
      decidedAt: '2026-07-22T01:00:00Z',
      decidedBy: 'owner@example.com',
      rejectionReason: null,
      bootstrapStatus: 'INVITE_SENT',
      tenantId: 'tenant-existing',
      provisionedPlanCode: 'ENTERPRISE',
      latestInvite: null
    }]);
    const approve = vi.spyOn(api, 'approveDemoRequest').mockResolvedValue({} as never);
    const seedDemoData = vi.spyOn(api, 'seedTenantDemoData').mockResolvedValue({});

    renderPlatformDemoRequests();

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Add demo data for Pending Co' }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Approve' })[0]!);

    await waitFor(() => expect(approve).toHaveBeenCalledWith('request-pending', true));

    fireEvent.click(screen.getByRole('button', { name: 'Add demo data' }));
    await waitFor(() => expect(seedDemoData).toHaveBeenCalledWith('tenant-existing'));
  });

  it('renders enterprise performance guardrails in reliability view', async () => {
    mockOperationsApi({
      performanceScorecard: {
        generatedAt: '2026-06-22T00:00:00Z',
        scaleProfile: '1M inventory components / 250k findings / 100 concurrent users',
        overallCompliant: false,
        routeFailureCount: 1,
        routeNoDataCount: 0,
        freshnessFailureCount: 1,
        resourceFailureCount: 1,
        resourceNoDataCount: 0,
        routeItems: [{
          key: 'findings-list',
          label: 'Findings List',
          path: '/api/findings',
          category: 'paginated-list',
          status: 'FAIL',
          unit: 'ms',
          targetP95Ms: 800,
          targetP99Ms: 1500,
          requestCount: 25,
          currentP95Ms: 920,
          currentP99Ms: 1510,
          compliant: false,
          note: 'Observed latency exceeds at least one current target.'
        }],
        freshnessItems: [{
          key: 'delta_queue_processing_oldest_age',
          label: 'Delta Queue Processing Oldest Age',
          unit: 'seconds',
          targetValue: 600,
          currentValue: 920,
          compliant: false,
          window: '15m freshness window'
        }],
        resourceItems: [{
          key: 'db-pool-active-utilization',
          label: 'DB Pool Active Utilization',
          category: 'database',
          status: 'FAIL',
          unit: '%',
          targetValue: 80,
          currentValue: 92,
          compliant: false,
          note: 'Active connections 23 of 25.'
        }]
      }
    });

    renderPlatformOperations('/platform/operations?ops=reliability');

    expect(await screen.findByText('Enterprise Performance Guardrails')).toBeInTheDocument();
    expect(screen.getByText('Validated against 1M inventory components / 250k findings / 100 concurrent users.')).toBeInTheDocument();
    expect(screen.getAllByText('Delta Queue Processing Oldest Age').length).toBeGreaterThan(0);
    expect(screen.getByText('DB Pool Active Utilization')).toBeInTheDocument();
    expect(screen.getByText('Findings List')).toBeInTheDocument();
    expect(screen.getAllByText('Needs attention').length).toBeGreaterThan(0);
  });

  it('exposes platform-owned vulnerability feed configuration under the platform console, not the tenant Connect page', async () => {
    vi.spyOn(api, 'getVulnIntelSourcesSummary').mockResolvedValue({ sources: {} });
    vi.spyOn(api, 'getVulnerabilitySourceFilterConfig').mockResolvedValue({
      sourceSystem: 'nvd',
      configured: false,
      isVulnerable: false,
      hasKev: false
    } as never);

    renderPlatformVulnIntel();

    expect(await screen.findByText('NVD Vulnerability Feed')).toBeInTheDocument();
    expect(screen.getByText('CISA KEV Feed')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run History' })).toBeInTheDocument();
  });
});

function renderPlatformTenants(actor: ActorContext, queryClient: ReturnType<typeof createTestQueryClient>) {
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/tenants']}>
        <ActorContextState.Provider value={actor}>
          <Routes>
            <Route path="/platform/tenants" element={<PlatformConsolePage selectedView="tenants" />} />
            <Route path="/" element={<div>Tenant Dashboard</div>} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformOperations(initialEntry = '/platform/operations?ops=overview') {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/platform/operations" element={<PlatformConsolePage selectedView="operations" />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformUsers() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/users']}>
        <ActorContextState.Provider value={PLATFORM_SCOPE_OWNER}>
          <Routes>
            <Route path="/platform/users" element={<PlatformConsolePage selectedView="users" />} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformAudit() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/platform-audit']}>
        <ActorContextState.Provider value={PLATFORM_SCOPE_OWNER}>
          <Routes>
            <Route path="/platform/platform-audit" element={<PlatformConsolePage selectedView="platform-audit" />} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformDemoRequests() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/demo-requests']}>
        <ActorContextState.Provider value={PLATFORM_SCOPE_OWNER}>
          <Routes>
            <Route path="/platform/demo-requests" element={<PlatformConsolePage selectedView="demo-requests" />} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function renderPlatformVulnIntel() {
  const queryClient = createTestQueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/platform/vuln-intel']}>
        <ActorContextState.Provider value={PLATFORM_SCOPE_OWNER}>
          <Routes>
            <Route path="/platform/vuln-intel" element={<PlatformConsolePage selectedView="vuln-intel" />} />
          </Routes>
        </ActorContextState.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

function mockOperationsApi({
  tenantAttention = [],
  connectorIssues = [],
  performanceScorecard
}: {
  tenantAttention?: Awaited<ReturnType<typeof api.getOperationalTenantAttention>>;
  connectorIssues?: Awaited<ReturnType<typeof api.getOperationalConnectorIssues>>;
  performanceScorecard?: Awaited<ReturnType<typeof api.getOperationalPerformanceScorecard>>;
} = {}) {
  vi.spyOn(api, 'getOperationalOverview').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      ingestionSuccessRateLast24h: 98.2,
      recomputeP95Ms: 2200,
      normalizationCoveragePercent: 97.4,
      correlationNoiseReductionPercent: 42.1,
      openCriticalFindings: 3
    }
  });
  vi.spyOn(api, 'getOperationalIngestionEfficiency').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      sbomIngestionsLast24h: 12,
      sbomIngestionsPerHour: 0.5,
      sbomSuccessRatePercent: 100,
      syncRunsLast24h: 24,
      syncSuccessRatePercent: 95,
      queueBacklog: 0,
      recordsFetchedLast24h: 1000,
      recordsInsertedLast24h: 200,
      recordsUpdatedLast24h: 300,
      sourceBreakdown: []
    }
  });
  vi.spyOn(api, 'getOperationalFreshnessDrift').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      staleThresholdHours: 24,
      staleSourceCount: 0,
      normalizationCoverageDrift7d: 0,
      cpeFallbackShareDrift7d: 0,
      sourceFreshness: []
    }
  });
  vi.spyOn(api, 'getOperationalQualitySummary').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    totalIssues: 0,
    criticalIssues: 0,
    affectsActiveFindingsCount: 0,
    newIssuesLast24h: 0,
    domainCounts: []
  });
  vi.spyOn(api, 'getOperationalApiReadPath').mockResolvedValue({
    generatedAt: '2026-06-22T00:00:00Z',
    data: {
      summaryReadModelReady: true,
      canonicalCveCount: 0,
      summaryCveCount: 0,
      summaryCoveragePercent: 100,
      filterCacheActive: true,
      filterCacheExpiresAt: undefined,
      filterCacheHits: 0,
      filterCacheMisses: 0,
      filterCacheHitRatioPercent: 100,
      endpointMetrics: []
    }
  });
  vi.spyOn(api, 'getSloStatus').mockResolvedValue({
    evaluatedAt: '2026-06-22T00:00:00Z',
    overallCompliant: true,
    slos: []
  });
  vi.spyOn(api, 'getOperationalPerformanceScorecard').mockResolvedValue(performanceScorecard ?? {
    generatedAt: '2026-06-22T00:00:00Z',
    scaleProfile: '1M inventory components / 250k findings / 100 concurrent users',
    overallCompliant: true,
    routeFailureCount: 0,
    routeNoDataCount: 0,
    freshnessFailureCount: 0,
    resourceFailureCount: 0,
    resourceNoDataCount: 0,
    routeItems: [],
    freshnessItems: [],
    resourceItems: []
  });
  vi.spyOn(api, 'listTenants').mockResolvedValue([]);
  vi.spyOn(api, 'listInventoryConnectorHealth').mockResolvedValue([]);
  vi.spyOn(api, 'getOperationalTenantAttention').mockResolvedValue(tenantAttention);
  vi.spyOn(api, 'getOperationalConnectorIssues').mockResolvedValue(connectorIssues);
}

function mockTenantSchemaStatus(items: Awaited<ReturnType<typeof api.getTenantSchemaStatus>>['items'] = []) {
  vi.spyOn(api, 'getTenantSchemaStatus').mockResolvedValue({
    items,
    page: 0,
    size: 200,
    total: items.length
  });
}
