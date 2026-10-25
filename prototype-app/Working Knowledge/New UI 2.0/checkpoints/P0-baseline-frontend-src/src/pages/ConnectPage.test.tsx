import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { intelligenceApi } from '../features/intelligence/api';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { renderWithProviders } from '../test/test-utils';
import { ConnectPage } from './ConnectPage';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'tenant.admin@example.test',
  userId: 'tenant-admin',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

function NavigationProbe() {
  const location = useLocation();
  const navigate = useNavigate();
  return <>
    <output aria-label="Current path">{location.pathname}</output>
    <output aria-label="Current search">{location.search}</output>
    <button onClick={() => navigate('?connectSource=tanium-patch&keep=1')}>Open retired bookmark</button>
  </>;
}

function RoutedConnectPage() {
  const location = useLocation();
  const navigate = useNavigate();
  return <ConnectPage
    initialView={location.pathname.endsWith('/run-history') ? 'run-history' : 'sources'}
    onViewChange={(view) => navigate(`/connect/${view}`, { replace: true })}
  />;
}

function renderConnectPage(actor: ActorContext, route = '/connect/sources') {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <RoutedConnectPage />
      <NavigationProbe />
    </ActorContextState.Provider>,
    { route }
  );
}

describe('ConnectPage', () => {
  beforeEach(() => {
    vi.spyOn(intelligenceApi, 'tenantStatus').mockResolvedValue({ tenant_id: 'tenant-1', status: 'COMPLETED', required_revision: 1, completed_revision: 1, completed_generation: 1, last_completed_at: null, last_error: null });
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getServiceNowCmdbConfig>>);
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getSccmCmdbConfig>>);
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getAwsDiscoveryConfig>>);
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getAzureDiscoveryConfig>>);
    vi.spyOn(api, 'listVulnerabilitySourceFilterConfigs').mockResolvedValue([]);
    vi.spyOn(api, 'getVulnIntelSourcesSummary').mockResolvedValue({ sources: {} } as Awaited<ReturnType<typeof api.getVulnIntelSourcesSummary>>);
  });

  it.each([{ roles: ['TENANT_ADMIN'] }, { roles: ['TENANT_ADMIN', 'PLATFORM_OWNER'] }])('omits unsupported patch connectors for roles $roles while retaining inventory, BOM and static AI cards', ({ roles }) => {
    renderConnectPage({ ...TENANT_ADMIN, roles, entitlements: { 'ai.security': true } });
    expect(screen.queryByRole('heading', { name: 'Patch Management' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /BigFix|Tanium/ })).not.toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /SCCM\/MECM/ })).toHaveLength(1);
    for (const name of ['GitHub', 'ServiceNow', 'SCCM/MECM', 'AWS', 'Azure', 'SBOM API Endpoint', 'BOM Management', 'AWS Bedrock', 'Azure AI', 'Copilot Studio']) {
      expect(screen.getAllByText(name).some((element) => element.closest('button') != null)).toBe(true);
    }
    const intelligence = screen.getByRole('button', { name: 'Vulnerability Intelligence' });
    fireEvent.click(intelligence);
    expect(intelligence).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(intelligence);
    expect(intelligence).toHaveAttribute('aria-expanded', 'true');
  });

  it.each(['sccm-patch', 'bigfix-patch', 'tanium-patch'])('rejects the %s query bookmark before mounting credential inputs', async (id) => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const fetch = vi.spyOn(globalThis, 'fetch');
    const { container } = renderConnectPage(TENANT_ADMIN, `/connect/sources?connectSource=${id}&keep=1`);
    expect(screen.getByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(screen.queryByText(/Patch Connector/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Test Connection|Save Configuration/ })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Current search')).toHaveTextContent(/^\?keep=1$/));
    expect(log).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects a retired bookmark during navigation from a retained connector', async () => {
    renderConnectPage(TENANT_ADMIN, '/connect/sources?connectSource=sccm-cmdb');
    expect(await screen.findByText(/SCCM live JDBC is disabled/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Open retired bookmark' }));
    expect(await screen.findByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Current search')).toHaveTextContent(/^\?keep=1$/));
    expect(screen.queryByRole('button', { name: /Test Connection|Save Configuration/ })).not.toBeInTheDocument();
  });

  it('opens a retained status card and closes it with Escape without dropping other query parameters', async () => {
    renderConnectPage(TENANT_ADMIN, '/connect/sources?keep=1');
    fireEvent.click(screen.getByText('SCCM/MECM').closest('button')!);
    expect(await screen.findByText(/SCCM live JDBC is disabled/)).toBeInTheDocument();
    expect(screen.getByLabelText('Current search')).toHaveTextContent('connectSource=sccm-cmdb');
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(await screen.findByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.getByLabelText('Current search')).toHaveTextContent(/^\?keep=1$/);
  });

  it('navigates to Run History from a selected retained connector without restoring its old path', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    vi.spyOn(api, 'listIngestionJobs').mockResolvedValue({ items: [], totalItems: 0, totalPages: 0, page: 0, size: 100 });
    renderConnectPage(TENANT_ADMIN, '/connect/sources?connectSource=sccm-cmdb');
    expect(await screen.findByText(/SCCM live JDBC is disabled/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Run History' }));
    await waitFor(() => expect(screen.getByLabelText('Current path')).toHaveTextContent('/connect/run-history'));
    expect(screen.getByLabelText('Current search')).toBeEmptyDOMElement();
    fireEvent.click(screen.getByRole('button', { name: 'Sources' }));
    expect(await screen.findByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.getByLabelText('Current path')).toHaveTextContent('/connect/sources');
  });

  it('retains generic Azure read-only details and the Back to Sources action', async () => {
    const save = vi.spyOn(api, 'saveAzureDiscoveryConfig');
    const test = vi.spyOn(api, 'testAzureDiscoveryConnection');
    const sync = vi.spyOn(api, 'triggerAzureDiscoverySync');
    renderConnectPage(TENANT_ADMIN, '/connect/sources?keep=1');
    fireEvent.click(screen.getByText('Azure').closest('button')!);
    expect(await screen.findByText(/Disabled for the pilot/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Save|Test Connection|Sync now/ })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Back to Sources/ }));
    expect(await screen.findByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.getByLabelText('Current search')).toHaveTextContent(/^\?keep=1$/);
    expect(save).not.toHaveBeenCalled();
    expect(test).not.toHaveBeenCalled();
    expect(sync).not.toHaveBeenCalled();
  });

  it.each([
    { card: 'BOM Management', title: 'BOM Management' },
    { card: 'GitHub', title: 'GitHub BOM Connector' },
  ])('retains the supported $card workflow and validates input before backend submission', async ({ card, title }) => {
    vi.spyOn(api, 'listBomSources').mockResolvedValue([]);
    vi.spyOn(api, 'listGithubSbomSources').mockResolvedValue([]);
    const submit = vi.spyOn(api, 'bomFetch');
    renderConnectPage(TENANT_ADMIN);
    fireEvent.click(screen.getAllByText(card).find((element) => element.closest('button'))!.closest('button')!);
    expect(await screen.findByRole('heading', { name: title })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'GitHub Auto-Pipeline' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'URL Fetch' }));
    fireEvent.change(screen.getByPlaceholderText('https://example.com/bom.json'), { target: { value: 'https://fixture.example/bom.json' } });
    fireEvent.click(screen.getByRole('button', { name: 'Ingest SBOM' }));
    expect(await screen.findByText('Asset Name is required')).toBeInTheDocument();
    expect(submit).not.toHaveBeenCalled();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders inventory connector failure state from live connector status data', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({
      sourceSystem: 'servicenow',
      configured: true,
      baseUrl: 'https://acme.service-now.example',
      authType: 'BASIC',
      username: 'admin',
      hasCredentialSecret: true,
      installTable: 'cmdb_sam_sw_install',
      discoveryModelTable: 'cmdb_sam_sw_discovery_model',
      ciTable: 'cmdb_ci',
      installQuery: '',
      discoveryQuery: '',
      installFields: 'sys_id',
      discoveryFields: 'sys_id',
      pageSize: 1000,
      enabled: true,
      autoSyncEnabled: true,
      intervalMinutes: 1440,
      lastTestStatus: 'FAILED',
      lastTestMessage: 'credential problem',
      lastTestedAt: '2026-06-07T10:00:00Z',
      lastSyncAt: '2026-06-07T10:30:00Z'
    });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({
      sourceSystem: 'sccm',
      configured: false,
      jdbcUrl: '',
      authType: 'SQL_AUTH',
      username: '',
      hasCredential: false,
      siteCode: '',
      databaseName: 'CM_P01',
      fetchSize: 500,
      queryTimeoutSeconds: 120,
      mockMode: false,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({
      sourceSystem: 'aws',
      configured: false,
      authType: 'INSTANCE_METADATA',
      accessKeyId: '',
      hasCredential: false,
      crossAccountRoleArn: '',
      externalId: '',
      awsAccountId: undefined,
      regionsJson: '["us-east-1"]',
      resourceTypesJson: '["EC2"]',
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });

    renderConnectPage(TENANT_ADMIN);

    expect(await screen.findByLabelText(/last sync failed/i)).toBeInTheDocument();
    expect(screen.getByText('ServiceNow')).toBeInTheDocument();
  });

  it('keeps platform-owned vulnerability connector management hidden from tenant users', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({
      sourceSystem: 'servicenow',
      configured: false,
      baseUrl: '',
      authType: 'BASIC',
      username: '',
      hasCredentialSecret: false,
      installTable: 'cmdb_sam_sw_install',
      discoveryModelTable: 'cmdb_sam_sw_discovery_model',
      ciTable: 'cmdb_ci',
      installQuery: '',
      discoveryQuery: '',
      installFields: 'sys_id',
      discoveryFields: 'sys_id',
      pageSize: 1000,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({
      sourceSystem: 'sccm',
      configured: false,
      jdbcUrl: '',
      authType: 'SQL_AUTH',
      username: '',
      hasCredential: false,
      siteCode: '',
      databaseName: 'CM_P01',
      fetchSize: 500,
      queryTimeoutSeconds: 120,
      mockMode: false,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({
      sourceSystem: 'aws',
      configured: false,
      authType: 'INSTANCE_METADATA',
      accessKeyId: '',
      hasCredential: false,
      crossAccountRoleArn: '',
      externalId: '',
      awsAccountId: undefined,
      regionsJson: '["us-east-1"]',
      resourceTypesJson: '["EC2"]',
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });

    renderConnectPage(TENANT_ADMIN);

    expect(await screen.findByText(/SBOM, CMDB, Cloud discovery, and AI resource inventory sources/i)).toBeInTheDocument();
    expect(screen.queryByText('Connectors')).not.toBeInTheDocument();
    expect(screen.queryByText('NVD Vulnerability Feed')).not.toBeInTheDocument();
  });

  it('shows the tenant sources catalog by default even for an actor who also holds the platform-owner role', async () => {
    // Regression test: a platform owner who has entered a tenant workspace (or a local-dev actor
    // granted every role) must still land on this tenant's connector catalog, not be redirected
    // into platform-owned vulnerability feed administration.
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({
      sourceSystem: 'servicenow',
      configured: false,
      baseUrl: '',
      authType: 'BASIC',
      username: '',
      hasCredentialSecret: false,
      installTable: 'cmdb_sam_sw_install',
      discoveryModelTable: 'cmdb_sam_sw_discovery_model',
      ciTable: 'cmdb_ci',
      installQuery: '',
      discoveryQuery: '',
      installFields: 'sys_id',
      discoveryFields: 'sys_id',
      pageSize: 1000,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({
      sourceSystem: 'sccm',
      configured: false,
      jdbcUrl: '',
      authType: 'SQL_AUTH',
      username: '',
      hasCredential: false,
      siteCode: '',
      databaseName: 'CM_P01',
      fetchSize: 500,
      queryTimeoutSeconds: 120,
      mockMode: false,
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({
      sourceSystem: 'aws',
      configured: false,
      authType: 'INSTANCE_METADATA',
      accessKeyId: '',
      hasCredential: false,
      crossAccountRoleArn: '',
      externalId: '',
      awsAccountId: undefined,
      regionsJson: '["us-east-1"]',
      resourceTypesJson: '["EC2"]',
      enabled: true,
      autoSyncEnabled: false,
      intervalMinutes: 1440
    });

    renderConnectPage({ ...TENANT_ADMIN, roles: ['TENANT_ADMIN', 'PLATFORM_OWNER'] });

    expect(await screen.findByText(/SBOM, CMDB, Cloud discovery, and AI resource inventory sources/i)).toBeInTheDocument();
    expect(screen.queryByText('Connectors')).not.toBeInTheDocument();
    expect(screen.queryByText('NVD Vulnerability Feed')).not.toBeInTheDocument();
  });
});
