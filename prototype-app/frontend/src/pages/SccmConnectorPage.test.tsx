import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import type { SccmCmdbConfig } from '../features/connect/types';
import { renderWithProviders } from '../test/test-utils';
import { SccmConnectorPage } from './SccmConnectorPage';

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'tenant.admin@example.test',
  userId: 'tenant-admin',
  tenantId: 'tenant-1',
  tenantName: 'Customer One',
  roles: ['TENANT_ADMIN']
};

const ANALYST: ActorContext = { ...TENANT_ADMIN, roles: ['SECURITY_ANALYST'] };

function renderPage(actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <SccmConnectorPage />
    </ActorContextState.Provider>
  );
}

function config(overrides: Partial<SccmCmdbConfig> = {}): SccmCmdbConfig {
  return {
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
    intervalMinutes: 1440,
    ...overrides
  };
}

describe('SccmConnectorPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('is a live connector with save, test and sync actions and no mock or Windows auth option', async () => {
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(config());
    renderPage();

    expect(await screen.findByRole('button', { name: 'Save Connector' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Test Connection' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Run Integration now' })).toBeEnabled();
    expect(screen.queryByText(/mock mode/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/windows auth/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/disabled for the assisted pilot/i)).not.toBeInTheDocument();
    expect(screen.getByText(/approved by your platform operator/i)).toBeInTheDocument();
  });

  it('saves SQL authentication with the password write-only and mock mode off', async () => {
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(config());
    const save = vi.spyOn(api, 'saveSccmCmdbConfig').mockResolvedValue(config({
      configured: true,
      jdbcUrl: 'jdbc:sqlserver://sccm.corp.example:1433;databaseName=CM_P01',
      username: 'svc-scout',
      hasCredential: true
    }));
    renderPage();

    fireEvent.change(await screen.findByPlaceholderText(/jdbc:sqlserver:\/\//), {
      target: { value: ' jdbc:sqlserver://sccm.corp.example:1433;databaseName=CM_P01 ' }
    });
    fireEvent.change(screen.getByPlaceholderText('svc-scout-sccm'), { target: { value: 'svc-scout' } });
    fireEvent.change(screen.getByPlaceholderText('Enter SQL password'), { target: { value: 's3cret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Connector' }));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save).toHaveBeenCalledWith(expect.objectContaining({
      jdbcUrl: 'jdbc:sqlserver://sccm.corp.example:1433;databaseName=CM_P01',
      authType: 'SQL_AUTH',
      username: 'svc-scout',
      credentialSecret: 's3cret',
      mockMode: false
    }));
    expect(await screen.findByText(/Password saved/)).toBeInTheDocument();
    expect(screen.queryByDisplayValue('s3cret')).not.toBeInTheDocument();
  });

  it('shows the server rejection when the host is not approved and does not try to test', async () => {
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(config());
    vi.spyOn(api, 'saveSccmCmdbConfig').mockRejectedValue(
      new Error('SCCM database host is not approved for this deployment. Ask an operator to add it to SCCM_ALLOWED_HOSTS.')
    );
    const test = vi.spyOn(api, 'testSccmCmdbConnection');
    renderPage();

    fireEvent.change(await screen.findByPlaceholderText(/jdbc:sqlserver:\/\//), {
      target: { value: 'jdbc:sqlserver://other.example' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));

    expect(await screen.findByText(/not approved for this deployment/)).toBeInTheDocument();
    expect(test).not.toHaveBeenCalled();
  });

  it('reports which SCCM views a connection test reached', async () => {
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(config({ configured: true, jdbcUrl: 'jdbc:sqlserver://sccm.corp.example', username: 'svc', hasCredential: true }));
    vi.spyOn(api, 'saveSccmCmdbConfig').mockResolvedValue(config({ configured: true, jdbcUrl: 'jdbc:sqlserver://sccm.corp.example', username: 'svc', hasCredential: true }));
    vi.spyOn(api, 'testSccmCmdbConnection').mockResolvedValue({
      status: 'FAILED',
      message: 'SCCM connection partial: v_R_System reachable but v_GS_INSTALLED_SOFTWARE was not.',
      systemViewReachable: true,
      softwareViewReachable: false,
      testedAt: '2026-10-26T10:00:00Z'
    });
    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Test Connection' }));

    expect(await screen.findByText(/Connection failed/)).toBeInTheDocument();
    expect(screen.getByText(/v_R_System ✓/)).toBeInTheDocument();
    expect(screen.getByText(/v_GS_INSTALLED_SOFTWARE ✗/)).toBeInTheDocument();
  });

  it('queues an integration run and points at the run queue', async () => {
    const saved = config({ configured: true, jdbcUrl: 'jdbc:sqlserver://sccm.corp.example', username: 'svc', hasCredential: true });
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(saved);
    vi.spyOn(api, 'saveSccmCmdbConfig').mockResolvedValue(saved);
    const sync = vi.spyOn(api, 'triggerSccmCmdbSync').mockResolvedValue({ runId: 'run-1', status: 'queued', message: 'SCCM CMDB sync queued' });
    renderPage();

    fireEvent.click(await screen.findByRole('button', { name: 'Run Integration now' }));

    await waitFor(() => expect(sync).toHaveBeenCalledTimes(1));
    expect(await screen.findByText(/Integration queued/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Integration Run Queue' })).toBeInTheDocument();
  });

  it('keeps the actions disabled for roles that cannot manage inventory sources', async () => {
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue(config());
    renderPage(ANALYST);

    expect(await screen.findByRole('button', { name: 'Save Connector' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Test Connection' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Run Integration now' })).toBeDisabled();
  });
});
