import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AssetsPage } from './AssetsPage';

function buildConfig(overrides = {}) {
  return {
    sourceSystem: 'servicenow',
    configured: true,
    baseUrl: 'https://example.service-now.com',
    authType: 'BASIC' as const,
    username: 'admin',
    hasCredentialSecret: true,
    installTable: 'cmdb_sam_sw_install',
    discoveryModelTable: 'cmdb_sam_sw_discovery_model',
    ciTable: 'cmdb_ci',
    installQuery: '',
    discoveryQuery: '',
    installFields: 'sys_id,display_name',
    discoveryFields: 'sys_id,primary_key',
    pageSize: 1000,
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440,
    ...overrides,
  };
}

describe('AssetsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows loading state while config is fetching', () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<AssetsPage />);
    expect(screen.getByText('Loading ServiceNow CMDB connector...')).toBeInTheDocument();
  });

  it('renders the Connection section heading after config loads', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue(buildConfig());
    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText('Connection')).toBeInTheDocument());
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });

  it('renders the Table Configuration section heading', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue(buildConfig());
    renderWithProviders(<AssetsPage />);
    await waitFor(() =>
      expect(screen.getByText('Table Configuration')).toBeInTheDocument()
    );
  });

  it('renders the Sync Settings section heading', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue(buildConfig());
    renderWithProviders(<AssetsPage />);
    await waitFor(() =>
      expect(screen.getByText('Sync Settings')).toBeInTheDocument()
    );
  });

  it('disables Save and Test buttons when actor is null (unauthenticated)', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue(buildConfig());
    renderWithProviders(<AssetsPage />);
    await waitFor(() => expect(screen.getByText('Connection')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: /save/i })).toBeDisabled();
    expect(screen.getByRole('button', { name: /test connection/i })).toBeDisabled();
  });

  it('shows the configured base URL in the form', async () => {
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue(
      buildConfig({ baseUrl: 'https://myinstance.service-now.com' })
    );
    renderWithProviders(<AssetsPage />);
    await waitFor(() => {
      const input = screen.getByDisplayValue('https://myinstance.service-now.com');
      expect(input).toBeInTheDocument();
    });
  });
});
