import { fireEvent, screen, waitFor } from '@testing-library/react';
import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityAzureFoundryConfig } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiSecurityAzureConnectorPage } from './AiSecurityAzureConnectorPage';

function buildConfig(overrides: Partial<AiSecurityAzureFoundryConfig> = {}): AiSecurityAzureFoundryConfig {
  return {
    configured: false,
    azureTenantId: null,
    clientId: null,
    hasCredential: false,
    primarySubscriptionId: null,
    subscriptionIds: [],
    regions: [],
    foundryEndpointUrl: null,
    connectorId: null,
    credentialExpiresAt: null,
    ...overrides,
  };
}

describe('AiSecurityAzureConnectorPage', () => {
  beforeEach(() => vi.spyOn(api, 'listAiSecurityConnectorFeatureFlags').mockResolvedValue([]));
  afterEach(() => vi.restoreAllMocks());

  it('explains disabled agent discovery and enables Foundry through the governed settings API', async () => {
    vi.spyOn(api, 'getAiSecurityAzureFoundryConfig').mockResolvedValue(buildConfig());
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
    const update = vi.spyOn(api, 'updateAiSecurityConnectorFeatureFlag').mockResolvedValue({
      featureKey: 'AZURE_NEW_FOUNDRY', enabled: true, killSwitch: false, updatedBy: 'admin', updatedAt: null,
    });
    renderWithProviders(<AiSecurityAzureConnectorPage />);
    expect(await screen.findByText(/Agent discovery is disabled/)).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText('Foundry agents', { exact: true }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('AZURE_NEW_FOUNDRY', { enabled: true, killSwitch: false }));
  });

  it('saves the single configuration form in one call, with no separate target step', async () => {
    // Regression test: the old page required a separate Azure Cloud Discovery connector to be
    // configured first, and a credential profile that had no visible confirmation after creation.
    // The simplified form now does everything in one save.
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
    const getConfig = vi.spyOn(api, 'getAiSecurityAzureFoundryConfig').mockResolvedValue(buildConfig());
    const saveConfig = vi.spyOn(api, 'saveAiSecurityAzureFoundryConfig').mockImplementation(async (payload) => {
      const saved = buildConfig({
        configured: true,
        azureTenantId: payload.azureTenantId,
        clientId: payload.clientId,
        hasCredential: true,
        primarySubscriptionId: 'sub-1',
        subscriptionIds: ['sub-1'],
        regions: ['eastus2'],
        foundryEndpointUrl: payload.foundryEndpointUrl ?? null,
        connectorId: 'connector-1',
      });
      getConfig.mockResolvedValue(saved);
      return saved;
    });

    renderWithProviders(<AiSecurityAzureConnectorPage />);

    expect(await screen.findByText('Not configured')).toBeInTheDocument();
    expect(screen.queryByText(/Bind an approved subscription/)).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Tenant ID'), { target: { value: 'tenant-abc' } });
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'client-abc' } });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'super-secret' } });
    fireEvent.change(screen.getByLabelText('Subscription IDs'), { target: { value: 'sub-1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save configuration' }));

    await waitFor(() => expect(saveConfig).toHaveBeenCalledWith(expect.objectContaining({
      azureTenantId: 'tenant-abc',
      clientId: 'client-abc',
      clientSecret: 'super-secret',
      subscriptionIds: 'sub-1',
    })));
    expect(await screen.findByText('Success')).toBeInTheDocument();
  });

  it('shows the latest run artifact count and enables test/execute once configured', async () => {
    vi.spyOn(api, 'getAiSecurityAzureFoundryConfig').mockResolvedValue(buildConfig({
      configured: true,
      azureTenantId: 'tenant-1',
      clientId: 'client-1',
      hasCredential: true,
      primarySubscriptionId: 'sub-1',
      subscriptionIds: ['sub-1'],
      regions: ['eastus2'],
      connectorId: 'connector-1',
    }));
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([{
      id: 'run-1',
      status: 'COMPLETED',
      recordsFetched: 9,
      recordsFailed: 0,
      startedAt: '2026-07-01T00:00:00Z',
      completedAt: '2026-07-01T00:02:00Z',
      errorMessage: null,
    }]);
    vi.spyOn(api, 'listAiSecurityRunScopes').mockResolvedValue([]);
    const run = vi.spyOn(api, 'runAiSecurityAzureFoundryConfig').mockResolvedValue({
      jobId: 'job-1', status: 'QUEUED', message: 'Queued',
    });

    renderWithProviders(<AiSecurityAzureConnectorPage />);

    expect(await screen.findByText('Last run completed with 9 artifacts discovered.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test connection' })).not.toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Execute now' }));
    await waitFor(() => expect(run).toHaveBeenCalled());
  });
});
