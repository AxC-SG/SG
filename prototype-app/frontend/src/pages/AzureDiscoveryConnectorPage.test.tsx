import { screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AzureDiscoveryConnectorPage } from './AzureDiscoveryConnectorPage';

afterEach(() => vi.restoreAllMocks());

it('shows containment and retained subscriptions without allowing live actions', async () => {
  vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue({
    sourceSystem: 'azure', configured: true, authType: 'CLIENT_SECRET', azureTenantId: 'saved-directory',
    clientId: '', hasCredential: true, subscriptionIdsJson: '[]', regionsJson: '[]', enabled: true,
    autoSyncEnabled: true, intervalMinutes: 1440,
  });
  vi.spyOn(api, 'listAzureDiscoveryTargets').mockResolvedValue([{
    id: 'target-1', subscriptionId: 'sub-1', subscriptionName: 'Production', enabled: true,
    regionsJson: '[]', hostCount: 3,
  }]);
  const save = vi.spyOn(api, 'saveAzureDiscoveryConfig');
  const test = vi.spyOn(api, 'testAzureDiscoveryConnection');
  const sync = vi.spyOn(api, 'triggerAzureDiscoverySync');
  renderWithProviders(<AzureDiscoveryConnectorPage />);
  expect(screen.getByRole('status')).toHaveTextContent('Disabled for the pilot');
  expect(await screen.findByText(/Production — sub-1/)).toBeInTheDocument();
  expect(screen.queryByRole('button')).not.toBeInTheDocument();
  expect(screen.getByRole('link', { name: /View retained cloud inventory/ })).toHaveAttribute('href', '/inventory/cloud-resources');
  expect(save).not.toHaveBeenCalled();
  expect(test).not.toHaveBeenCalled();
  expect(sync).not.toHaveBeenCalled();
});

it('distinguishes a failed settings load from the paused-for-pilot banner', async () => {
  vi.spyOn(api, 'getAzureDiscoveryConfig').mockRejectedValue(new Error('down'));
  renderWithProviders(<AzureDiscoveryConnectorPage />);
  expect(await screen.findByRole('alert')).toHaveTextContent('Saved Azure settings could not be loaded.');
  expect(screen.getByRole('status')).toHaveTextContent('Disabled for the pilot');
  expect(screen.queryByText(/No Azure settings were saved/)).not.toBeInTheDocument();
});
