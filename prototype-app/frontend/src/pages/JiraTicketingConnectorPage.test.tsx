import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import type { JiraTicketingConfig, TicketingProviderStatus } from '../features/connect/types';
import { renderWithProviders } from '../test/test-utils';
import { JiraTicketingConnectorPage } from './JiraTicketingConnectorPage';

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
      <JiraTicketingConnectorPage />
    </ActorContextState.Provider>
  );
}

function config(overrides: Partial<JiraTicketingConfig> = {}): JiraTicketingConfig {
  return {
    configured: false,
    baseUrl: '',
    authType: 'BASIC',
    username: '',
    hasCredentialSecret: false,
    projectKey: '',
    issueTypeId: '',
    issueTypeName: 'Task',
    defaultLabels: '',
    includePriority: true,
    enabled: true,
    ...overrides
  };
}

function providerStatus(overrides: Partial<TicketingProviderStatus> = {}): TicketingProviderStatus {
  return {
    activeProvider: null,
    activeProviderName: null,
    configuredProviders: [],
    overridden: [],
    ...overrides
  };
}

describe('JiraTicketingConnectorPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('prompts for setup when no connector is saved', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(config());
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus());

    renderPage();

    expect(await screen.findByText(/not yet configured/i)).toBeInTheDocument();
  });

  it('says Jira is overriding ServiceNow and that existing incidents keep syncing', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', hasCredentialSecret: true })
    );
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus({
      activeProvider: 'jira',
      activeProviderName: 'Jira',
      configuredProviders: ['jira', 'servicenow'],
      overridden: ['servicenow']
    }));

    renderPage();

    expect(await screen.findByText(/Jira is the active ticketing system/i)).toBeInTheDocument();
    expect(screen.getByText(/continue to sync from ServiceNow/i)).toBeInTheDocument();
  });

  it('explains that a disabled connector hands ticketing back to ServiceNow', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', enabled: false })
    );
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus({
      activeProvider: 'servicenow',
      activeProviderName: 'ServiceNow',
      configuredProviders: ['servicenow']
    }));

    renderPage();

    expect(await screen.findByText(/saved but disabled/i)).toBeInTheDocument();
  });

  /**
   * The stored token must survive a save that does not re-enter it, otherwise editing any other
   * field would silently break ticketing.
   */
  it('omits the credential when the token field is left blank', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', hasCredentialSecret: true })
    );
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus());
    const save = vi.spyOn(api, 'saveJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', hasCredentialSecret: true })
    );

    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: /save connector/i }));

    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(save.mock.calls[0][0].credentialSecret).toBeUndefined();
  });

  it('sends a newly entered token and upper-cases the project key', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(config());
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus());
    const save = vi.spyOn(api, 'saveJiraTicketingConfig').mockResolvedValue(config({ configured: true }));

    renderPage();

    fireEvent.change(await screen.findByPlaceholderText('https://your-org.atlassian.net'), {
      target: { value: 'https://acme.atlassian.net' }
    });
    fireEvent.change(screen.getByPlaceholderText('SEC'), { target: { value: 'sec' } });
    fireEvent.change(screen.getByPlaceholderText('Enter API token'), { target: { value: 'token-123' } });
    fireEvent.click(screen.getByRole('button', { name: /save connector/i }));

    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(save.mock.calls[0][0].credentialSecret).toBe('token-123');
    expect(save.mock.calls[0][0].projectKey).toBe('SEC');
  });

  it('surfaces which half of the connection test failed', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', hasCredentialSecret: true })
    );
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus());
    vi.spyOn(api, 'saveJiraTicketingConfig').mockResolvedValue(
      config({ configured: true, baseUrl: 'https://acme.atlassian.net', projectKey: 'SEC', hasCredentialSecret: true })
    );
    vi.spyOn(api, 'testJiraTicketingConnection').mockResolvedValue({
      status: 'FAILED',
      message: 'Jira project check returned HTTP 404',
      credentialsValid: true,
      projectReachable: false,
      testedAt: '2026-09-20T09:00:00Z'
    });

    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: /test connection/i }));

    expect(await screen.findByText(/Connection failed/i)).toBeInTheDocument();
    expect(screen.getByText(/Credentials ✓/)).toBeInTheDocument();
    expect(screen.getByText(/Project ✗/)).toBeInTheDocument();
  });

  it('blocks editing for an actor without connector management rights', async () => {
    vi.spyOn(api, 'getJiraTicketingConfig').mockResolvedValue(config());
    vi.spyOn(api, 'getTicketingProviderStatus').mockResolvedValue(providerStatus());

    renderPage(ANALYST);

    expect(await screen.findByRole('button', { name: /save connector/i })).toBeDisabled();
    expect(screen.getByText(/need the Tenant Admin or Inventory Admin role/i)).toBeInTheDocument();
  });
});
