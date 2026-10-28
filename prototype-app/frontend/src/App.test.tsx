import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { QueryClient } from '@tanstack/react-query';
import { useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { pathForFixIntelligenceView } from './app/routes';
import type { ActorContext } from './features/auth/types';
import { renderWithProviders } from './test/test-utils';

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname}</output>;
}

const TENANT_ADMIN: ActorContext = {
  creator: false,
  principal: 'admin-a@example.test',
  userId: 'admin-a',
  tenantId: 'tenant-a',
  tenantName: 'Customer A',
  roles: ['TENANT_ADMIN']
};

const PLATFORM_OWNER_PLATFORM_SCOPE: ActorContext = {
  creator: true,
  principal: 'owner@example.com',
  userId: 'owner@example.com',
  tenantId: null,
  tenantName: null,
  roles: ['PLATFORM_OWNER'],
  platformScope: true
};

const PLATFORM_OWNER_TENANT_CONTEXT: ActorContext = {
  creator: true,
  principal: 'owner@example.com',
  userId: 'owner@example.com',
  tenantId: 'tenant-a',
  tenantName: 'Customer A',
  roles: ['PLATFORM_OWNER'],
  platformScope: false,
  actingAsPlatformOwner: true,
  allowedTenants: [{
    id: 'tenant-a',
    name: 'Customer A',
    slug: 'customer-a',
    role: 'PLATFORM_OWNER',
    accessMode: 'READ_ONLY',
    expiresAt: '2026-12-31T00:00:00Z'
  }]
};

describe('App test persona switcher', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.resetModules();
    window.localStorage.clear();
  });

  it('shows the public landing page immediately while the root session check is pending', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockImplementation(() => new Promise<ActorContext>(() => undefined));

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/' });

    expect(await screen.findByRole('heading', { name: /The Exposure Management Platform Powered by AI Grid/i })).toBeInTheDocument();
    expect(screen.queryByText('Loading page...')).not.toBeInTheDocument();
  });

  it('keeps the session on a temporary verification failure and retries', async () => {
    const auth = await import('./features/auth/api');
    const client = await import('./api/client');
    client.setStoredAuthToken('valid-session');
    vi.spyOn(auth.authApi, 'getActorContext').mockRejectedValueOnce(new client.ApiError('Service unavailable', 503)).mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    expect(await screen.findByRole('button', { name: 'Retry' })).toBeInTheDocument();
    expect(client.getStoredAuthToken()).toBe('valid-session');
    expect(screen.queryByRole('button', { name: 'Sign in' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('button', { name: 'Customer A TENANT ADMIN: Open account menu' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Customer A TENANT ADMIN: Open account menu' }));
    expect(await screen.findByRole('menuitem', { name: 'Log out' })).toBeInTheDocument();
    expect(screen.getByText('admin-a@example.test')).toBeInTheDocument();
  });

  it('clears an expired session before showing login', async () => {
    const auth = await import('./features/auth/api');
    const client = await import('./api/client');
    client.setStoredAuthToken('expired-session');
    vi.spyOn(auth.authApi, 'getActorContext').mockRejectedValue(new client.ApiError('Unauthorized', 401));
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(client.getStoredAuthToken()).toBe('');
    expect(screen.queryByRole('button', { name: 'Log out' })).not.toBeInTheDocument();
  });

  it('shows non-production personas from the gear menu and supports UI preview mode', async () => {
    vi.stubEnv('VITE_ENABLE_TEST_PERSONAS', 'true');
    const auth = await import('./features/auth/api');
    const client = await import('./api/client');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    vi.spyOn(client.api, 'listTestPersonas').mockResolvedValue([
      {
        key: 'tenant-a-admin',
        label: 'Tenant A Admin',
        subject: 'persona-tenant-a-admin',
        tenantSlug: 'customer-a',
        tenantName: 'Customer A',
        roles: ['TENANT_ADMIN']
      }
    ]);

    const { default: App } = await import('./App');
    renderWithProviders(<App />);

    fireEvent.click(await screen.findByLabelText('Open settings menu'));
    expect(screen.getByText('Impersonate User')).toBeInTheDocument();
    expect(screen.queryByText(/Refresh personas/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Load personas/i)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('menuitem', { name: /Impersonate User/i }));
    expect(await screen.findByRole('dialog', { name: /Non-production test personas/i })).toBeInTheDocument();
    expect(await screen.findByText('Tenant A Admin')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Preview' }));

    await waitFor(() => {
      expect(screen.getByText('Impersonating: Tenant A Admin')).toBeInTheDocument();
    });
    expect(screen.getAllByText('UI preview only')[0]).toBeInTheDocument();
    expect(screen.getByText(/backend authorization still uses the current real session/i)).toBeInTheDocument();
  });

  it('hides the gear-menu persona option unless explicitly enabled', async () => {
    vi.stubEnv('VITE_ENABLE_TEST_PERSONAS', 'false');
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);

    const { default: App } = await import('./App');
    renderWithProviders(<App />);

    fireEvent.click(await screen.findByLabelText('Open settings menu'));

    expect(screen.queryByText('Impersonate User')).not.toBeInTheDocument();
  });

  it('refetches actor context when the auth token changes between sessions', async () => {
    const auth = await import('./features/auth/api');
    const client = await import('./api/client');
    const platformOwner: ActorContext = {
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER']
    };
    const actorSpy = vi.spyOn(auth.authApi, 'getActorContext')
      .mockResolvedValueOnce(TENANT_ADMIN)
      .mockResolvedValueOnce(platformOwner);

    client.setStoredAuthToken('tenant-token');
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
          staleTime: 10_000
        }
      }
    });

    const { default: App } = await import('./App');
    const view = renderWithProviders(<App />, { route: '/platform/demo-requests', queryClient });

    expect(await screen.findByText(/Platform console access requires the Platform Owner role/i)).toBeInTheDocument();

    client.setStoredAuthToken('platform-token');
    view.unmount();
    renderWithProviders(<App />, { route: '/platform/demo-requests', queryClient });

    await waitFor(() => {
      expect(actorSpy).toHaveBeenCalledTimes(2);
    });
    expect(await screen.findByRole('heading', { name: 'Tenant Management' })).toBeInTheDocument();
  });

  it('shows EOL in the platform-owner nav, keeps operations out of the global nav, and groups it in the platform sidebar', async () => {
    const auth = await import('./features/auth/api');
    const platformOwner: ActorContext = {
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    };
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(platformOwner);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/platform/tenants' });

    expect(await screen.findByRole('button', { name: 'Tenant Management' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Tenant context switcher')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'End-of-Life' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Policy Distribution' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'AI Policies' })).not.toBeInTheDocument();
    const platformViews = await screen.findByLabelText('Platform views');
    expect(within(platformViews).getByLabelText('Tenant Management')).toBeInTheDocument();
    expect(within(platformViews).queryByText('AI Policy Studio')).not.toBeInTheDocument();
    expect(within(platformViews).queryByLabelText('Operations')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Operations' })).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Open settings menu'));
    expect(screen.queryByText('Tenant Administration')).not.toBeInTheDocument();
  });

  it('opens platform policies from its top-level navigation item', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(PLATFORM_OWNER_PLATFORM_SCOPE);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/platform/tenants' });

    fireEvent.click(await screen.findByRole('button', { name: 'Policy Distribution' }));

    expect(await screen.findByRole('heading', { name: 'Policy distribution' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Policy Distribution' })).toHaveClass('active');
    expect(screen.queryByLabelText('Platform views')).not.toBeInTheDocument();
  });

  it('redirects platform-scope owners away from operations into platform EOL', async () => {
    const auth = await import('./features/auth/api');
    const platformOwner: ActorContext = {
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    };
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(platformOwner);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/operations/pipeline' });

    expect((await screen.findAllByRole('heading', { name: 'End-of-Life' })).length).toBeGreaterThan(0);
    expect(screen.getByText(/Operations is no longer part of the platform view/i)).toBeInTheDocument();
  });

  it('shows only EOL info in the platform subnav for the EOL view', async () => {
    const auth = await import('./features/auth/api');
    const platformOwner: ActorContext = {
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    };
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(platformOwner);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/platform/eol' });

    expect(await screen.findByRole('heading', { name: 'End-of-Life' })).toBeInTheDocument();
    expect(screen.queryByLabelText('Platform views')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'End-of-Life' })).toBeInTheDocument();
  });

  it('redirects legacy end-of-life route into the platform console for platform owners', async () => {
    const auth = await import('./features/auth/api');
    const platformOwner: ActorContext = {
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    };
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(platformOwner);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/end-of-life' });

    expect(await screen.findByRole('heading', { name: 'End-of-Life' })).toBeInTheDocument();
  });

  it('shows tenant administration navigation for tenant admins', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/' });

    expect(await screen.findByText('Configurations')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Exposure' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Findings' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Vulnerability Repository' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Campaigns' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Connectors' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Administration' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Configurations' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'End-of-Life' })).not.toBeInTheDocument();
  });

  it('redirects platform-scope owners away from tenant administration routes', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(PLATFORM_OWNER_PLATFORM_SCOPE);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/admin/users' });

    expect(await screen.findByRole('heading', { name: 'Tenant Management' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Members and access scope/ })).not.toBeInTheDocument();
  });

  it('blocks tenant admins from platform-user management routes', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/platform/users' });

    expect(await screen.findByText(/Platform console access requires the Platform Owner role/i)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Platform User Directory' })).not.toBeInTheDocument();
  });

  it('keeps acting platform owners out of tenant user-management routes', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(PLATFORM_OWNER_TENANT_CONTEXT);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/admin/users' });

    expect(await screen.findByText('Exposure Dashboard')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Members and access scope/ })).not.toBeInTheDocument();
  });

  it('redirects tenant-scoped users away from the legacy EOL URL', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/end-of-life' });

    expect(await screen.findByText('Exposure Dashboard')).toBeInTheDocument();
    expect(screen.queryByText('End-of-Life')).not.toBeInTheDocument();
  });

  it.each([
    '/connect/sources?connectSource=sccm-patch',
    '/connect/sources?connectSource=bigfix-patch',
    '/connect/sources?connectSource=tanium-patch',
    '/connect/sccm-patch',
    '/connect/bigfix-patch',
    '/connect/tanium-patch',
  ])('contains retired patch connector navigation through the app router: %s', async (route) => {
    const auth = await import('./features/auth/api');
    const { api } = await import('./api/client');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue({ ...TENANT_ADMIN, entitlements: { 'ai.security': true } });
    vi.spyOn(api, 'getServiceNowCmdbConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getServiceNowCmdbConfig>>);
    vi.spyOn(api, 'getSccmCmdbConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getSccmCmdbConfig>>);
    vi.spyOn(api, 'getAwsDiscoveryConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getAwsDiscoveryConfig>>);
    vi.spyOn(api, 'getAzureDiscoveryConfig').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof api.getAzureDiscoveryConfig>>);
    vi.spyOn(api, 'listVulnerabilitySourceFilterConfigs').mockResolvedValue([]);
    vi.spyOn(api, 'getVulnIntelSourcesSummary').mockResolvedValue({ sources: {} } as Awaited<ReturnType<typeof api.getVulnIntelSourcesSummary>>);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const { default: App } = await import('./App');
    const { container } = renderWithProviders(<App />, { route });
    expect(await screen.findByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Patch Management' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /BigFix|Tanium|Test Connection|Save Configuration/ })).not.toBeInTheDocument();
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(log).not.toHaveBeenCalled();
  });

  it('removes synthetic Fix Intelligence navigation while retained workflows remain reachable', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    expect(await screen.findByText('Exposure Dashboard')).toBeInTheDocument();
    expect(screen.queryByText('Fix Intelligence')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Findings' })).toBeInTheDocument();
  });

  it.each([
    '/fix-intelligence',
    pathForFixIntelligenceView('patches'),
    '/fix-intelligence/details/fix-1',
  ])('redirects retired Fix Intelligence URLs to findings: %s', async (route) => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<><App /><LocationProbe /></>, { route });
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/findings$/));
    expect(screen.queryByText('Fix Intelligence')).not.toBeInTheDocument();
  });
});
