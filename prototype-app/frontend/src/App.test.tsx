import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { QueryClient } from '@tanstack/react-query';
import { useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { pathForFixIntelligenceView } from './app/routes';
import type { ActorContext } from './features/auth/types';
import { renderWithProviders } from './test/test-utils';

const sidebar = () => within(screen.getByRole('navigation', { name: 'Primary' }));

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

    expect(await screen.findByRole('heading', { name: /Secure AI\.\s*See the whole exposure\./i })).toBeInTheDocument();
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
    renderWithProviders(<App />, { route: '/exposure' });

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

    expect(await screen.findByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Tenant Management' })).toHaveAttribute('aria-current', 'page');
    expect(screen.queryByLabelText('Tenant context switcher')).not.toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'End-of-Life' })).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Policy Distribution' })).toBeInTheDocument();
    expect(sidebar().queryByRole('link', { name: 'Policies' })).not.toBeInTheDocument();
    expect(sidebar().queryByRole('link', { name: 'Fix Intelligence' })).not.toBeInTheDocument();
    expect(sidebar().queryByRole('group', { name: 'Remediation' })).not.toBeInTheDocument();
    const platformViews = await screen.findByLabelText('Platform views');
    expect(within(platformViews).getByLabelText('Tenant Management')).toBeInTheDocument();
    expect(within(platformViews).queryByText('AI Policy Studio')).not.toBeInTheDocument();
    expect(within(platformViews).queryByLabelText('Operations')).not.toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Operations' })).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText('Open settings menu'));
    expect(screen.queryByText('Tenant Administration')).not.toBeInTheDocument();
  });

  it('opens platform policies from its top-level navigation item', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(PLATFORM_OWNER_PLATFORM_SCOPE);

    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/platform/tenants' });

    await screen.findByRole('navigation', { name: 'Primary' });
    fireEvent.click(sidebar().getByRole('link', { name: 'Policy Distribution' }));

    expect(await screen.findByRole('heading', { name: 'Policy distribution' })).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Policy Distribution' })).toHaveAttribute('aria-current', 'page');
    expect(sidebar().getByRole('link', { name: 'Tenant Management' })).not.toHaveAttribute('aria-current');
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

  it.each(['TENANT_ADMIN', 'INVENTORY_ADMIN', 'SECURITY_ANALYST', 'READ_ONLY_AUDITOR'].flatMap((role) => (
    ['/operations', '/operations/pipeline', '/operations/platform-health'].map((route) => ({ role, route }))
  )))('redirects $role away from platform-only $route before requesting operations data', async ({ role, route }) => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue({ ...TENANT_ADMIN, roles: [role] });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const { default: App } = await import('./App');
    renderWithProviders(<><App /><LocationProbe /></>, { route });

    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/exposure$/));
    expect(fetchSpy.mock.calls.some(([url]) => /\/api\/(operations|slo)\//.test(String(url)))).toBe(false);
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
    expect(sidebar().getByRole('link', { name: 'End-of-Life' })).toHaveAttribute('aria-current', 'page');
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
    renderWithProviders(<><App /><LocationProbe /></>, { route: '/' });

    expect(await screen.findByRole('link', { name: 'Configurations' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/exposure$/));
    expect(sidebar().getByRole('link', { name: 'Exposure' })).toBeInTheDocument();
    const remediation = within(sidebar().getByRole('group', { name: 'Remediation' }));
    expect(remediation.getAllByRole('link').map((link) => link.textContent)).toEqual(['Vulnerability Findings', 'Campaigns']);
    expect(within(sidebar().getByRole('group', { name: 'Intelligence' })).getAllByRole('link').map((link) => link.textContent)).toEqual(['Vulnerability Repository']);
    expect(within(sidebar().getByRole('group', { name: 'Assets' })).getByRole('link', { name: 'Inventory' })).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Fix Intelligence' }).closest('[role="group"]')).toBeNull();
    expect(sidebar().getByRole('link', { name: 'Connectors' })).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Administration' })).toBeInTheDocument();
    expect(sidebar().queryByRole('link', { name: 'End-of-Life' })).not.toBeInTheDocument();
    expect(sidebar().queryByRole('link', { name: 'Policies' })).not.toBeInTheDocument();
    expect(sidebar().queryByRole('link', { name: 'AI Inventory' })).not.toBeInTheDocument();
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

  it('collapses sidebar sections again when entering a different tenant', async () => {
    const auth = await import('./features/auth/api');
    const client = await import('./api/client');
    const actorSpy = vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    client.setStoredAuthToken('tenant-a-token');
    const { default: App } = await import('./App');
    const view = renderWithProviders(<App />, { route: '/exposure' });
    fireEvent.click(await screen.findByRole('button', { name: 'Expand Inventory sections' }));
    expect(sidebar().getByRole('button', { name: 'Collapse Inventory sections' })).toHaveAttribute('aria-expanded', 'true');

    actorSpy.mockResolvedValue({ ...TENANT_ADMIN, tenantId: 'tenant-b', tenantName: 'Customer B' });
    client.setStoredAuthToken('tenant-b-token');
    view.rerender(<App />);

    await screen.findByRole('button', { name: 'Customer B TENANT ADMIN: Open account menu' });
    for (const disclosure of sidebar().getAllByRole('button', { name: /^Expand .* sections$/ })) {
      expect(disclosure).toHaveAttribute('aria-expanded', 'false');
    }
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
    const { fixIntelligenceApi } = await import('./features/fix-intelligence/api');
    vi.spyOn(fixIntelligenceApi, 'getPatchConnector').mockResolvedValue({ configured: false } as Awaited<ReturnType<typeof fixIntelligenceApi.getPatchConnector>>);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const { default: App } = await import('./App');
    const { container } = renderWithProviders(<App />, { route });
    // The first case also pays for lazily loading the Connect page.
    expect(await screen.findByRole('heading', { name: 'Inventory' }, { timeout: 5000 })).toBeInTheDocument();
    // Retired mock IDs fall back to the catalog; they never open a connector form.
    expect(screen.queryByRole('button', { name: /Test Connection|Save Configuration/ })).not.toBeInTheDocument();
    expect(container.querySelector('input[type="password"]')).toBeNull();
    expect(log).not.toHaveBeenCalled();
  });

  it('shows Fix Intelligence navigation for tenant users', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    expect(await screen.findByText('Exposure Dashboard')).toBeInTheDocument();
    expect(sidebar().getByRole('link', { name: 'Fix Intelligence' })).toHaveAttribute('href', '/fix-intelligence');
    expect(sidebar().getByRole('link', { name: 'Vulnerability Findings' })).toBeInTheDocument();
  });

  it('expands sidebar sections independently from navigation without nested buttons', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    const { container } = renderWithProviders(<><App /><LocationProbe /></>, { route: '/exposure' });
    const toggle = await screen.findByRole('button', { name: 'Expand Fix Intelligence sections' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    for (const disclosure of sidebar().getAllByRole('button', { name: /^Expand .* sections$/ })) {
      expect(disclosure).toHaveAttribute('aria-expanded', 'false');
      expect(document.getElementById(disclosure.getAttribute('aria-controls') ?? '')).not.toBeVisible();
    }
    expect(toggle.parentElement).toBe(sidebar().getByRole('link', { name: 'Fix Intelligence' }).parentElement);
    expect(container.querySelector('button button, button a, a a, a button, a [role="button"]')).toBeNull();
    // Group headings label their group and are not controls.
    expect(container.querySelectorAll('.nav-group-heading button, button.nav-group-heading, a.nav-group-heading')).toHaveLength(0);
    fireEvent.click(toggle);
    expect(screen.getByTestId('location')).toHaveTextContent(/^\/exposure$/);
    expect(screen.getByRole('button', { name: 'Collapse Fix Intelligence sections' })).toHaveAttribute('aria-expanded', 'true');
    expect(document.getElementById(toggle.getAttribute('aria-controls') ?? '')).toBeVisible();
    expect(sidebar().getByRole('link', { name: 'Patches' })).toHaveAttribute('href', '/fix-intelligence/patches');
    fireEvent.click(toggle);
    expect(sidebar().queryByRole('link', { name: 'Patches' })).not.toBeInTheDocument();
    fireEvent.click(sidebar().getByRole('link', { name: 'Vulnerability Findings' }));
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(/^\/findings$/));
  });

  it.each([
    ['/fix-intelligence', '/fix-intelligence/all'],
    [pathForFixIntelligenceView('patches'), '/fix-intelligence/patches'],
    ['/fix-intelligence/details/fix-1', '/fix-intelligence/details/fix-1'],
  ])('opens Fix Intelligence routes: %s', async (route, expected) => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const fixtures = await import('./features/fix-intelligence/fixtures');
    const { fixIntelligenceApi } = await import('./features/fix-intelligence/api');
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(fixtures.summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(fixtures.page([fixtures.listItem()]));
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(fixtures.detail({ title: 'Disable SMBv1' }));
    const { default: App } = await import('./App');
    renderWithProviders(<><App /><LocationProbe /></>, { route });
    await waitFor(() => expect(screen.getByTestId('location')).toHaveTextContent(new RegExp(`^${expected}$`)));
    expect(await screen.findByRole('link', { name: 'Fix Intelligence' }, { timeout: 5000 })).toHaveAttribute('aria-current', 'page');
  });
  it('groups AI destinations under Remediation and Assets and keeps Policies standalone when entitled', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue({ ...TENANT_ADMIN, entitlements: { 'ai.security': true } });
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    await screen.findByRole('navigation', { name: 'Primary' });
    expect(within(sidebar().getByRole('group', { name: 'Remediation' })).getAllByRole('link').map((link) => link.textContent))
      .toEqual(['Vulnerability Findings', 'AI Findings', 'Campaigns']);
    expect(within(sidebar().getByRole('group', { name: 'Assets' })).getAllByRole('link', { name: /Inventory$/ }).map((link) => link.textContent))
      .toEqual(['Inventory', 'AI Inventory']);
    const policies = sidebar().getByRole('link', { name: 'Policies' });
    expect(policies.closest('[role="group"]')).toBeNull();
    expect(sidebar().getByRole('link', { name: 'Exposure' })).toHaveAttribute('aria-current', 'page');
  });

  it('shows read-only auditors the workflow destinations, including Fix Intelligence, without tenant utilities', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue({ ...TENANT_ADMIN, roles: ['READ_ONLY_AUDITOR'] });
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    await screen.findByRole('navigation', { name: 'Primary' });
    for (const name of ['Exposure', 'Vulnerability Findings', 'Campaigns', 'Fix Intelligence', 'Vulnerability Repository', 'Inventory']) {
      expect(sidebar().getByRole('link', { name })).toBeInTheDocument();
    }
    for (const name of ['Connectors', 'Configurations', 'Administration', 'AI Findings', 'Policies']) {
      expect(sidebar().queryByRole('link', { name })).not.toBeInTheDocument();
    }
  });

  it('omits empty groups for actors who only see Exposure', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue({ ...TENANT_ADMIN, roles: [] });
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    await screen.findByRole('navigation', { name: 'Primary' });
    expect(sidebar().getAllByRole('link').map((link) => link.textContent)).toEqual(['Exposure']);
    expect(sidebar().queryAllByRole('group')).toHaveLength(0);
  });

  it('highlights Campaigns, not Vulnerability Repository, on a campaign record', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/vuln-repo/campaigns/campaign-1' });
    await screen.findByRole('navigation', { name: 'Primary' });
    expect(sidebar().getByRole('link', { name: 'Campaigns' })).toHaveAttribute('aria-current', 'page');
    expect(sidebar().getByRole('link', { name: 'Vulnerability Repository' })).not.toHaveAttribute('aria-current');
    expect(screen.getAllByRole('heading', { level: 1 }).map((heading) => heading.textContent)).toEqual(['Campaigns']);
  });

  it('renders one shell-owned H1 with the workbench record title under Vulnerability Repository', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/vuln-repo/org-cves/CVE-2024-0001' });
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2024-0001' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(sidebar().getByRole('link', { name: 'Vulnerability Repository' })).toHaveAttribute('aria-current', 'page');
  });

  it('opens the navigation drawer with focus inside and closes it with Escape, returning focus', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(TENANT_ADMIN);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    const toggle = await screen.findByRole('button', { name: 'Menu' });
    expect(toggle).toHaveAttribute('aria-controls', 'app-sidebar');
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(toggle);
    const drawer = document.getElementById('app-sidebar') as HTMLElement;
    expect(drawer).toHaveClass('open');
    expect(screen.getByRole('button', { name: 'Close Menu' })).toHaveAttribute('aria-expanded', 'true');
    expect(drawer).toContainElement(document.activeElement as HTMLElement);
    const focusable = [...drawer.querySelectorAll<HTMLElement>('a[href], button:not([disabled])')].filter((element) => !element.closest('[hidden]'));
    focusable[focusable.length - 1].focus();
    fireEvent.keyDown(drawer, { key: 'Tab' });
    expect(document.activeElement).toBe(focusable[0]);
    fireEvent.keyDown(drawer, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(focusable[focusable.length - 1]);
    fireEvent.keyDown(drawer, { key: 'Escape' });
    expect(drawer).not.toHaveClass('open');
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Menu' }));
  });

  it('operates the account menu by keyboard and closes it on Escape or an outside press', async () => {
    const auth = await import('./features/auth/api');
    vi.spyOn(auth.authApi, 'getActorContext').mockResolvedValue(PLATFORM_OWNER_TENANT_CONTEXT);
    const { default: App } = await import('./App');
    renderWithProviders(<App />, { route: '/exposure' });
    const trigger = await screen.findByRole('button', { name: 'Open settings menu' });
    expect(trigger).toHaveAttribute('aria-haspopup', 'menu');
    trigger.focus();
    fireEvent.click(trigger);
    const menu = screen.getByRole('menu', { name: 'Account' });
    const items = within(menu).getAllByRole('menuitem');
    expect(items.map((item) => item.textContent)).toEqual(['Authorized WorkspacesOpen only tenant-approved access', 'Log out']);
    expect(document.activeElement).toBe(items[0]);
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[0]);
    fireEvent.keyDown(menu, { key: 'End' });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(menu, { key: 'Home' });
    expect(document.activeElement).toBe(items[0]);
    fireEvent.keyDown(menu, { key: 'ArrowUp' });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(menu, { key: 'Escape' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    expect(document.activeElement).toBe(trigger);

    fireEvent.click(screen.getByRole('button', { name: /Open account menu/ }));
    expect(screen.getByRole('menu', { name: 'Account' })).toBeInTheDocument();
    fireEvent.mouseDown(screen.getByRole('heading', { level: 1 }));
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
    fireEvent.click(trigger);
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'Tab' });
    expect(screen.queryByRole('menu')).not.toBeInTheDocument();
  });
});
