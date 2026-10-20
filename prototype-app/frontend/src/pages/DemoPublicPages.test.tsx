import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { authApi } from '../features/auth/api';
import { useActorQuery } from '../features/auth/queries';
import { createTestQueryClient, renderWithProviders } from '../test/test-utils';
import {
  BlogIndexPage,
  DemoInvitePage,
  DemoLandingPage,
  DemoRequestPage,
  LoginPage,
  SetupSessionPage,
  ZeroDayBlogPage
} from './DemoPublicPages';

function ExposureActorProbe() {
  const actorQuery = useActorQuery();
  return <div>{actorQuery.data?.principal ?? 'missing actor'}</div>;
}

describe('Demo public pages', () => {
  beforeEach(() => {
    window.turnstile = {
      render: (_container, options) => {
        options.callback('test-captcha-token');
        return 'test-widget';
      },
      reset: vi.fn(),
      remove: vi.fn()
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredAuthToken();
    delete window.turnstile;
  });

  it('renders the first-class ScoutGrid landing page at the index route', () => {
    renderWithProviders(
      <Routes>
        <Route path="/" element={<DemoLandingPage />} />
      </Routes>,
      { route: '/' }
    );

    expect(screen.getByRole('heading', { name: /The Exposure Management Platform Powered by AI Grid/i })).toBeInTheDocument();
    expect(screen.queryByTitle('ScoutGrid — exposure and BOM management')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Request Product Demo/i })).toHaveAttribute('href', '/demo/request');
    expect(document.getElementById('grids')).toBeInTheDocument();
    expect(document.getElementById('bom-grid')).toBeInTheDocument();
    expect(document.getElementById('ai-grid')).toBeInTheDocument();
  });

  it('uses application routes for public landing-page actions', () => {
    renderWithProviders(<DemoLandingPage />, { route: '/demo' });

    const navigation = within(screen.getByRole('navigation'));
    expect(navigation.getByRole('link', { name: 'Platform' })).toHaveAttribute('href', '/demo#grids');
    expect(navigation.getByRole('link', { name: 'Grids' })).toHaveAttribute('href', '/demo#ai-grid');
    expect(navigation.getByRole('link', { name: 'Blog' })).toHaveAttribute('href', '/demo/blog');
    expect(navigation.getByRole('link', { name: 'Request Demo' })).toHaveAttribute('href', '/demo/request');
    expect(navigation.queryByRole('link', { name: 'Four Grids' })).not.toBeInTheDocument();
    expect(navigation.queryByRole('link', { name: 'AI Grid' })).not.toBeInTheDocument();
    screen.getAllByRole('link', { name: 'Log in' }).forEach((link) => {
      expect(link).toHaveAttribute('href', '/login');
    });
    expect(screen.getByRole('link', { name: /Schedule a Live Demo/i })).toHaveAttribute('href', '/demo/request');
  });

  it('lists the first blog post and links to the article', () => {
    renderWithProviders(<BlogIndexPage />, { route: '/demo/blog' });

    expect(screen.getByRole('heading', { name: 'Blog' })).toBeInTheDocument();
    expect(screen.getByText('July 19, 2026')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Zero-day response: from disclosure/i }))
      .toHaveAttribute('href', '/demo/blog/zero-day-response-hours-not-weeks');
  });

  it('publishes the zero-day article using ScoutGrid branding', () => {
    renderWithProviders(<ZeroDayBlogPage />, { route: '/demo/blog/zero-day-response-hours-not-weeks' });

    expect(screen.getByRole('heading', { name: /Zero-day response: from disclosure/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'How ScoutGrid closes the gap' })).toBeInTheDocument();
    expect(screen.getByText(/ScoutGrid tells you what it means for you/i)).toBeInTheDocument();
    expect(screen.queryByText(/^Scout$/)).not.toBeInTheDocument();
  });

  it('submits a demo request with customer details', async () => {
    const createDemoRequest = vi.spyOn(api, 'createDemoRequest').mockResolvedValue({
      id: 'request-1',
      email: 'alex@example.com',
      fullName: 'Alex Rivera',
      company: 'Example Co',
      roleTitle: 'Security Lead',
      companySize: '101-1000',
      useCase: 'SBOM validation',
      notes: '',
      status: 'PENDING',
      requestedAt: new Date().toISOString(),
      decidedAt: null,
      decidedBy: null,
      rejectionReason: null,
      bootstrapStatus: null,
      tenantId: null,
      provisionedPlanCode: 'ENTERPRISE',
      latestInvite: null
    });

    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    expect(screen.getByRole('heading', { name: 'Request for product demo' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Already have access\? Log in/i })).toHaveAttribute('href', '/login');

    fireEvent.change(screen.getByLabelText(/Full name/i), { target: { value: 'Alex Rivera' } });
    fireEvent.change(screen.getByLabelText(/Work email/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Company$/i), { target: { value: 'Example Co' } });
    fireEvent.change(screen.getByLabelText(/Role/i), { target: { value: 'Security Lead' } });
    fireEvent.change(screen.getByLabelText(/Company size/i), { target: { value: '101-1000' } });
    expect(screen.queryByLabelText(/Primary use case/i)).not.toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/I understand/i));
    fireEvent.click(screen.getByRole('button', { name: /Submit request/i }));

    await waitFor(() => {
      expect(createDemoRequest).toHaveBeenCalledWith(expect.objectContaining({
        fullName: 'Alex Rivera',
        email: 'alex@example.com',
        company: 'Example Co',
        acceptedTerms: true,
        captchaToken: 'test-captcha-token'
      }), expect.anything());
    });
    expect(createDemoRequest.mock.calls[0]?.[0]).not.toHaveProperty('useCase');
  });

  it('rejects free email providers before submitting a demo request', async () => {
    const createDemoRequest = vi.spyOn(api, 'createDemoRequest');
    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    fireEvent.change(screen.getByLabelText(/Full name/i), { target: { value: 'Alex Rivera' } });
    fireEvent.change(screen.getByLabelText(/Work email/i), { target: { value: 'alex@gmail.com' } });
    fireEvent.change(screen.getByLabelText(/^Company$/i), { target: { value: 'Example Co' } });
    fireEvent.click(screen.getByLabelText(/I understand/i));
    fireEvent.click(screen.getByRole('button', { name: /Submit request/i }));

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Enter a valid corporate email address.');
    expect(alert).not.toHaveTextContent(/free email providers/i);
    expect(createDemoRequest).not.toHaveBeenCalled();
  });

  it('renders invite validation details', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'VALID',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite is ready'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite" element={<DemoInvitePage />} />
      </Routes>,
      { route: '/invite#token=demo-token' }
    );

    expect(await screen.findByText('Example Co')).toBeInTheDocument();
    expect(screen.getByText('alex@example.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Activate your workspace/i })).toBeEnabled();
    expect(screen.queryByRole('link', { name: /Continue to login/i })).not.toBeInTheDocument();
  });

  it('renders delivery failure invites as manual setup fallback', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'DELIVERY_ERROR',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Email delivery failed, but this invite link is still valid. Continue here to set the tenant password manually.'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite" element={<DemoInvitePage />} />
      </Routes>,
      { route: '/invite#token=demo-token' }
    );

    expect(await screen.findByText(/Email delivery failed/i)).toBeInTheDocument();
    expect(screen.getByText(/could not deliver the email automatically/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Activate your workspace/i })).toBeEnabled();
  });

  it('routes tenant admins to configurations after credential login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    const actor = {
      creator: false,
      principal: 'alex@example.com',
      userId: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      planCode: 'ENTERPRISE',
      demo: true,
      roles: ['TENANT_ADMIN'],
      platformScope: false
    };
    const getAuthContextSpy = vi.spyOn(api, 'getAuthContext').mockResolvedValue(actor);
    const getActorContextSpy = vi.spyOn(authApi, 'getActorContext').mockResolvedValue(actor);
    const queryClient = createTestQueryClient();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<ExposureActorProbe />} />
        <Route path="/platform/tenants" element={<div>Platform Tenants</div>} />
      </Routes>,
      { queryClient, route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('alex@example.com');
    expect(api.login).toHaveBeenCalledWith('alex@example.com', 'password-123');
    expect(getAuthContextSpy).toHaveBeenCalledTimes(1);
    expect(getActorContextSpy).not.toHaveBeenCalled();
  });

  it('routes demo analysts to exposure instead of connectors', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({ token: 'analyst-token', tokenType: 'Bearer', expiresAt: '2026-12-01T00:00:00Z' });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({ creator: false, principal: 'analyst@example.test', userId: 'analyst', tenantId: 'tenant-1', tenantName: 'Demo', demo: true, roles: ['SECURITY_ANALYST'] });
    renderWithProviders(<Routes><Route path="/login" element={<LoginPage />} /><Route path="/exposure" element={<div>Analyst exposure</div>} /></Routes>, { route: '/login' });
    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'analyst@example.test' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));
    expect(await screen.findByText('Analyst exposure')).toBeInTheDocument();
  });

  it('routes platform owners to platform tenants after credential login', async () => {
    vi.spyOn(api, 'login').mockResolvedValue({
      token: 'platform-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      creator: true,
      principal: 'owner@example.com',
      userId: 'owner@example.com',
      tenantId: null,
      tenantName: null,
      roles: ['PLATFORM_OWNER'],
      platformScope: true
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/exposure" element={<div>Exposure Home</div>} />
        <Route path="/platform/tenants" element={<div>Platform Tenants</div>} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'owner@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Platform Tenants');
    expect(api.login).toHaveBeenCalledWith('owner@example.com', 'password-123');
  });

  it('sends invite activation flows to password setup login', async () => {
    vi.spyOn(api, 'validateDemoInvite').mockResolvedValue({
      valid: true,
      status: 'VALID',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite is ready'
    });
    vi.spyOn(api, 'acceptDemoInvite').mockResolvedValue({
      valid: true,
      status: 'ACCEPTED',
      email: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      demoExpiresAt: '2026-05-09T00:00:00Z',
      inviteExpiresAt: '2026-05-09T00:00:00Z',
      loginUrl: '/login',
      message: 'Invite accepted'
    });

    renderWithProviders(
      <Routes>
        <Route path="/invite" element={<DemoInvitePage />} />
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/invite#token=demo-token' }
    );

    fireEvent.click(await screen.findByRole('button', { name: /Activate your workspace/i }));

    expect(await screen.findByText(/Set a password for your tenant workspace/i)).toBeInTheDocument();
  });

  it('completes password setup and returns to login with a success message', async () => {
    vi.spyOn(api, 'setupPassword').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/login?setup=1&email=alex%40example.com' }
    );

    fireEvent.change(screen.getByLabelText(/New password/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Set password/i }));

    expect(await screen.findByText(/Password created successfully/i)).toBeInTheDocument();
    expect(screen.getByDisplayValue('alex@example.com')).toBeInTheDocument();
    expect(api.setupPassword).toHaveBeenCalledWith('password-123');
  });

  it('exchanges a setup link before rendering the password form', async () => {
    const exchangeSpy = vi.spyOn(api, 'startPasswordSetupSession').mockResolvedValue(undefined);

    renderWithProviders(
      <Routes>
        <Route path="/setup" element={<SetupSessionPage />} />
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/setup#token=one-time-secret&email=alex%40example.com' }
    );

    expect(await screen.findByText(/Set a password for your tenant workspace/i)).toBeInTheDocument();
    expect(screen.getByText(/Account: alex@example.com/i)).toBeInTheDocument();
    expect(exchangeSpy).toHaveBeenCalledWith('one-time-secret');
    expect(window.location.href).not.toContain('one-time-secret');
  });

  it('allows tenant login with the request email and new password after activation reset', async () => {
    vi.spyOn(api, 'setupPassword').mockResolvedValue({
      token: 'tenant-token',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      creator: false,
      principal: 'alex@example.com',
      userId: 'alex@example.com',
      tenantId: 'tenant-1',
      tenantName: 'Example Co',
      planCode: 'ENTERPRISE',
      demo: true,
      roles: ['TENANT_ADMIN'],
      platformScope: false
    });
    const loginSpy = vi.spyOn(api, 'login').mockResolvedValue({
      token: 'tenant-token-2',
      tokenType: 'Bearer',
      expiresAt: '2026-05-09T00:00:00Z'
    });

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<div>Configurations</div>} />
      </Routes>,
      { route: '/login?setup=1&email=alex%40example.com' }
    );

    fireEvent.change(screen.getByLabelText(/New password/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Set password/i }));
    await screen.findByText(/Password created successfully/i);

    clearStoredAuthToken();
    cleanup();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/configurations" element={<div>Configurations</div>} />
      </Routes>,
      { route: '/login' }
    );

    expect(screen.queryByRole('link', { name: /Need access\? Request a demo/i })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Configurations');
    expect(loginSpy).toHaveBeenCalledWith('alex@example.com', 'password-123');
  });

  it('lets users clear a saved session from the login shell', async () => {
    setStoredAuthToken('saved-token');

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
      </Routes>,
      { route: '/login' }
    );

    fireEvent.click(screen.getByRole('button', { name: /Log out/i }));

    await waitFor(() => {
      expect(getStoredAuthToken()).toBe('');
    });
    expect(screen.getByRole('heading', { name: /Log in to ScoutGrid/i })).toBeInTheDocument();
  });

  it('toggles password visibility on the login form', () => {
    renderWithProviders(<LoginPage />, { route: '/login' });

    const password = screen.getByLabelText(/^Password$/i);
    expect(password).toHaveAttribute('type', 'password');
    fireEvent.click(screen.getByRole('button', { name: /Show password/i }));
    expect(password).toHaveAttribute('type', 'text');
    fireEvent.click(screen.getByRole('button', { name: /Hide password/i }));
    expect(password).toHaveAttribute('type', 'password');
  });
});
