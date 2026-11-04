import { act, cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { authApi } from '../features/auth/api';
import { useActorQuery } from '../features/auth/queries';
import { createTestQueryClient, renderWithProviders } from '../test/test-utils';
import {
  AnnouncementsIndexPage,
  BlogIndexPage,
  DemoInvitePage,
  DemoLandingPage,
  DemoRequestPage,
  CookiePolicyPage,
  LoginPage,
  NvidiaInceptionAnnouncementPage,
  PrivacyPolicyPage,
  SetupSessionPage,
  TermsOfServicePage,
  TenantInvitePage,
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

  it('renders the Scoutgrid landing page from the mock at the index route', () => {
    renderWithProviders(
      <Routes>
        <Route path="/" element={<DemoLandingPage />} />
      </Routes>,
      { route: '/' }
    );

    expect(screen.getByRole('heading', { level: 1, name: /Secure AI\.\s*See the whole exposure\./i })).toBeInTheDocument();
    for (const heading of [
      /AI doesn.t exist in isolation/i,
      /Four Grids\.\s*A wider view of risk\./i,
      /Move AI forward/i,
      /Better context\.\s*Sharper decisions\./i,
      /Make the next move count\./i,
      /The value is in the connections\./i,
      /Different perspectives\.\s*One direction\./i,
      /See your exposure in a different light\./i
    ]) {
      expect(screen.getByRole('heading', { level: 2, name: heading })).toBeInTheDocument();
    }
    for (const grid of ['AI Grid', 'Infra Grid', 'BOM Grid', 'Cloud Grid']) {
      expect(screen.getByRole('heading', { level: 3, name: grid })).toBeInTheDocument();
    }
    for (const id of ['platform', 'products', 'ai-grid', 'solutions', 'act']) {
      expect(document.getElementById(id)).toBeInTheDocument();
    }
    expect(screen.getByText(/Explore Scoutgrid in a private demo/i)).toBeInTheDocument();
  });

  it('sends every demo and request action on the landing page to the request form', () => {
    renderWithProviders(<DemoLandingPage />, { route: '/demo' });

    const main = within(screen.getByRole('main'));
    const demoLinks = [
      ...main.getAllByRole('link', { name: /Request a demo/i }),
      ...main.getAllByRole('link', { name: /Explore .*in a demo/i }),
      main.getByRole('link', { name: /Request an AI Grid demo/i }),
      main.getByRole('link', { name: /Find your starting point/i })
    ];
    expect(demoLinks).toHaveLength(8);
    demoLinks.forEach((link) => expect(link).toHaveAttribute('href', '/demo/contact'));
    expect(main.getByRole('link', { name: /Explore AI Grid in a demo/i })).toBeInTheDocument();
    expect(main.getByRole('link', { name: /Meet the four Grids/i })).toHaveAttribute('href', '/demo#products');
  });

  it('shows the new top bar without the AI security link', () => {
    renderWithProviders(<DemoLandingPage />, { route: '/demo' });

    const banner = within(screen.getByRole('banner'));
    expect(banner.getByRole('link', { name: 'Scoutgrid home' })).toHaveAttribute('href', '/demo');
    const navigation = within(screen.getByRole('navigation', { name: 'Scoutgrid site' }));
    expect(navigation.getByRole('link', { name: 'Platform' })).toHaveAttribute('href', '/demo#platform');
    expect(navigation.getByRole('link', { name: 'Products' })).toHaveAttribute('href', '/demo#products');
    expect(navigation.getByRole('link', { name: 'Solutions' })).toHaveAttribute('href', '/demo#solutions');
    expect(navigation.queryByRole('link', { name: 'Blog' })).not.toBeInTheDocument();
    const resources = navigation.getByRole('button', { name: 'Resources' });
    expect(resources).toHaveAttribute('aria-expanded', 'false');
    fireEvent.click(resources);
    expect(resources).toHaveAttribute('aria-expanded', 'true');
    expect(navigation.getByRole('link', { name: 'Blog' })).toHaveAttribute('href', '/demo/blog');
    expect(navigation.getByRole('link', { name: 'Announcements' })).toHaveAttribute('href', '/demo/announcements');
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(resources).toHaveAttribute('aria-expanded', 'false');
    expect(resources).toHaveFocus();
    expect(navigation.queryByRole('link', { name: 'Announcements' })).not.toBeInTheDocument();
    expect(banner.getByRole('link', { name: 'Log in' })).toHaveAttribute('href', '/login');
    expect(banner.getByRole('link', { name: 'Request a demo' })).toHaveAttribute('href', '/demo/contact');
    expect(screen.queryByRole('link', { name: /^AI security$/i })).not.toBeInTheDocument();
  });

  it('links the footer to products, blog, log in, request a demo, privacy and terms', () => {
    renderWithProviders(<DemoLandingPage />, { route: '/demo' });

    const footer = within(screen.getByRole('contentinfo'));
    expect(footer.getByRole('link', { name: 'AI Grid' })).toHaveAttribute('href', '/demo#ai-grid');
    expect(footer.getByRole('link', { name: 'Platform' })).toHaveAttribute('href', '/demo#platform');
    expect(footer.getByRole('link', { name: 'Blog' })).toHaveAttribute('href', '/demo/blog');
    expect(footer.getByRole('link', { name: 'Request a demo' })).toHaveAttribute('href', '/demo/contact');
    expect(footer.getByRole('link', { name: 'Log in' })).toHaveAttribute('href', '/login');
    expect(footer.getByRole('link', { name: 'Privacy' })).toHaveAttribute('href', '/demo/privacy');
    expect(footer.getByRole('link', { name: 'Terms' })).toHaveAttribute('href', '/demo/terms');
    expect(footer.getByRole('link', { name: 'Cookies' })).toHaveAttribute('href', '/demo/cookies');
    expect(footer.getByText('© 2026 Axoncyber Private Limited. All rights reserved. Scoutgrid is a product of Axoncyber Private Limited.')).toBeInTheDocument();
    expect(footer.queryByRole('link', { name: /^AI security$/i })).not.toBeInTheDocument();
    expect(footer.getByRole('link', { name: 'Announcements' })).toHaveAttribute('href', '/demo/announcements');
    expect(footer.getByRole('link', { name: 'Partners' })).toHaveAttribute('href', '/demo/partners');
    expect(footer.getByRole('link', { name: 'Contact' })).toHaveAttribute('href', '/demo/contact');
    expect(footer.getAllByRole('listitem')).toHaveLength(17);
  });

  it('navigates from the landing page to the blog and the legal pages', () => {
    renderWithProviders(
      <Routes>
        <Route path="/demo" element={<DemoLandingPage />} />
        <Route path="/demo/blog" element={<BlogIndexPage />} />
        <Route path="/demo/privacy" element={<PrivacyPolicyPage />} />
        <Route path="/demo/terms" element={<TermsOfServicePage />} />
      </Routes>,
      { route: '/demo' }
    );

    const siteNav = within(screen.getByRole('navigation', { name: 'Scoutgrid site' }));
    fireEvent.click(siteNav.getByRole('button', { name: 'Resources' }));
    fireEvent.click(siteNav.getByRole('link', { name: 'Blog' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Blog' })).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: 'Privacy' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Privacy Policy' })).toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('contentinfo')).getByRole('link', { name: 'Terms' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Terms of Service' })).toBeInTheDocument();
  });

  it('lists the NVIDIA Inception announcement and opens it from the Resources menu', () => {
    renderWithProviders(
      <Routes>
        <Route path="/demo" element={<DemoLandingPage />} />
        <Route path="/demo/announcements" element={<AnnouncementsIndexPage />} />
        <Route path="/demo/announcements/scoutgrid-joins-nvidia-inception" element={<NvidiaInceptionAnnouncementPage />} />
      </Routes>,
      { route: '/demo' }
    );

    const siteNav = within(screen.getByRole('navigation', { name: 'Scoutgrid site' }));
    fireEvent.click(siteNav.getByRole('button', { name: 'Resources' }));
    fireEvent.click(siteNav.getByRole('link', { name: 'Announcements' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Announcements' })).toBeInTheDocument();
    expect(siteNav.queryByRole('link', { name: 'Announcements' })).not.toBeInTheDocument();
    expect(screen.getByRole('img', { name: 'NVIDIA Inception Program and Scoutgrid' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('link', { name: 'Scoutgrid joins the NVIDIA Inception program' }));
    expect(screen.getByRole('heading', { level: 1, name: 'Scoutgrid joins the NVIDIA Inception program' })).toBeInTheDocument();
    for (const heading of ['Securing AI in context', 'What Inception brings', 'What\u2019s next']) {
      expect(screen.getByRole('heading', { level: 2, name: heading })).toBeInTheDocument();
    }
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Request a demo' })).toHaveAttribute('href', '/demo/contact');
  });

  it('places the NVIDIA Inception logo on the left and Scoutgrid on the right in the co-brand lockup', () => {
    const { container } = renderWithProviders(<NvidiaInceptionAnnouncementPage />, { route: '/demo/announcements/scoutgrid-joins-nvidia-inception' });

    const lockup = container.querySelector('.sgw-cobrand');
    expect(Array.from(lockup?.children ?? []).map((child) => child.className)).toEqual([
      'sgw-cobrand-nvidia', 'sgw-cobrand-partner'
    ]);
    expect(lockup?.querySelector('img')).toHaveAttribute('src', '/brand/nvidia-inception-program-logo.png');
  });

  it('renders the privacy policy with every required section', () => {
    renderWithProviders(<PrivacyPolicyPage />, { route: '/demo/privacy' });

    expect(screen.getByRole('heading', { level: 1, name: 'Privacy Policy' })).toBeInTheDocument();
    expect(screen.getByText('Last updated: 3 November 2026')).toBeInTheDocument();
    for (const section of [
      'Scope and our role', 'Information we collect', 'Where it comes from', 'How we use it, and our legal basis',
      'Sharing and processors', 'Retention', 'Security', 'Your rights and how to contact us', 'Regional information',
      'International transfers', 'Children', 'Links to other sites', 'Changes to this policy', 'Effective date'
    ]) {
      expect(screen.getByRole('heading', { level: 2, name: new RegExp(`^\\d+\\. ${section}$`) })).toBeInTheDocument();
    }
    expect(screen.getByText(/Demo-request details\./)).toBeInTheDocument();
    expect(screen.getByText(/Digital Personal Data Protection Act, 2023/)).toBeInTheDocument();
    expect(screen.getAllByRole('link', { name: 'support@scoutgrid.io' })[0]).toHaveAttribute('href', 'mailto:support@scoutgrid.io');
    expect(screen.getAllByText(/Axoncyber Private Limited, Hyderabad, India/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/\[[^\]]*(legal name|address|email|governing)[^\]]*\]/i)).not.toBeInTheDocument();
    const main = within(screen.getByRole('main'));
    expect(main.getByRole('link', { name: 'Terms of Service' })).toHaveAttribute('href', '/demo/terms');
    expect(main.getAllByRole('link', { name: 'Cookie Policy' })[0]).toHaveAttribute('href', '/demo/cookies');
  });

  it('renders the terms of service with every required section', () => {
    renderWithProviders(<TermsOfServicePage />, { route: '/demo/terms' });

    expect(screen.getByRole('heading', { level: 1, name: 'Terms of Service' })).toBeInTheDocument();
    expect(screen.getByText('Last updated: 3 November 2026')).toBeInTheDocument();
    for (const section of [
      'Acceptance', 'The service and demo access', 'Accounts and acceptable use', 'Customer data and confidentiality',
      'Intellectual property', 'Third-party services', 'Disclaimers and limitation of liability', 'Termination',
      'Governing law', 'Changes', 'Contact'
    ]) {
      expect(screen.getByRole('heading', { level: 2, name: new RegExp(`^\\d+\\. ${section}$`) })).toBeInTheDocument();
    }
    expect(screen.getByText(/governed by the laws of India/)).toBeInTheDocument();
    expect(screen.getByText(/courts at Hyderabad, Telangana, India/)).toBeInTheDocument();
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Privacy Policy' })).toHaveAttribute('href', '/demo/privacy');
  });

  it('renders the cookie policy with the storage Scoutgrid actually uses', () => {
    renderWithProviders(<CookiePolicyPage />, { route: '/demo/cookies' });

    expect(screen.getByRole('heading', { level: 1, name: 'Cookie Policy' })).toBeInTheDocument();
    expect(screen.getByText('Last updated: 3 November 2026')).toBeInTheDocument();
    const essential = within(screen.getByRole('table', { name: 'Strictly necessary cookies and storage' }));
    for (const name of ['Sign-in token', 'XSRF-TOKEN', 'scout_setup_session', 'Cloudflare Turnstile']) {
      expect(essential.getByRole('rowheader', { name })).toBeInTheDocument();
    }
    const preferences = within(screen.getByRole('table', { name: 'Preference storage' }));
    expect(preferences.getByRole('rowheader', { name: 'scoutai-theme' })).toBeInTheDocument();
    expect(screen.getByText(/do not show a cookie banner/i)).toBeInTheDocument();
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Privacy Policy' })).toHaveAttribute('href', '/demo/privacy');
  });

  it('gives the login page the new top bar without the site footer', () => {
    renderWithProviders(<LoginPage />, { route: '/login' });

    expect(within(screen.getByRole('banner')).getByRole('link', { name: 'Scoutgrid home' })).toHaveAttribute('href', '/demo');
    expect(screen.queryByRole('contentinfo')).not.toBeInTheDocument();
  });

  it('lists the first blog post and links to the article', () => {
    renderWithProviders(<BlogIndexPage />, { route: '/demo/blog' });

    expect(screen.getByRole('heading', { name: 'Blog' })).toBeInTheDocument();
    expect(screen.getByText('July 19, 2026')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Zero-day response: from disclosure/i }))
      .toHaveAttribute('href', '/demo/blog/zero-day-response-hours-not-weeks');
  });

  it('publishes the zero-day article using Scoutgrid branding', () => {
    renderWithProviders(<ZeroDayBlogPage />, { route: '/demo/blog/zero-day-response-hours-not-weeks' });

    expect(screen.getByRole('heading', { name: /Zero-day response: from disclosure/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'How Scoutgrid closes the gap' })).toBeInTheDocument();
    expect(screen.getByText(/Scoutgrid tells you what it means for you/i)).toBeInTheDocument();
    expect(screen.queryByText(/Scout[G]rid/)).not.toBeInTheDocument();
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

  it.each(['TENANT_ADMIN', 'INVENTORY_ADMIN', 'PLATFORM_OWNER'])('routes tenant %s to Exposure after credential login', async (role) => {
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
      roles: [role],
      platformScope: false
    };
    const getAuthContextSpy = vi.spyOn(api, 'getAuthContext').mockResolvedValue(actor);
    const getActorContextSpy = vi.spyOn(authApi, 'getActorContext').mockResolvedValue(actor);
    const queryClient = createTestQueryClient();

    renderWithProviders(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/exposure" element={<ExposureActorProbe />} />
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

    expect(await screen.findByText(/Set a password for your SG account/i)).toBeInTheDocument();
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

    expect(await screen.findByText(/Set a password for your SG account/i)).toBeInTheDocument();
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
        <Route path="/exposure" element={<div>Exposure Dashboard</div>} />
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
        <Route path="/exposure" element={<div>Exposure Dashboard</div>} />
      </Routes>,
      { route: '/login' }
    );

    expect(screen.queryByRole('link', { name: /Need access\? Request a demo/i })).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/^Email$/i), { target: { value: 'alex@example.com' } });
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'password-123' } });
    fireEvent.click(screen.getByRole('button', { name: /Sign in/i }));

    await screen.findByText('Exposure Dashboard');
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
    expect(screen.getByRole('heading', { name: /Log in to Scoutgrid/i })).toBeInTheDocument();
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

  it('gives the login fields credential semantics and states the supported recovery', () => {
    renderWithProviders(<LoginPage />, { route: '/login' });

    const email = screen.getByLabelText(/^Email$/i);
    expect(email).toHaveAttribute('type', 'email');
    expect(email).toHaveAttribute('autocomplete', 'username');
    expect(screen.getByLabelText(/^Password$/i)).toHaveAttribute('autocomplete', 'current-password');
    expect(screen.getByText(/no self-service password reset/i)).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /forgot|reset/i })).not.toBeInTheDocument();
  });

  it('states the server password minimum in setup mode and enforces it', () => {
    renderWithProviders(<LoginPage />, { route: '/login?setup=1&email=alex%40example.com' });

    const password = screen.getByLabelText(/New password/i);
    expect(password).toHaveAttribute('autocomplete', 'new-password');
    expect(password).toHaveAccessibleDescription('Use at least 12 characters.');
    fireEvent.change(password, { target: { value: 'elevenchars' } });
    expect(screen.getByRole('button', { name: /Set password/i })).toBeDisabled();
    fireEvent.change(password, { target: { value: 'twelve-chars' } });
    expect(screen.getByRole('button', { name: /Set password/i })).toBeEnabled();
  });

  it('offers log in after an invalid setup link', async () => {
    vi.spyOn(api, 'startPasswordSetupSession').mockRejectedValue(new Error('Password setup link is invalid or expired.'));

    renderWithProviders(
      <Routes>
        <Route path="/setup" element={<SetupSessionPage />} />
      </Routes>,
      { route: '/setup#token=used-token' }
    );

    expect(await screen.findByRole('alert')).toHaveTextContent('invalid or expired');
    expect(screen.getByRole('link', { name: 'Go to log in' })).toHaveAttribute('href', '/login');
  });

  it('announces unusable invite links with supported next steps', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/tenant-invite" element={<TenantInvitePage />} />
      </Routes>,
      { route: '/tenant-invite' }
    );
    expect(screen.getByRole('alert')).toHaveTextContent('This link has expired.');
    expect(screen.getByText(/Ask your workspace administrator to send a new invite/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to log in' })).toHaveAttribute('href', '/login');
    expect(within(screen.getByRole('main')).queryByRole('link', { name: 'Request a demo' })).not.toBeInTheDocument();
    cleanup();

    vi.spyOn(api, 'validateDemoInvite').mockRejectedValue(new Error('Invite has expired'));
    renderWithProviders(
      <Routes>
        <Route path="/invite" element={<DemoInvitePage />} />
      </Routes>,
      { route: '/invite#token=old-token' }
    );
    expect(await screen.findByRole('alert')).toHaveTextContent('Invite has expired');
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Request a demo' })).toHaveAttribute('href', '/demo/contact');
    expect(screen.getByRole('link', { name: 'Go to log in' })).toHaveAttribute('href', '/login');
  });

  it('explains the corporate email rule and ties the rejection to the field', async () => {
    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    const email = screen.getByLabelText(/Work email/i);
    expect(email).toHaveAccessibleDescription(/Personal email providers are not accepted/i);
    fireEvent.change(screen.getByLabelText(/Full name/i), { target: { value: 'Alex Rivera' } });
    fireEvent.change(email, { target: { value: 'alex@gmail.com' } });
    fireEvent.change(screen.getByLabelText(/^Company$/i), { target: { value: 'Example Co' } });
    fireEvent.click(screen.getByLabelText(/I understand/i));
    fireEvent.click(screen.getByRole('button', { name: /Submit request/i }));

    await screen.findByRole('alert');
    expect(email).toHaveAttribute('aria-invalid', 'true');
    expect(email).toHaveAccessibleDescription(/Enter a valid corporate email address/i);
    expect(email).toHaveValue('alex@gmail.com');
  });

  it('explains an expired CAPTCHA instead of silently disabling submit', async () => {
    let expire: (() => void) | undefined;
    window.turnstile = {
      render: (_container, options) => {
        options.callback('test-captcha-token');
        expire = options['expired-callback'];
        return 'test-widget';
      },
      reset: vi.fn(),
      remove: vi.fn()
    };
    renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });

    expect(screen.getByRole('button', { name: /Submit request/i })).toBeEnabled();
    act(() => expire?.());
    const submit = screen.getByRole('button', { name: /Submit request/i });
    expect(submit).toBeDisabled();
    expect(submit).toHaveAccessibleDescription(/verification expired/i);
  });

  it('marks only authentication entry pages for the UI 2.0 presentation root', () => {
    const { container, unmount } = renderWithProviders(<LoginPage />, { route: '/login' });
    expect(container.querySelector('main.public-demo-shell')).toHaveClass('ui2-experience-family');
    unmount();

    const request = renderWithProviders(<DemoRequestPage />, { route: '/demo/request' });
    expect(request.container.querySelector('main.public-demo-shell')).not.toHaveClass('ui2-experience-family');
  });
});
