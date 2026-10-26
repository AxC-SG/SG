import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, apiRequest, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from './client';

function buildToken(payload: Record<string, unknown>): string {
  const encode = (value: Record<string, unknown>) => btoa(JSON.stringify(value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

describe('api client auth headers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    clearStoredAuthToken();
  });

  it('excludes static authentication inputs in production while preserving stored browser authentication', async () => {
    vi.stubEnv('DEV', false);
    for (const name of ['VITE_API_KEY', 'VITE_CREATOR_KEY', 'VITE_AUTH_TOKEN', 'VITE_USER_ID', 'VITE_TENANT_ID']) {
      vi.stubEnv(name, 'static-auth-sentinel');
    }
    vi.resetModules();
    const productionClient = await import('./client');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response('{}', {
      status: 200, headers: { 'content-type': 'application/json' },
    })));
    await productionClient.apiRequest('/me');
    let headers = new Headers(fetchSpy.mock.calls[0][1]?.headers);
    expect(headers.has('Authorization')).toBe(false);
    for (const name of ['X-API-Key', 'X-Creator-Key', 'X-User-ID', 'X-Tenant-ID']) expect(headers.has(name)).toBe(false);
    productionClient.setStoredAuthToken('browser-session-sentinel');
    await productionClient.apiRequest('/me');
    headers = new Headers(fetchSpy.mock.calls[1][1]?.headers);
    expect(headers.get('Authorization')).toBe('Bearer browser-session-sentinel');
  });

  it('uses bearer auth for audit export when a session token is present', async () => {
    setStoredAuthToken('jwt-for-preprod');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('id,action\n', {
      status: 200,
      headers: {
        'content-type': 'text/csv',
        'content-disposition': 'attachment; filename="audit.csv"'
      }
    }));

    await api.exportAuditEventsCsv();

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get('Authorization')).toBe('Bearer jwt-for-preprod');
    expect(headers.has('X-API-Key')).toBe(false);
  });

  it('adds platform-owner confirmation headers for tenant-scoped sensitive writes', async () => {
    setStoredAuthToken(buildToken({
      sub: 'owner@example.com',
      roles: ['PLATFORM_OWNER'],
      active_tenant_id: 'tenant-123'
    }));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await apiRequest('/findings', {
      method: 'POST',
      body: JSON.stringify({ action: 'update' })
    });

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(window.confirm).toHaveBeenCalled();
    expect(headers.get('X-Platform-Action-Confirm')).toBe('true');
    expect(headers.get('X-Platform-Action-Tenant')).toBe('tenant-123');
    expect(headers.get('X-Platform-Action-Time')).toBeTruthy();
  });

  it('accepts namespaced roles claims for platform-owner confirmation headers', async () => {
    setStoredAuthToken(buildToken({
      sub: 'owner@example.com',
      'https://hossstore.in/roles': ['PLATFORM_OWNER'],
      active_tenant_id: 'tenant-456'
    }));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await apiRequest('/findings', {
      method: 'POST',
      body: JSON.stringify({ action: 'update' })
    });

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(window.confirm).toHaveBeenCalled();
    expect(headers.get('X-Platform-Action-Confirm')).toBe('true');
    expect(headers.get('X-Platform-Action-Tenant')).toBe('tenant-456');
  });

  it('preserves the session token for tenant-context authorization failures', async () => {
    setStoredAuthToken('tenant-context-session');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      code: 'FORBIDDEN',
      error: 'Tenant context is required'
    }), {
      status: 403,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await expect(apiRequest('/service-accounts')).rejects.toThrow('[FORBIDDEN] Tenant context is required');

    expect(getStoredAuthToken()).toBe('tenant-context-session');
  });

  it('clears the session token and redirects on invalid jwt failures', async () => {
    setStoredAuthToken('expired-session');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      code: 'UNAUTHORIZED',
      error: 'Invalid JWT token'
    }), {
      status: 401,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await expect(apiRequest('/me')).rejects.toThrow('[UNAUTHORIZED] Invalid JWT token');

    expect(getStoredAuthToken()).toBe('');
  });
});

describe('api method coverage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredAuthToken();
  });

  it('listFindings sends GET to /findings with query params', async () => {
    const payload = { items: [], page: 0, size: 25, totalItems: 0, totalPages: 0 };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.listFindings({ page: 0, size: 25, severity: ['CRITICAL'], status: ['OPEN'] });

    const [url] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/findings');
    expect(String(url)).toContain('severity=CRITICAL');
    expect(String(url)).toContain('status=OPEN');
  });

  it('rejects an invalid governed policy catalog response instead of treating it as an empty catalog', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<!doctype html><title>SPA fallback</title>', {
        status: 200,
        headers: { 'content-type': 'text/html' }
      })
    );

    await expect(api.listPlatformAiGridPolicies()).rejects.toThrow(
      'The governed policy catalog returned an invalid response.'
    );
  });

  it('getRiskPolicy sends GET to /risk-policy', async () => {
    const policy = { criticalSlaDays: 7, highSlaDays: 14 };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(policy), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.getRiskPolicy();

    const [url] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/risk-policy');
  });

  it('updateRiskPolicy sends POST to /risk-policy with policy body', async () => {
    const updated = { criticalSlaDays: 3, highSlaDays: 7 };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(updated), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.updateRiskPolicy({ criticalSlaDays: 3 });

    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/risk-policy');
    expect(init?.method).toBe('POST');
    expect(init?.body).toContain('"criticalSlaDays":3');
  });

  it('getRiskPolicy returns parsed JSON response', async () => {
    const policy = { criticalSlaDays: 7, highSlaDays: 14, mediumSlaDays: 30, lowSlaDays: 60 };
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(policy), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    const result = await api.getRiskPolicy();

    expect(result).toMatchObject({ criticalSlaDays: 7 });
  });

  it('listFindings without filters still sends request', async () => {
    const payload = { items: [], page: 0, size: 25, totalItems: 0, totalPages: 0 };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(payload), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.listFindings({});

    const [url] = fetchSpy.mock.calls[0];
    expect(String(url)).toContain('/findings');
  });

  it('injects X-API-Key header when no bearer token is present', async () => {
    clearStoredAuthToken();
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.getRiskPolicy();

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.has('X-API-Key')).toBe(true);
    expect(headers.has('Authorization')).toBe(false);
    expect(headers.get('X-Tenant-ID')).toBe('1');
    expect(headers.get('X-User-ID')).toBe('local-analyst');
  });

  it('injects Authorization bearer header when session token is present', async () => {
    setStoredAuthToken('test-session-token');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({}), { status: 200, headers: { 'content-type': 'application/json' } })
    );

    await api.getRiskPolicy();

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get('Authorization')).toBe('Bearer test-session-token');
    expect(headers.has('X-API-Key')).toBe(false);
  });

  it('does not clear the session for a plain 403 forbidden response', async () => {
    setStoredAuthToken('platform-owner-session');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ message: 'Forbidden' }), {
        status: 403,
        headers: { 'content-type': 'application/json' }
      })
    );

    await expect(api.getRiskPolicy()).rejects.toThrow('Forbidden');
    expect(getStoredAuthToken()).toBe('platform-owner-session');
  });

  it('clears the session for an expired bearer token response', async () => {
    window.history.replaceState({}, '', '/login');
    setStoredAuthToken('expired-session');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ message: 'Bearer token expired' }), {
        status: 403,
        headers: { 'content-type': 'application/json' }
      })
    );

    await expect(api.getRiskPolicy()).rejects.toThrow('Bearer token expired');
    expect(getStoredAuthToken()).toBe('');
  });
});
