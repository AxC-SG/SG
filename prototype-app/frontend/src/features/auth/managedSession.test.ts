import { afterEach, describe, expect, it, vi } from 'vitest';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

async function loadManagedModules() {
  vi.stubEnv('VITE_MANAGED_BROWSER_AUTH_ENABLED', 'true');
  vi.resetModules();
  return Promise.all([
    import('../../api/client'),
    import('./api'),
    import('./managedSession')
  ]);
}

describe('managed browser session', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('opens the only authorized workspace for a tenant administrator and uses it on writes', async () => {
    const [client, { authApi }, session] = await loadManagedModules();
    client.setStoredAuthToken('legacy-bearer');
    const actor = { userId: 'admin', roles: [], tenantId: null, allowedTenants: [{ id: 'workspace-1' }] };
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(actor))
      .mockResolvedValueOnce(json({ ...actor, roles: ['TENANT_ADMIN'], tenantId: 'workspace-1' }))
      .mockResolvedValueOnce(json({ headerName: 'X-XSRF-TOKEN', token: 'csrf' }))
      .mockResolvedValueOnce(json({}));

    await expect(authApi.getActorContext()).resolves.toMatchObject({ tenantId: 'workspace-1', roles: ['TENANT_ADMIN'] });
    expect(session.getManagedWorkspace()).toBe('workspace-1');
    const headers = (index: number) => new Headers(fetch.mock.calls[index][1]?.headers);
    expect(headers(0).has('X-Scout-Workspace')).toBe(false);
    expect(headers(1).get('X-Scout-Workspace')).toBe('workspace-1');

    await client.apiRequest('/findings', { method: 'POST' });
    expect(fetch.mock.calls[2][0]).toMatch(/\/auth\/csrf$/);
    expect(headers(3).get('X-Scout-Workspace')).toBe('workspace-1');
    expect(headers(3).get('X-XSRF-TOKEN')).toBe('csrf');
    expect(headers(3).has('Authorization')).toBe(false);
    expect(fetch.mock.calls[3][1]?.credentials).toBe('include');
  });

  it('returns a platform owner to platform scope if a stored grant is revoked', async () => {
    const [client, { authApi }, session] = await loadManagedModules();
    session.setManagedWorkspace('revoked');
    const fetch = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json({ error: 'Managed session or workspace was rejected' }, 403))
      .mockResolvedValueOnce(json({ tenantId: null, roles: ['PLATFORM_OWNER'], allowedTenants: [{ id: 'other' }] }))
      .mockResolvedValueOnce(json({ headerName: 'X-XSRF-TOKEN', token: 'csrf' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(authApi.getActorContext()).resolves.toMatchObject({ tenantId: null });
    expect(session.getManagedWorkspace()).toBeNull();
    expect(new Headers(fetch.mock.calls[0][1]?.headers).get('X-Scout-Workspace')).toBe('revoked');
    expect(new Headers(fetch.mock.calls[1][1]?.headers).has('X-Scout-Workspace')).toBe(false);
    await client.api.managedLogout();
    expect(fetch.mock.calls[3][0]).toMatch(/\/auth\/managed\/logout$/);
    expect(new Headers(fetch.mock.calls[3][1]?.headers).get('X-XSRF-TOKEN')).toBe('csrf');
  });
});
