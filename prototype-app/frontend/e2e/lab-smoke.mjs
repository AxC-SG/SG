#!/usr/bin/env node
// Lab release smoke (CD plan R4): signed-in WRITES, not just page loads. The c013bd7 pages loaded
// while every platform-scope write failed. release.py runs this after rollout; it is never run
// in CI, because it needs the lab's dedicated smoke accounts.
//
// Usage: node lab-smoke.mjs --config <json file outside the repo>
//   { "appOrigin": "https://scoutgrid.io", "apiOrigin": "https://api-lab.scoutgrid.io",
//     "platform": { "email": "...", "password": "..." },   (optional; see the lab README)
//     "tenant": { "email": "...", "password": "...", "tenantId": "<uuid>" },
//     "inviteAddress": "delivered+smoke@resend.dev" }
//
// Prints one JSON object { passed, checks: [{ name, ok, detail }] } and exits 0 only when every
// check passed. Public repository: it records no trace, screenshot, video, HAR or storage state,
// and never prints credentials, cookies or tokens (tests in .github/scripts/test-ci-contracts.py).
import { chromium } from '@playwright/test';
import { readFileSync } from 'node:fs';

const configPath = process.argv[process.argv.indexOf('--config') + 1];
if (!process.argv.includes('--config') || !configPath) {
  console.error('Usage: node lab-smoke.mjs --config <file>');
  process.exit(2);
}
const config = JSON.parse(readFileSync(configPath, 'utf8'));
const { appOrigin, apiOrigin } = config;
const WORKSPACE_HEADER = 'X-Scout-Workspace';
const INVITE_DELIVERY_TIMEOUT_MS = 90_000;
const checks = [];

function check(name, ok, detail = '') {
  checks.push({ name, ok: Boolean(ok), detail: String(detail).slice(0, 300) });
  return Boolean(ok);
}

async function step(name, body) {
  try {
    await body();
  } catch (error) {
    check(name, false, error?.message ?? error);
  }
}

// API responses the pages make; a 5xx or a managed-session 403 is a failure wherever it happens.
function watchApi(page) {
  const failures = [];
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (url.origin === apiOrigin && (response.status() >= 500 || response.status() === 403)) {
      failures.push(`${response.request().method()} ${url.pathname} ${response.status()}`);
    }
  });
  return failures;
}

async function signIn(browser, credentials) {
  const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block' });
  const page = await context.newPage();
  const apiFailures = watchApi(page);
  await page.goto(`${apiOrigin}/api/auth/managed/login`);
  // Cognito managed login (version 2). It may ask for the username and password on one page or two.
  const username = page.locator('input[name="username"], input[type="email"]').first();
  await username.waitFor({ timeout: 30_000 });
  await username.fill(credentials.email);
  const password = page.locator('input[type="password"]').first();
  if (!(await password.isVisible())) {
    await page.locator('button[type="submit"]').first().click();
    await password.waitFor({ timeout: 30_000 });
  }
  await password.fill(credentials.password);
  await page.locator('button[type="submit"]').first().click();
  await page.waitForURL((url) => url.origin === appOrigin, { timeout: 60_000 });
  return { context, page, apiFailures };
}

async function csrfHeaders(context) {
  const response = await context.request.get(`${apiOrigin}/api/auth/csrf`);
  const token = await response.json();
  return { [token.headerName]: token.token, Origin: appOrigin };
}

// Every write gets a fresh CSRF token, as the app's own client does (addManagedCsrf in src/api/client.ts):
// the CSRF cookie can rotate after an authenticated write, so a reused token is rejected with 403.
async function api(context, method, path, { headers = {}, data } = {}) {
  const csrf = ['GET', 'HEAD', 'OPTIONS'].includes(method) ? {} : await csrfHeaders(context);
  const response = await context.request.fetch(`${apiOrigin}${path}`, {
    method, headers: { Origin: appOrigin, ...headers, ...csrf }, data, failOnStatusCode: false,
  });
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status(), body };
}

async function pageLoads(session, name, path) {
  const before = session.apiFailures.length;
  await session.page.goto(`${appOrigin}${path}`);
  await session.page.waitForLoadState('networkidle', { timeout: 45_000 });
  const failures = session.apiFailures.slice(before);
  const onLogin = new URL(session.page.url()).pathname.startsWith('/login');
  check(name, failures.length === 0 && !onLogin, onLogin ? 'redirected to sign-in' : failures.join(', ') || 'ok');
}

async function signOut(session, name) {
  const logout = await api(session.context, 'POST', '/api/auth/managed/logout');
  const after = await api(session.context, 'GET', '/api/auth/context');
  check(name, logout.status === 204 && after.status === 401, `logout ${logout.status}, then context ${after.status}`);
}

async function platformChecks(browser) {
  const session = await signIn(browser, config.platform);
  try {
    const context = await api(session.context, 'GET', '/api/auth/context');
    check('platform owner signs in without a workspace', context.status === 200 && !context.body?.tenantId,
      `context ${context.status}`);
    for (const [name, path] of [
      ['Platform Audit loads', '/platform/platform-audit'],
      ['End-of-Life loads', '/end-of-life'],
      ['Vulnerability Repository dashboard loads', '/vuln-repo'],
      ['Vulnerability Intelligence feeds load', '/platform/vuln-intel'],
    ]) {
      await step(name, () => pageLoads(session, name, path));
    }
    // Platform-scope writes on disposable fixtures: the 2026-11-15 audit_events RLS failure.
    await step('platform write: reject a demo request', async () => {
      const fixture = await api(session.context, 'POST', '/api/platform/demo-requests/smoke-fixtures');
      if (!check('platform write: create a smoke fixture', fixture.status === 200, `status ${fixture.status}`)) return;
      const rejected = await api(session.context, 'POST', `/api/platform/demo-requests/${fixture.body.id}/reject`,
        { data: { reason: 'Release smoke' } });
      check('platform write: reject a demo request', rejected.status === 200 && rejected.body?.status === 'REJECTED',
        `status ${rejected.status} ${rejected.body?.status ?? ''}`);
    });
    await step('platform write: delete a demo request', async () => {
      const fixture = await api(session.context, 'POST', '/api/platform/demo-requests/smoke-fixtures');
      if (fixture.status !== 200) {
        check('platform write: delete a demo request', false, `fixture status ${fixture.status}`);
        return;
      }
      const removed = await api(session.context, 'DELETE', `/api/platform/demo-requests/${fixture.body.id}`);
      const queue = await api(session.context, 'GET', '/api/platform/demo-requests');
      const gone = Array.isArray(queue.body) && !queue.body.some((request) => request.id === fixture.body.id);
      check('platform write: delete a demo request', removed.status === 200 && gone, `status ${removed.status}, gone ${gone}`);
    });
    await step('platform owner signs out', () => signOut(session, 'platform owner signs out'));
  } finally {
    await session.context.close();
  }
}

async function tenantChecks(browser) {
  const { tenantId } = config.tenant;
  const session = await signIn(browser, config.tenant);
  const workspace = { [WORKSPACE_HEADER]: tenantId };
  try {
    const context = await api(session.context, 'GET', '/api/auth/context', { headers: workspace });
    check('tenant admin enters the workspace', context.status === 200 && context.body?.tenantId === tenantId,
      `context ${context.status}`);
    await step('Findings loads', () => pageLoads(session, 'Findings loads', '/findings'));
    // Tenant write that produces email: an invite is queued, the worker's outbox submits it (every 5 s), and
    // Resend must accept it (SENT). Then it is cancelled.
    await step('tenant write: invite is accepted by the email provider', async () => {
      const headers = workspace;
      const invitesPath = `/api/tenants/${tenantId}/invites`;
      const create = () => api(session.context, 'POST', invitesPath, {
        headers, data: { email: config.inviteAddress, displayName: 'Release smoke', role: 'READ_ONLY_AUDITOR' },
      });
      let invite = await create();
      if (invite.status === 409) {
        // A previous run stopped before cancelling its invite; cancel open smoke invites and retry once.
        const open = await api(session.context, 'GET', invitesPath, { headers });
        for (const stale of (open.body ?? []).filter((item) => item.email === config.inviteAddress.toLowerCase()
            && !['CANCELLED', 'ACCEPTED'].includes(item.status))) {
          await api(session.context, 'DELETE', `${invitesPath}/${stale.id}`, { headers });
        }
        invite = await create();
      }
      let status = invite.body?.status;
      let detail = invite.body?.deliveryDetail ?? '';
      const deadline = Date.now() + INVITE_DELIVERY_TIMEOUT_MS;
      while (invite.status === 200 && status === 'QUEUED' && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 5_000));
        const listed = await api(session.context, 'GET', invitesPath, { headers });
        const current = (listed.body ?? []).find((item) => item.id === invite.body.id);
        status = current?.status ?? status;
        detail = current?.deliveryDetail ?? detail;
      }
      check('tenant write: invite is accepted by the email provider', invite.status === 200 && status === 'SENT',
        `status ${invite.status} ${status ?? ''} ${detail}`);
      if (invite.body?.id) {
        const cancelled = await api(session.context, 'DELETE', `${invitesPath}/${invite.body.id}`, { headers });
        check('tenant write: cancel the smoke invite', cancelled.status === 200, `status ${cancelled.status}`);
      }
    });
    await step('tenant admin signs out', () => signOut(session, 'tenant admin signs out'));
  } finally {
    await session.context.close();
  }
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined });
try {
  if (config.platform) {
    await step('platform owner journey', () => platformChecks(browser));
  } else {
    // No second managed platform owner can be bound yet (infrastructure/lab/README.md#signed-in-smoke).
    check('platform owner journey', true, 'not configured: platform-scope writes unverified after deploy');
  }
  await step('tenant admin journey', () => tenantChecks(browser));
} finally {
  await browser.close();
}
const passed = checks.length > 0 && checks.every((item) => item.ok);
console.log(JSON.stringify({ passed, checks }, null, 2));
process.exit(passed ? 0 : 1);
