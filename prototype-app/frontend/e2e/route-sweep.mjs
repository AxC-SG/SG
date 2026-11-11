#!/usr/bin/env node
// UI 2.0 P7 — consistency sweep over every active tenant and platform route (direct links from
// e2e/routes.mjs with fixture IDs) and every left-navigation destination.
//
// For each page it records the final URL, whether the rendered content sits under a UI 2.0
// presentation root (an orphan is legacy presentation on an active route), page errors and
// horizontal overflow at each width (default 1440px and 390px). Authenticated routes must have
// exactly one visible H1 and one main landmark, both owned by the shell (U03). Run against the UI 2.0 build;
// on the legacy build every route reports as orphan by design (no family roots are styled there).
// Fixture-backed only: this is NOT authenticated staging evidence.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node route-sweep.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--theme dark] [--widths 1440,390]
// Left-navigation clicks run at the widest width only.
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext, waitForPageReady } from './browser.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import { APPROVED_PLATFORM_POLICY_ID, PRIMARY_POLICY_ID, platformActor } from './governance-fixtures.mjs';
import { PRIMARY_CVE } from './cve-fixtures.mjs';
import { PRIMARY_AI_ASSET_ID, PRIMARY_DECLARED_RESOURCE_ID, PRIMARY_HOST_ID, PRIMARY_SOFTWARE_IDENTITY_ID } from './inventory-fixtures.mjs';
import { PRIMARY_CAMPAIGN_ID } from './experience-fixtures.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);

const base = args.base ?? 'http://127.0.0.1:5175';
const out = args.out ?? 'screenshots';
const label = args.label ?? 'sweep';
const theme = args.theme ?? 'dark';
const widths = (args.widths ?? '1440,390').split(',').map(Number);
const navWidth = Math.max(...widths);
mkdirSync(out, { recursive: true });

// Presentation roots of the UI 2.0 families (P2–P7). Auth entry pages carry theirs on the shell.
const FAMILY_ROOTS = [
  '[class*="ui2-"][class*="-family"]', '.fpl-root', '.fd3-page', '.cve-assessment-page',
  '.vuln-repo-vulnerabilities-shell', '.vuln-repo-assets-shell',
].join(', ');

const opsActor = { ...actor, roles: ['PLATFORM_OWNER', 'TENANT_ADMIN'], platformScope: false, actingAsPlatformOwner: true };

const tenantRoutes = [
  '/exposure', '/findings', '/findings/F-10420', '/findings/00000000-0000-4000-8000-000000000001', '/findings/ai', '/findings/ai/vulnerabilities', '/findings/ai/exposures',
  '/findings/ai/exposures/exposure-1', '/findings/ai/ai-finding-1', '/policies', `/policies/${PRIMARY_POLICY_ID}`,
  '/vuln-repo', '/vuln-repo/vulnerabilities', `/vuln-repo/intel/${PRIMARY_CVE}`, '/vuln-repo/org-cves', `/vuln-repo/org-cves/${PRIMARY_CVE}`,
  `/vuln-repo/org-cves/${PRIMARY_CVE}/assets`, `/vuln-repo/org-cves/${PRIMARY_CVE}/software`,
  '/vuln-repo/software-assets?softwareIdentityId=sw-1&software=log4j-core', `/vuln-repo/host-assets/${PRIMARY_HOST_ID}`,
  '/vuln-repo/campaigns', `/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`,
  '/inventory', '/inventory/overview', '/inventory/hosts', '/inventory/cloud-resources', `/inventory/hosts/${PRIMARY_HOST_ID}`, '/inventory/software-identities',
  `/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`, '/inventory/container-images', '/inventory/sbom',
  '/inventory/bom-components', '/inventory/bom-inventory', '/inventory/ai', '/inventory/ai/agents', '/inventory/ai/agent-versions',
  '/inventory/ai/assets', '/inventory/ai/knowledge-data', '/inventory/ai/mcp', '/inventory/ai/declared-resources',
  `/inventory/ai/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}`, `/inventory/ai/${PRIMARY_AI_ASSET_ID}`,
  '/connect', '/connect/run-history', '/connect?connectSource=servicenow-cmdb', '/connect/copilot-studio',
  '/admin/users', '/admin/invites', '/admin/roles', '/admin/service-accounts', '/admin/audit',
  '/configurations/sla', '/configurations/triage', '/configurations/automation', '/configurations/ownership',
  '/configurations/findings-score', '/configurations/suppress', '/configurations/auto-findings',
];
const opsRoutes = ['/operations/pipeline', '/operations/platform-health'];
const platformRoutes = [
  '/platform/tenants', '/platform/users', '/platform/platform-audit', '/platform/demo-requests', '/platform/operations',
  '/platform/vuln-intel', '/platform/eol', '/platform/ai-policies', `/platform/ai-policies/${APPROVED_PLATFORM_POLICY_ID}`,
  '/authorized-workspaces', '/vuln-repo', '/vuln-repo/vulnerabilities',
];
const publicRoutes = ['/login', '/tenant-invite#token=fixture-invite-token', '/invite#token=fixture-invite-token', '/setup'];

// Requests outside the served build: the Google Fonts import in base.css only (answered locally by browser.mjs).
const EXPECTED_EXTERNAL_HOSTS = new Set(['fonts.googleapis.com', 'fonts.gstatic.com']);

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const rows = [];

async function sweep(who, routes, { unauthenticated = false, navClicks = false } = {}) {
  for (const width of widths) {
    const context = await newContext(browser, { viewport: { width, height: 1000 } });
    await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
    await routeFixtures(context, { actorOverride: who });
    if (unauthenticated) await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
    const page = await context.newPage();
    let errors = [];
    let consoleErrors = [];
    let externalRequests = [];
    let missingFindingResponse = false;
    page.on('pageerror', (error) => errors.push(error.message));
    page.on('console', (message) => { if (message.type() === 'error') consoleErrors.push({ text: message.text(), url: message.location().url }); });
    page.on('response', (response) => {
      if (new URL(response.url()).pathname === '/api/findings/F-10420' && response.status() === 404) missingFindingResponse = true;
    });
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.origin !== new URL(base).origin && !EXPECTED_EXTERNAL_HOSTS.has(url.hostname)) externalRequests.push(`${request.method()} ${url.origin}${url.pathname}`);
    });
    const inspect = async (route, via) => {
      await waitForPageReady(page);
      await page.waitForTimeout(700);
      const state = await page.evaluate((roots) => {
        const content = document.querySelector('main.content') ?? document.body;
        const rendered = [...content.children].filter((child) => !child.matches('header.topbar'));
        return {
          ui: document.documentElement.dataset.ui ?? null,
          family: Boolean(document.querySelector('main.public-demo-shell')?.matches(roots)) || Boolean(content.querySelector(roots)),
          roots: [...new Set([...content.querySelectorAll(roots)].slice(0, 4).map((el) => [...el.classList].find((name) => /family|fpl-root|fd3-page|cve-assessment-page|-shell$/.test(name))))],
          overflow: document.documentElement.scrollWidth > window.innerWidth + 1,
          h1: [...document.querySelectorAll('h1')].filter((el) => el.getClientRects().length > 0).length,
          main: document.querySelectorAll('main, [role="main"]').length,
          text: rendered.map((child) => child.textContent ?? '').join(' ').trim().slice(0, 80),
        };
      }, FAMILY_ROOTS);
      // This bookmark deliberately exercises the documented unsupported display-ID state.
      // Accept only its exact 404 diagnostic, and only after the expected unavailable UI renders.
      const expectedMissing = route === '/findings/F-10420' && missingFindingResponse
        && await page.getByRole('heading', { name: 'Finding not found', exact: true }).isVisible()
        && await page.getByText('No finding matches F-10420.', { exact: false }).isVisible();
      if (route === '/findings/F-10420' && !expectedMissing) errors.push('Display-ID bookmark did not render its expected 404/unavailable state');
      const unexpectedConsoleErrors = consoleErrors.filter((entry) => !(expectedMissing
        && entry.url === `${base}/api/findings/F-10420`
        && entry.text === 'Failed to load resource: the server responded with a status of 404 (Not Found)')).map((entry) => entry.text);
      const url = new URL(page.url());
      rows.push({ actor: who.roles.join('+') + (unauthenticated ? ' (signed out)' : ''), authenticated: !unauthenticated, width, via, route, final: url.pathname + url.search, ...state, errors, consoleErrors: unexpectedConsoleErrors, expectedMissing, externalRequests });
      errors = [];
      consoleErrors = [];
      missingFindingResponse = false;
      externalRequests = [];
    };
    for (const route of routes) {
      await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
      await inspect(route.split('#')[0], 'direct');
    }
    if (navClicks && width === navWidth) {
      await page.goto(`${base}${routes[0]}`, { waitUntil: 'networkidle' });
      // Expand every collapsible nav group, then visit each destination it lists.
      const toggles = page.locator('aside.sidebar button[aria-expanded="false"]');
      for (let i = await toggles.count(); i > 0; i -= 1) await toggles.first().click();
      const labels = await page.locator('aside.sidebar button, aside.sidebar a').evaluateAll((items) => items
        .filter((item) => !item.hasAttribute('aria-expanded'))
        .map((item) => item.textContent.trim()).filter(Boolean));
      for (const text of [...new Set(labels)]) {
        await page.goto(`${base}${routes[0]}`, { waitUntil: 'networkidle' });
        const groups = page.locator('aside.sidebar button[aria-expanded="false"]');
        for (let i = await groups.count(); i > 0; i -= 1) await groups.first().click();
        const item = page.locator('aside.sidebar').locator('button, a').filter({ hasText: new RegExp(`^${text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }).first();
        if (!(await item.count())) continue;
        await item.click();
        await page.waitForLoadState('networkidle');
        await inspect(text, 'nav');
      }
    }
    await context.close();
  }
}

await sweep(actor, tenantRoutes, { navClicks: true });
await sweep(opsActor, opsRoutes, { navClicks: true });
await sweep(platformActor, platformRoutes, { navClicks: true });
await sweep(actor, publicRoutes, { unauthenticated: true });
await browser.close();

writeFileSync(path.join(out, `${label}_route_sweep.json`), JSON.stringify(rows, null, 2));
const orphans = rows.filter((row) => !row.family);
const overflowing = rows.filter((row) => row.overflow);
const erroring = rows.filter((row) => row.errors.length > 0);
const consoleErroring = rows.filter((row) => row.consoleErrors.length > 0);
const external = rows.filter((row) => row.externalRequests.length > 0);
const flagged = rows.filter((row) => row.ui !== '2');
const headerless = rows.filter((row) => row.authenticated && (row.h1 !== 1 || row.main !== 1));
console.log(`${label}: ${rows.length} page checks (${rows.filter((row) => row.via === 'nav').length} via navigation); `
  + `${orphans.length} orphan, ${overflowing.length} overflow, ${erroring.length} with page errors, ${consoleErroring.length} with console errors, `
  + `${external.length} with unexpected requests, ${flagged.length} without data-ui=2, ${headerless.length} without exactly one H1/main`);
for (const row of orphans) console.log(`ORPHAN ${row.actor} ${row.width} ${row.via} ${row.route} -> ${row.final} :: ${row.text}`);
for (const row of overflowing) console.log(`OVERFLOW ${row.actor} ${row.width} ${row.route} -> ${row.final}`);
for (const row of erroring) console.log(`ERROR ${row.actor} ${row.width} ${row.route} -> ${row.final} :: ${row.errors.join(' | ')}`);
for (const row of consoleErroring) console.log(`CONSOLE ${row.actor} ${row.width} ${row.route} -> ${row.final} :: ${row.consoleErrors.join(' | ')}`);
for (const row of headerless) console.log(`HEADER ${row.actor} ${row.width} ${row.via} ${row.route} -> ${row.final} :: ${row.h1} h1, ${row.main} main`);
for (const row of external) console.log(`REQUEST ${row.actor} ${row.width} ${row.route} -> ${row.final} :: ${row.externalRequests.join(' | ')}`);
// Orphans and overflow are reported for review; legacy builds report every route as orphan by design.
process.exitCode = erroring.length || consoleErroring.length || external.length || headerless.length ? 1 : 0;
failOnUnexpectedApi();
