#!/usr/bin/env node
// UI 2.0 P7 — remaining experience browser journey: exposure dashboard drill-downs, the CVE
// dashboard, campaigns list/detail and status transition, tenant and platform operations views,
// the public authentication entry points (login, password setup, demo and workspace invites),
// legacy redirects and the role-based home redirect, plus 390px overflow on every P7 route.
//
// Runs the same deterministic journey against any build (legacy or UI 2.0) so behaviour can be
// compared, records request URLs and bodies to verify serialisation, and saves screenshots.
// Fixture-backed only: this is NOT authenticated staging evidence, and no write is persisted.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node experience-journey.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext } from './browser.mjs';
import { unexpectedFailures } from './known-failures.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import { platformActor } from './governance-fixtures.mjs';
import {
  BLOCKED_CAMPAIGN_ID,
  CRITICAL_CVE_ID,
  DELIVERY_ERROR_INVITE_TOKEN,
  EXPIRED_INVITE_MESSAGE,
  EXPIRED_INVITE_TOKEN,
  EXPOSED_HOST_ID,
  LOGIN_REJECTED_MESSAGE,
  LOGIN_REJECTED_PASSWORD,
  PRIMARY_CAMPAIGN_ID,
  SETUP_TOKEN,
  VALID_INVITE_TOKEN,
  campaigns,
} from './experience-fixtures.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);

const base = args.base ?? 'http://127.0.0.1:5175';
const out = args.out ?? 'screenshots';
const label = args.label ?? 'journey';
const themes = (args.themes ?? 'dark,light').split(',');
mkdirSync(out, { recursive: true });

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail: typeof detail === 'string' ? detail : JSON.stringify(detail) });
}

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});

// A platform owner acting inside a tenant: the only actor that reaches /operations.
const opsActor = { ...actor, roles: ['PLATFORM_OWNER', 'TENANT_ADMIN'], platformScope: false, actingAsPlatformOwner: true };
const analystActor = { ...actor, roles: ['SECURITY_ANALYST'] };

async function newPage(theme, width, actorOverride = actor, { unauthenticated = false } = {}) {
  const context = await newContext(browser, { viewport: { width, height: 1000 } });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  const requests = [];
  await routeFixtures(context, {
    actorOverride,
    onRequest: (request) => requests.push({ url: request.url(), method: request.method(), body: request.postData() }),
  });
  // Registered after the shared router, so it takes precedence for /api/me.
  if (unauthenticated) await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  return { context, page, requests, errors };
}

const apiPath = (url) => new URL(url).pathname.replace(/^\/api/, '');
const calls = (requests, pathname, method = 'GET') => requests.filter((request) => apiPath(request.url) === pathname && request.method === method);
const body = (request) => { try { return JSON.parse(request?.body ?? 'null'); } catch { return null; } };
const shot = async (page, name) => {
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(out, `${label}_${name}.png`), fullPage: true });
};
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
const settle = (page) => page.waitForTimeout(500);
const here = (page) => { const url = new URL(page.url()); return url.pathname + url.search; };
const params = (page) => Object.fromEntries(new URL(page.url()).searchParams.entries());
const goto = async (page, route) => { await page.goto(`${base}${route}`, { waitUntil: 'networkidle' }); await settle(page); };

for (const theme of themes) {
  const tag = (name) => `${name}_${theme}`;

  // ── Exposure dashboard: KPIs, grid exposure, insights, drill-downs ───────
  const tenant = await newPage(theme, 1440);
  const { page, requests, errors } = tenant;
  await goto(page, '/exposure');
  await page.locator('.exec-kpi').first().waitFor();
  for (const endpoint of ['/dashboard/exposure-summary', '/dashboard/grid-exposure', '/vuln-repo/dashboard', '/eol/status/summary']) {
    check(tag(`exposure loads ${endpoint}`), calls(requests, endpoint).length > 0);
  }
  const kpiLabels = await page.locator('.exec-kpi-label').allTextContents();
  check(tag('six KPI tiles in order'), kpiLabels.join('|') === 'Critical Findings|Open Findings|Impacted CVEs|CISA KEV Exposure|Needs Attention|EOL Software', kpiLabels.join('|'));
  check(tag('KPI values from fixtures'), (await page.locator('.exec-kpi-value').allTextContents()).join('|') === '84|1,223|286|12|58|14', (await page.locator('.exec-kpi-value').allTextContents()).join('|'));
  check(tag('KPI tone classes kept'), (await page.locator('.exec-kpi').first().getAttribute('class')).includes('exec-kpi--critical'));
  check(tag('grid exposure 4 asset domains'), (await page.locator('.grid-exposure-table tbody tr').count()) === 4);
  check(tag('grid exposure band classes kept'), (await page.locator('.grid-exposure-cell--high .grid-exposure-cell-btn').count()) > 0);
  check(tag('insights listed'), (await page.locator('.exec-insight').count()) === 6, String(await page.locator('.exec-insight').count()));
  check(tag('critical CVE rows'), (await page.locator('.exec-cve-row').count()) === 4);
  check(tag('top asset by finding volume'), (await page.locator('.exec-asset-attention').textContent()).includes('payments-api-01.example.test'));
  check(tag('freshness status shown'), await page.getByText(/Last updated/).first().isVisible());
  await shot(page, tag('exposure'));

  await page.locator('.exec-kpi', { hasText: 'Critical Findings' }).click();
  await settle(page);
  check(tag('critical KPI opens open critical findings'), new URL(page.url()).pathname === '/findings' && /CRITICAL/.test(page.url()) && /OPEN/.test(page.url()), here(page));
  await goto(page, '/exposure');
  await page.locator('.grid-exposure-table tbody tr').first().locator('.grid-exposure-cell-btn').first().click();
  await settle(page);
  check(tag('grid cell opens host critical findings'), new URL(page.url()).pathname === '/findings' && /HOST/.test(page.url()) && /CRITICAL/.test(page.url()), here(page));
  await goto(page, '/exposure');
  await page.locator('.exec-kpi', { hasText: 'Needs Attention' }).click();
  await settle(page);
  check(tag('needs-attention KPI opens unworked impacted CVEs'), here(page) === '/vuln-repo/vulnerabilities?impactedOnly=true&hasFindings=false', here(page));
  await goto(page, '/exposure');
  await page.locator('.exec-cve-row').first().click();
  await settle(page);
  check(tag('critical CVE row opens the workbench'), new URL(page.url()).pathname === `/vuln-repo/org-cves/${CRITICAL_CVE_ID}`, here(page));
  await goto(page, '/exposure');
  await page.locator('.exec-asset-row').first().click();
  await settle(page);
  check(tag('asset row opens host detail'), new URL(page.url()).pathname === `/vuln-repo/host-assets/${EXPOSED_HOST_ID}`, here(page));
  await goto(page, '/exposure');
  await page.locator('.exec-exploit-btn').click();
  await settle(page);
  check(tag('exploit callout opens KEV intelligence'), new URL(page.url()).pathname === '/vuln-repo/vulnerabilities' && params(page).inKev === 'true', here(page));
  await goto(page, '/exposure');
  check(tag('EOL insight has no self-looping action'), (await page.getByRole('button', { name: /View (near-)?EOL/ }).count()) === 0);
  check(tag('EOL insight explains missing lifecycle view'), (await page.getByText('Lifecycle detail view not available yet').count()) >= 1);
  check(tag('EOL KPI is not a navigation control'), (await page.locator('button.exec-kpi', { hasText: 'EOL Software' }).count()) === 0);
  check(tag('no page errors on exposure'), errors.length === 0, errors);

  // ── CVE dashboard (/vuln-repo) ────────────────────────────────────────────
  await goto(page, '/vuln-repo');
  await page.locator('.vuln-repo-dashboard-unresolved-item').first().waitFor();
  check(tag('CVE dashboard lists critical unresolved'), (await page.locator('.vuln-repo-dashboard-unresolved-item').count()) === 4);
  check(tag('CVE dashboard lists impacted assets'), (await page.locator('.vuln-repo-dashboard-asset-card').count()) === 4);
  await shot(page, tag('vuln-repo'));
  await page.locator('.vuln-repo-dashboard-cve-link').first().click();
  await settle(page);
  check(tag('unresolved item opens the workbench'), new URL(page.url()).pathname.startsWith('/vuln-repo/org-cves/'), here(page));

  // ── Campaigns list ────────────────────────────────────────────────────────
  requests.length = 0;
  await goto(page, '/vuln-repo/campaigns');
  await page.locator('.campaigns-table tbody tr').first().waitFor();
  check(tag('campaigns list renders every campaign'), (await page.locator('.campaigns-table tbody tr').count()) === campaigns.length);
  check(tag('campaigns list requests all statuses'), calls(requests, '/campaigns').some((request) => !new URL(request.url).search));
  await shot(page, tag('campaigns'));
  await page.getByPlaceholder('Search campaigns, CVEs, or summary').fill('kubelet');
  await settle(page);
  check(tag('search narrows to one campaign'), (await page.locator('.campaigns-table tbody tr').count()) === 1);
  await page.getByPlaceholder('Search campaigns, CVEs, or summary').fill('');
  requests.length = 0;
  await page.locator('.campaigns-tab-row button', { hasText: /^Blocked/ }).click();
  await settle(page);
  check(tag('Blocked tab requests status=BLOCKED'), calls(requests, '/campaigns').some((request) => new URL(request.url).searchParams.get('status') === 'BLOCKED'));
  check(tag('Blocked tab shows the blocked campaign'), (await page.locator('.campaigns-table tbody tr').count()) === 1
    && (await page.locator('.campaigns-table tbody tr').first().textContent()).includes('Legacy log4j decommission'));
  await page.locator('.campaigns-tab-row button', { hasText: /^All Campaigns/ }).click();
  await settle(page);
  await page.getByRole('button', { name: 'New Campaign' }).click();
  await page.locator('.cw-modal').waitFor();
  check(tag('New Campaign opens the wizard'), await page.locator('.cw-modal').isVisible());
  await shot(page, tag('campaign-wizard'));
  await page.locator('.cw-header .cd-delete-btn').click();
  await settle(page);
  check(tag('wizard closes'), (await page.locator('.cw-modal').count()) === 0);
  await page.locator('.campaigns-table tbody tr', { hasText: 'OpenSSL Q4 remediation sprint' }).click();
  await settle(page);
  check(tag('row opens the campaign detail'), here(page) === `/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`, here(page));

  // ── Campaign detail: tabs, status transition, breadcrumb ─────────────────
  await page.locator('.cd-hero-title').waitFor();
  check(tag('detail shows the campaign title'), (await page.locator('.cd-hero-title').textContent()).includes('OpenSSL Q4 remediation sprint'));
  check(tag('detail tab strip'), (await page.locator('.cd-tab').count()) === 7, String(await page.locator('.cd-tab').count()));
  await shot(page, tag('campaign-detail'));
  await page.locator('.cd-tab', { hasText: /^Findings/ }).click();
  await settle(page);
  check(tag('findings tab lists campaign findings'), await page.getByText('F-1001').first().isVisible());
  check(tag('findings tab marks the active tab'), (await page.locator('.cd-tab.active').textContent()).startsWith('Findings'));
  await shot(page, tag('campaign-findings'));
  requests.length = 0;
  await page.getByRole('button', { name: 'Move to Review' }).click();
  await settle(page);
  const statusCall = calls(requests, `/campaigns/${PRIMARY_CAMPAIGN_ID}/status`, 'POST').at(-1);
  check(tag('Move to Review posts IN_REVIEW'), statusCall && body(statusCall).status === 'IN_REVIEW', statusCall?.body);
  await page.locator('.cd-breadcrumb-link').click();
  await settle(page);
  check(tag('breadcrumb returns to campaigns'), here(page) === '/vuln-repo/campaigns', here(page));
  await goto(page, '/vuln-repo/campaigns/campaign-missing');
  check(tag('unknown campaign shows not-found with back action'), await page.getByRole('button', { name: 'Back to Campaigns' }).isVisible());
  await goto(page, `/vuln-repo/campaigns/${BLOCKED_CAMPAIGN_ID}`);
  await page.locator('.cd-hero-title').waitFor();
  check(tag('blocked campaign renders its status'), await page.locator('.cd-page').getByText('BLOCKED', { exact: false }).first().isVisible());
  check(tag('no page errors on tenant journey'), errors.length === 0, errors);
  await tenant.context.close();

  // ── Tenant operations views (platform owner acting in a tenant) ──────────
  const ops = await newPage(theme, 1440, opsActor);
  await goto(ops.page, '/operations');
  await ops.page.getByRole('heading', { name: /^Ingestion Efficiency/ }).first().waitFor();
  check(tag('/operations renders the pipeline view'), (await ops.page.locator('.ops-context-view').textContent()) === 'Pipeline Analytics', here(ops.page));
  check(tag('pipeline stale-source delay notice'), await ops.page.getByText('Some shared sources are stale').isVisible());
  check(tag('pipeline source breakdown rows'), (await ops.page.locator('.ops-table').first().locator('.ops-table-row').count()) === 3);
  await shot(ops.page, tag('ops-pipeline'));
  await goto(ops.page, '/operations/platform-health');
  await ops.page.getByRole('heading', { name: /^Enterprise Performance Scorecard/ }).first().waitFor();
  check(tag('platform health scorecard'), await ops.page.getByRole('heading', { name: /^Interactive Route Budgets/ }).first().isVisible() && await ops.page.getByRole('heading', { name: /^Runtime Resource Ceilings/ }).first().isVisible());
  const cellCounts = await ops.page.locator('.ops-table').evaluateAll((tables) => tables.map((table) => {
    const header = table.querySelector('.ops-table-header')?.children.length ?? 0;
    const rows = [...table.querySelectorAll('.ops-table-row')].map((row) => row.children.length);
    return rows.every((count) => count === header);
  }));
  check(tag('ops table rows carry one cell per header'), cellCounts.length > 0 && cellCounts.every(Boolean), cellCounts);
  await shot(ops.page, tag('ops-health'));
  await goto(ops.page, '/operations/ingestion-efficiency');
  check(tag('legacy ops alias renders pipeline'), (await ops.page.locator('.ops-context-view').textContent()) === 'Pipeline Analytics');
  await goto(ops.page, '/operations/quality?domain=VEX');
  check(tag('/operations/quality redirects to inventory quality tab'), new URL(ops.page.url()).pathname === '/inventory' && params(ops.page).inventoryTabs === 'quality-vex', here(ops.page));
  check(tag('no page errors on operations'), ops.errors.length === 0, ops.errors);
  await ops.context.close();

  // ── Platform owner: operations console view and redirects ───────────────
  const owner = await newPage(theme, 1440, platformActor);
  await goto(owner.page, '/operations/pipeline');
  check(tag('platform-scope /operations redirects to platform EOL'), new URL(owner.page.url()).pathname === '/platform/eol', here(owner.page));
  await goto(owner.page, '/platform/operations');
  await owner.page.getByRole('heading', { name: /^Tenant Attention Queue/ }).first().waitFor();
  check(tag('platform operations tenant attention rows'), (await owner.page.locator('.ops-table').first().locator('.ops-table-row').count()) === 2);
  check(tag('platform operations subnav tabs'), (await owner.page.locator('.platform-ops-subnav button').count()) === 3);
  await shot(owner.page, tag('platform-ops'));
  await owner.page.locator('.platform-ops-subnav button', { hasText: 'Freshness & Access' }).click();
  await settle(owner.page);
  check(tag('platform operations subview in URL'), params(owner.page).ops !== undefined, here(owner.page));
  await goto(owner.page, '/end-of-life');
  check(tag('platform-scope /end-of-life redirects to platform EOL'), here(owner.page) === '/platform/eol', here(owner.page));
  await goto(owner.page, '/');
  check(tag('platform owner home is tenants'), here(owner.page) === '/platform/tenants', here(owner.page));
  await goto(owner.page, '/vuln-repo');
  check(tag('platform CVE dashboard renders'), await owner.page.locator('.vuln-repo-dashboard-page').first().isVisible());
  await shot(owner.page, tag('platform-vuln-repo'));
  check(tag('no page errors on platform journey'), owner.errors.length === 0, owner.errors);
  await owner.context.close();

  // ── Legacy redirects and role-based home ─────────────────────────────────
  const legacy = await newPage(theme, 1440);
  for (const [from, expected] of [
    ['/', '/configurations'],
    ['/vulnerability-intelligence?severity=CRITICAL', '/vuln-repo/vulnerabilities?severity=CRITICAL'],
    ['/vulnerability-intelligence/vulnerabilities', '/vuln-repo/vulnerabilities'],
    [`/vulnerability-intelligence/org-cves/${CRITICAL_CVE_ID}`, `/vuln-repo/org-cves/${CRITICAL_CVE_ID}`],
    ['/vuln-repo/policies', '/platform/ai-policies'],
    ['/fix-intelligence', '/fix-intelligence/all'],
    ['/end-of-life', '/exposure'],
    ['/no-such-route', '/configurations'],
  ]) {
    await goto(legacy.page, from);
    check(tag(`redirect ${from}`), here(legacy.page) === expected, here(legacy.page));
  }
  // Recorded quirk (unchanged): HomeRoute redirects '/' to the role home before LegacyQueryRedirect
  // runs, so a legacy '/?tab=findings' link opens the role home, not /findings.
  await goto(legacy.page, '/?tab=findings');
  check(tag('legacy /?tab= link resolves to the role home (recorded quirk)'), here(legacy.page) === '/configurations', here(legacy.page));
  await goto(legacy.page, '/inventory/ai/executions');
  check(tag('redirect /inventory/ai/executions stays in AI inventory'), new URL(legacy.page.url()).pathname.startsWith('/inventory/ai'), here(legacy.page));
  await legacy.context.close();
  const analyst = await newPage(theme, 1440, analystActor);
  await goto(analyst.page, '/');
  check(tag('analyst home is exposure'), here(analyst.page) === '/exposure', here(analyst.page));
  await goto(analyst.page, '/operations');
  check(tag('analyst /operations has no operations nav'), (await analyst.page.locator('nav').getByText('Operations', { exact: true }).count()) === 0);
  await analyst.context.close();

  // ── Authentication entry ────────────────────────────────────────────────
  const anon = await newPage(theme, 1440, actor, { unauthenticated: true });
  await goto(anon.page, '/exposure');
  check(tag('unauthenticated route redirects to login with next'), here(anon.page) === `/login?next=${encodeURIComponent('/exposure')}`, here(anon.page));
  const signIn = anon.page.getByRole('button', { name: 'Sign in' });
  check(tag('sign in disabled until both fields are filled'), await signIn.isDisabled());
  check(tag('test personas hidden without the flag'), (await anon.page.getByText('Non-production test personas').count()) === 0);
  await shot(anon.page, tag('login'));
  await anon.page.getByLabel('Email').fill('fixture.analyst@example.test');
  await anon.page.getByLabel('Password', { exact: true }).fill(LOGIN_REJECTED_PASSWORD);
  anon.requests.length = 0;
  await signIn.click();
  await anon.page.getByRole('alert').waitFor();
  check(tag('rejected login shows the server message'), (await anon.page.getByRole('alert').textContent()).includes(LOGIN_REJECTED_MESSAGE));
  check(tag('rejected login keeps the email'), (await anon.page.getByLabel('Email').inputValue()) === 'fixture.analyst@example.test');
  const loginCall = calls(anon.requests, '/auth/login', 'POST').at(-1);
  check(tag('login posts email and password'), loginCall && body(loginCall).email === 'fixture.analyst@example.test' && typeof body(loginCall).password === 'string');
  await shot(anon.page, tag('login-error'));
  await goto(anon.page, '/login?activated=1&email=new.user%40example.test');
  check(tag('activation notice and prefilled email'), await anon.page.getByRole('status').filter({ hasText: 'Password created successfully' }).isVisible()
    && (await anon.page.getByLabel('Email').inputValue()) === 'new.user@example.test');
  await goto(anon.page, '/login?setup=1&email=new.user%40example.test');
  const setPassword = anon.page.getByRole('button', { name: 'Set password' });
  await anon.page.getByLabel('New password').fill('short');
  check(tag('set password needs 8 characters'), await setPassword.isDisabled());
  await anon.page.getByLabel('New password').fill('long-enough-password');
  anon.requests.length = 0;
  await setPassword.click();
  await settle(anon.page);
  check(tag('set password posts and returns to login'), calls(anon.requests, '/auth/setup-password', 'POST').length === 1
    && here(anon.page) === '/login?activated=1&email=new.user%40example.test', here(anon.page));
  await shot(anon.page, tag('login-activated'));

  await goto(anon.page, `/tenant-invite#token=${VALID_INVITE_TOKEN}`);
  await anon.page.getByRole('button', { name: 'Accept invite' }).waitFor();
  check(tag('invite link token removed from the URL'), here(anon.page) === '/tenant-invite' && !anon.page.url().includes(VALID_INVITE_TOKEN), anon.page.url());
  check(tag('workspace invite details'), (await anon.page.locator('.demo-invite-details').textContent()).includes('SECURITY ANALYST'));
  await shot(anon.page, tag('tenant-invite'));
  await anon.page.getByRole('button', { name: 'Accept invite' }).click();
  await settle(anon.page);
  check(tag('accepted invite opens password setup'), here(anon.page) === '/login?setup=1&email=new.user%40example.test', here(anon.page));
  await goto(anon.page, `/invite#token=${DELIVERY_ERROR_INVITE_TOKEN}`);
  await anon.page.getByRole('button', { name: 'Activate your workspace' }).waitFor();
  check(tag('demo invite delivery error is truthful'), await anon.page.getByText('could not deliver the email automatically').isVisible());
  await shot(anon.page, tag('demo-invite'));
  await goto(anon.page, `/tenant-invite#token=${EXPIRED_INVITE_TOKEN}`);
  await anon.page.locator('.notice.error').waitFor();
  check(tag('expired invite shows the server message'), (await anon.page.locator('.notice.error').textContent()).includes(EXPIRED_INVITE_MESSAGE));
  await goto(anon.page, '/tenant-invite');
  check(tag('invite without token reports an expired link'), await anon.page.getByText('This link has expired. Request a new invitation link.').isVisible());
  anon.requests.length = 0;
  await goto(anon.page, `/setup#token=${SETUP_TOKEN}&email=new.user%40example.test`);
  check(tag('setup link exchanges and opens password setup'), calls(anon.requests, '/auth/setup-session', 'POST').length === 1
    && here(anon.page) === '/login?setup=1&email=new.user%40example.test', here(anon.page));
  await goto(anon.page, '/setup#token=bad-token');
  await anon.page.getByRole('alert').waitFor();
  check(tag('invalid setup link shows an error'), (await anon.page.getByRole('alert').textContent()).includes('invalid or expired'));
  await shot(anon.page, tag('setup-error'));
  await anon.page.locator('.public-demo-nav').getByRole('link', { name: 'Log in' }).click();
  await settle(anon.page);
  check(tag('public nav log-in link kept'), here(anon.page) === '/login', here(anon.page));
  check(tag('no page errors on auth entry'), anon.errors.length === 0, anon.errors);
  await anon.context.close();

  // Successful login lands on the role home.
  const fresh = await newPage(theme, 1440);
  await goto(fresh.page, '/login');
  await fresh.page.getByLabel('Email').fill('fixture.analyst@example.test');
  await fresh.page.getByLabel('Password', { exact: true }).fill('correct-password');
  await fresh.page.getByRole('button', { name: 'Sign in' }).click();
  await settle(fresh.page);
  check(tag('successful login opens the role home'), here(fresh.page) === '/configurations', here(fresh.page));
  await fresh.context.close();

  // ── Narrow viewport ─────────────────────────────────────────────────────
  for (const [who, routes, options] of [
    [actor, ['/exposure', '/vuln-repo', '/vuln-repo/campaigns', `/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`], {}],
    [opsActor, ['/operations/pipeline', '/operations/platform-health'], {}],
    [platformActor, ['/platform/operations', '/vuln-repo'], {}],
    [actor, ['/login', `/tenant-invite#token=${VALID_INVITE_TOKEN}`, `/invite#token=${VALID_INVITE_TOKEN}`, '/setup'], { unauthenticated: true }],
  ]) {
    const narrow = await newPage(theme, 390, who, options);
    for (const route of routes) {
      await goto(narrow.page, route);
      check(tag(`no page overflow at 390px ${route.split('#')[0]} (${who.roles.join('+')})`), !(await overflow(narrow.page)));
    }
    if (routes[0] === '/exposure') {
      await goto(narrow.page, '/exposure');
      await shot(narrow.page, tag('exposure_390'));
      await goto(narrow.page, `/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`);
      await shot(narrow.page, tag('campaign-detail_390'));
    }
    if (routes[0] === '/login') await shot(narrow.page, tag('setup_390'));
    await narrow.context.close();
  }
}

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
console.log(`${label}: ${results.length - failed.length}/${results.length} passed`);
for (const result of failed) console.log(`FAIL ${result.name} ${result.detail}`);
process.exitCode = unexpectedFailures(results).length ? 1 : 0;
failOnUnexpectedApi();
