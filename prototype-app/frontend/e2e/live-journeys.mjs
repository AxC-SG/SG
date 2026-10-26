#!/usr/bin/env node
// UI 2.0 P8 — critical browser journeys (plan "Minimum critical browser journeys") against a REAL local
// backend: no route fixtures, sign-in through the login form, writes only to a disposable tenant.
// Assertions are data-independent (request shapes, totals invariants, navigation and return context)
// because live data is not the fixture data the *-journey.mjs scripts pin.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   LIVE_CREDENTIALS=<json file {email,password} of a disposable tenant admin, outside the repo> \
//   LIVE_PLATFORM_CREDENTIALS=<json file {email,password} of a local platform owner, outside the repo> \
//   node live-journeys.mjs --base http://127.0.0.1:5180 --out <dir> --label live \
//     [--journeys findings,ai,cve,inventory,authority,connect] [--themes dark,light]
// External delivery is never exercised: ServiceNow is left unconfigured or pointed at a reserved
// example.test host, and the platform-create step only creates another disposable tenant.
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);

const base = args.base ?? 'http://127.0.0.1:5180';
const out = args.out ?? 'live';
const label = args.label ?? 'live';
const themes = (args.themes ?? 'dark,light').split(',');
const journeys = new Set((args.journeys ?? 'findings,ai,cve,inventory,authority,connect').split(','));
const tenantCredentials = JSON.parse(readFileSync(process.env.LIVE_CREDENTIALS, 'utf8'));
const platformCredentials = process.env.LIVE_PLATFORM_CREDENTIALS ? JSON.parse(readFileSync(process.env.LIVE_PLATFORM_CREDENTIALS, 'utf8')) : null;
mkdirSync(out, { recursive: true });

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail });
}
/** A step live data cannot exercise: reported separately, never counted as a pass. */
function skip(name, reason) {
  results.push({ name, ok: true, skipped: true, detail: reason });
}

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});

// One form sign-in per account per run; later contexts reuse that browser session. The backend
// limits logins to 10 per email per 15 minutes, so signing in per journey would trip it.
const sessions = new Map();
async function signedInPage(theme, width = 1440, credentials = tenantCredentials) {
  const storageState = sessions.get(credentials.email);
  const context = await browser.newContext({ viewport: { width, height: 1000 }, acceptDownloads: true, ...(storageState ? { storageState } : {}) });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  const requests = [];
  const failures = [];
  context.on('request', (request) => { if (new URL(request.url()).pathname.startsWith('/api/')) requests.push(request); });
  context.on('response', (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith('/api/') && response.status() >= 500) failures.push(`${response.status()} ${url.pathname}`);
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  if (storageState) {
    await page.goto(`${base}/`, { waitUntil: 'networkidle' });
  } else {
    await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
    await page.getByLabel('Email').fill(credentials.email);
    await page.getByLabel('Password', { exact: true }).fill(credentials.password);
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL((url) => url.pathname !== '/login', { timeout: 15000 });
    sessions.set(credentials.email, await context.storageState());
  }
  return { context, page, requests, failures, errors };
}

const apiPath = (url) => new URL(url).pathname.replace(/^\/api/, '');
const calls = (requests, pathname, method = 'GET') => requests.filter((request) => apiPath(request.url()) === pathname && request.method() === method);
const bodyOf = (request) => { try { return JSON.parse(request?.postData() ?? 'null'); } catch { return null; } };
const here = (page) => { const url = new URL(page.url()); return url.pathname + url.search; };
const settle = (page) => page.waitForTimeout(600);
const visible = (locator) => locator.first().isVisible().catch(() => false);
const statusOf = async (request) => (await request?.response().catch(() => null))?.status();
const shot = async (page, name) => {
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(out, `${label}_${name}.png`), fullPage: true });
};
/** Runs `action` and resolves with the next request to `pathname` (and its response) it causes. */
async function requestFrom(page, pathname, action, method = null) {
  const pending = page.waitForRequest((request) => apiPath(request.url()) === pathname && (!method || request.method() === method), { timeout: 10000 }).catch(() => null);
  await action();
  const request = await pending;
  const response = request ? await request.response().catch(() => null) : null;
  await page.waitForTimeout(400);
  return request ? { url: new URL(request.url()), request, response } : null;
}
const pageInfo = async (page) => (await page.locator('.fpl-page-info').innerText().catch(() => '')).replace(/\s+/g, ' ');
const totalOf = (info) => Number((/([\d,]+) findings?/.exec(info) ?? [])[1]?.replace(/,/g, '') ?? NaN);

async function findingsJourney(theme) {
  const tag = (name) => `findings: ${name} [${theme}]`;
  const { context, page, requests, failures, errors } = await signedInPage(theme);
  check(tag('sign-in leaves /login'), new URL(page.url()).pathname !== '/login', page.url().replace(base, ''));

  // URL scope: status=OPEN deep link is serialised into the list request.
  const scoped = await requestFrom(page, '/findings', () => page.goto(`${base}/findings?status=OPEN`, { waitUntil: 'networkidle' }));
  await page.locator('.fpl-tr').first().waitFor({ timeout: 15000 });
  check(tag('URL scope status=OPEN sent'), scoped?.url.searchParams.getAll('status').join() === 'OPEN', scoped?.url.search);
  check(tag('list request 200'), scoped?.response?.status() === 200, String(scoped?.response?.status()));
  const scopedTotal = totalOf(await pageInfo(page));
  check(tag('page info shows a total'), Number.isFinite(scopedTotal) && scopedTotal > 0, await pageInfo(page));
  await shot(page, `findings-list_${theme}`);

  await page.goto(`${base}/findings`, { waitUntil: 'networkidle' });
  await page.locator('.fpl-tr').first().waitFor();
  const queueTotal = totalOf(await pageInfo(page));
  const rows = await page.locator('.fpl-tr').count();
  check(tag('rows rendered within page size'), rows > 0 && rows <= 25, String(rows));

  // Widget toggle narrows the table only; queue-wide aggregates keep scope.
  requests.length = 0;
  const legend = page.locator('.fpl-legend-row').first();
  const legendLabel = (await legend.innerText()).split('\n')[0].trim().toUpperCase();
  const narrowed = await requestFrom(page, '/findings', () => legend.click());
  check(tag(`widget sends severity=${legendLabel}`), narrowed?.url.searchParams.getAll('severity').join() === legendLabel, narrowed?.url.search);
  const aggregates = requests.filter((request) => /\/findings\/(summary|distributions|backlog-health)/.test(request.url()));
  check(tag('aggregates not re-requested with severity'), aggregates.every((request) => !new URL(request.url()).searchParams.has('severity')), aggregates.map((request) => new URL(request.url()).search).join(' | '));
  const narrowedTotal = totalOf(await pageInfo(page));
  check(tag('narrowed total <= queue total'), narrowedTotal <= queueTotal, `${narrowedTotal} <= ${queueTotal}`);
  await shot(page, `findings-widget-active_${theme}`);
  await legend.click();
  await page.waitForTimeout(800);
  check(tag('widget toggles off, queue total restored'), (await page.locator('.fpl-legend-row--active').count()) === 0 && totalOf(await pageInfo(page)) === queueTotal, await pageInfo(page));

  // Multi-column narrowing: two Status values accumulate.
  const popover = page.locator('.fpl-col-filter-popover');
  const statusFilter = page.locator('.fpl-th', { hasText: 'Status' }).locator('.fpl-filter-btn');
  await statusFilter.click();
  if (!(await popover.isVisible())) await statusFilter.click();
  await popover.waitFor();
  const options = popover.locator('.fpl-col-filter-check');
  const optionCount = await options.count();
  if (optionCount >= 2) {
    await requestFrom(page, '/findings', () => options.nth(0).click());
    const second = await requestFrom(page, '/findings', () => options.nth(1).click());
    check(tag('status column values accumulate'), second?.url.searchParams.getAll('status').length === 2, second?.url.search);
  } else {
    check(tag('status column offers values'), optionCount >= 1, String(optionCount));
  }
  await page.keyboard.press('Escape');
  await page.mouse.click(1300, 40);
  check(tag('filter chip shown'), (await page.locator('.fpl-chip').count()) >= 1);
  const clearAll = page.locator('.fpl-chip-clear');
  await requestFrom(page, '/findings', () => clearAll.count().then((count) => (count ? clearAll.click() : page.locator('.fpl-chip button').first().click())));
  await page.waitForTimeout(600);
  check(tag('clearing chips restores queue total'), totalOf(await pageInfo(page)) === queueTotal, await pageInfo(page));

  // Cursor next/back/reset (only when the live queue has more than one page).
  const next = page.getByRole('button', { name: 'Next →' });
  if (await next.isEnabled().catch(() => false)) {
    const nextRequest = await requestFrom(page, '/findings', () => next.click());
    check(tag('next page sends cursor'), Boolean(nextRequest?.url.searchParams.get('cursor')), nextRequest?.url.search);
    check(tag('page 2 info'), /Page 2 of/.test(await pageInfo(page)), await pageInfo(page));
    await page.getByRole('button', { name: '← Prev' }).click();
    await page.waitForTimeout(800);
    check(tag('prev returns to page 1'), /Page 1 of/.test(await pageInfo(page)), await pageInfo(page));
  } else {
    check(tag('single page: next disabled is consistent'), queueTotal <= rows, `${queueTotal} total, ${rows} rows`);
  }

  // Row click selects without navigating.
  const firstRow = page.locator('.fpl-tr').first();
  await firstRow.locator('td').nth(3).click();
  check(tag('row click selects'), (await firstRow.getAttribute('class')).includes('fpl-tr--selected'));
  check(tag('row click stays on list'), new URL(page.url()).pathname === '/findings');

  // Group selection: server group aggregates without ad-hoc table filters.
  await page.locator('.multi-groupby-trigger').first().click();
  const group = await requestFrom(page, '/findings/groups', () => page.locator('.multi-groupby-option', { hasText: 'Severity' }).first().click());
  check(tag('group-by requests server groups'), group?.url.searchParams.get('field') === 'severity' && group?.response?.status() === 200, group?.url.search);
  await page.locator('.fpl-group-item').first().waitFor({ timeout: 8000 }).catch(() => null);
  check(tag('group cards render'), (await page.locator('.fpl-group-item').count()) > 0);
  await shot(page, `findings-grouped_${theme}`);
  await page.goto(`${base}/findings`, { waitUntil: 'networkidle' });
  await page.locator('.fpl-tr').first().waitFor();

  // Detail → CVE link → return context; read-only actions stay non-mutating.
  const findingId = (await page.locator('.finding-id-link').first().innerText()).trim();
  await page.locator('.finding-id-link').first().click();
  await page.locator('.fd3-topbar').waitFor({ timeout: 15000 });
  check(tag('finding link opens detail'), new URL(page.url()).pathname === `/findings/${findingId}`, page.url().replace(base, ''));
  await page.waitForLoadState('networkidle');
  await shot(page, `finding-detail_${theme}`);
  const cveLink = page.locator('.fd3-cve-link').first();
  const cveId = (await cveLink.innerText().catch(() => '')).trim();
  check(tag('detail shows CVE link'), /^CVE-\d{4}-\d+$/.test(cveId), cveId);
  await cveLink.click();
  await page.waitForURL((url) => url.pathname.startsWith('/vuln-repo/org-cves/'), { timeout: 10000 }).catch(() => null);
  check(tag('CVE link opens workbench record'), new URL(page.url()).pathname === `/vuln-repo/org-cves/${cveId}`, page.url().replace(base, ''));
  await page.goBack();
  await page.locator('.fd3-topbar').waitFor({ timeout: 10000 });
  check(tag('back from CVE returns to finding'), new URL(page.url()).pathname === `/findings/${findingId}`, page.url().replace(base, ''));
  const writesBefore = requests.filter((request) => request.method() !== 'GET').length;
  await page.locator('.fd3-tab', { hasText: 'Affected Assets' }).click().catch(() => null);
  await page.waitForTimeout(600);
  check(tag('tab switch issues no writes'), requests.filter((request) => request.method() !== 'GET').length === writesBefore);
  await page.locator('.fd3-back-btn').click();
  await page.locator('.fpl-tr').first().waitFor();
  check(tag('back returns to findings'), new URL(page.url()).pathname === '/findings', page.url().replace(base, ''));

  check(tag('no 5xx API responses'), failures.length === 0, failures.join(' | '));
  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();
}

async function aiFindingsJourney(theme) {
  const tag = (name) => `ai-findings: ${name} [${theme}]`;
  const { context, page, failures, errors } = await signedInPage(theme);
  const list = await requestFrom(page, '/ai-security/findings', () => page.goto(`${base}/findings/ai`, { waitUntil: 'networkidle' }));
  check(tag('entitled tenant stays on /findings/ai'), new URL(page.url()).pathname === '/findings/ai', here(page));
  check(tag('default scope status=OPEN'), list?.url.searchParams.get('status') === 'OPEN' && list?.response?.status() === 200, list?.url.search);
  await shot(page, `ai-findings_${theme}`);
  const provider = await requestFrom(page, '/ai-security/findings', () => page.getByLabel('Cloud provider').selectOption('AWS'));
  check(tag('provider filter keeps status scope'), provider?.url.searchParams.get('provider') === 'AWS' && provider?.url.searchParams.get('status') === 'OPEN', provider?.url.search);
  await page.getByLabel('Cloud provider').selectOption('');
  await settle(page);

  // Deep-link scope is policyId/severity/nativeKind (provider is page state only).
  const deep = await requestFrom(page, '/ai-security/findings', () => page.goto(`${base}/findings/ai?severity=CRITICAL`, { waitUntil: 'networkidle' }));
  check(tag('deep link severity=CRITICAL serialised with status'), deep?.url.searchParams.get('severity') === 'CRITICAL' && deep?.url.searchParams.get('status') === 'OPEN', deep?.url.search);
  await page.goto(`${base}/findings/ai`, { waitUntil: 'networkidle' });
  const aiRows = page.locator('.ai-security-table-panel tbody tr');
  if ((await aiRows.count()) > 0 && !(await aiRows.first().innerText()).match(/No .*found/i)) {
    await aiRows.first().click();
    await page.locator('.fd3-topbar').waitFor({ timeout: 10000 }).catch(() => null);
    const detailUrl = new URL(page.url());
    check(tag('row opens detail with returnTo'), detailUrl.pathname.startsWith('/findings/ai/') && detailUrl.searchParams.get('returnTo') === '/findings/ai', here(page));
    await page.locator('.fd3-back-btn').click();
    await page.waitForURL(`${base}/findings/ai`);
    check(tag('detail back returns'), new URL(page.url()).pathname === '/findings/ai');
  } else {
    check(tag('empty AI findings state renders without error'), errors.length === 0 && new URL(page.url()).pathname === '/findings/ai', `${await page.locator('main').innerText().catch(() => '')}`.slice(0, 160));
  }

  const vuln = await requestFrom(page, '/findings', () => page.getByRole('button', { name: 'Software Vulnerabilities' }).click());
  check(tag('software-vulnerability tab keeps AI-resource constraint'), vuln?.url.searchParams.getAll('findingKind').join() === 'VULNERABILITY'
    && vuln?.url.searchParams.get('hasAffectedAiResource') === 'true' && vuln?.url.searchParams.get('status') === 'OPEN', vuln?.url.search);
  const vulnAll = await requestFrom(page, '/findings', () => page.getByLabel('Finding status').selectOption(''));
  check(tag('status change retains AI-resource constraint'), vulnAll?.url.searchParams.get('hasAffectedAiResource') === 'true' && !vulnAll?.url.searchParams.has('status'), vulnAll?.url.search);
  await shot(page, `ai-vulnerabilities_${theme}`);

  await page.goto(`${base}/findings/ai/exposures`, { waitUntil: 'networkidle' });
  check(tag('exposures route renders'), new URL(page.url()).pathname === '/findings/ai/exposures' && (await page.locator('.ai-security-table-panel, .empty-state').count()) > 0);
  const exposureRows = page.locator('.ai-security-table-panel tbody tr');
  if ((await exposureRows.count()) > 0 && !(await exposureRows.first().innerText()).match(/No .*found/i)) {
    await exposureRows.first().click();
    await page.waitForURL(/\/findings\/ai\/exposures\/[^/]+$/, { timeout: 8000 }).catch(() => null);
    check(tag('exposure row opens detail'), /\/findings\/ai\/exposures\/[^/]+$/.test(new URL(page.url()).pathname), here(page));
  }
  await shot(page, `ai-exposures_${theme}`);
  check(tag('no 5xx API responses'), failures.length === 0, failures.join(' | '));
  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();
}

async function cveJourney(theme) {
  const tag = (name) => `cve: ${name} [${theme}]`;
  const { context, page, requests, failures, errors } = await signedInPage(theme);
  const rowsOf = () => page.locator('.resizable-table tbody tr');

  // Intelligence → record overview.
  await page.goto(`${base}/vuln-repo/vulnerabilities`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('intelligence list renders published CVEs'), await visible(page.getByText(/CVE-\d{4}-\d+/)));
  await shot(page, `intelligence_${theme}`);

  await page.goto(`${base}/vuln-repo/org-cves`, { waitUntil: 'networkidle' });
  await rowsOf().first().waitFor({ timeout: 15000 });
  const listRows = await rowsOf().count();
  check(tag('org records list renders rows'), listRows > 0, String(listRows));
  requests.length = 0;
  await page.getByLabel('KEV Status').selectOption('KEV_ONLY');
  await settle(page);
  const kev = calls(requests, '/vuln-repo/org-cves').at(-1);
  check(tag('KEV filter sends inKev=true&page=0'), kev && new URL(kev.url()).searchParams.get('inKev') === 'true' && new URL(kev.url()).searchParams.get('page') === '0', kev?.url());
  await page.getByLabel('KEV Status').selectOption({ index: 0 });
  await settle(page);
  const firstCve = ((await rowsOf().first().innerText()).match(/CVE-\d{4}-\d+/) ?? [])[0];
  await page.getByLabel('Search CVE / Title / Severity').fill(`  ${firstCve}  `);
  requests.length = 0;
  await page.getByRole('button', { name: 'Apply' }).click();
  await settle(page);
  const searched = calls(requests, '/vuln-repo/org-cves').at(-1);
  check(tag('Apply sends trimmed query'), searched && new URL(searched.url()).searchParams.get('query') === firstCve, searched?.url());
  check(tag('search narrows to the CVE'), (await rowsOf().count()) >= 1 && (await rowsOf().count()) <= listRows);
  await page.getByRole('button', { name: 'Clear' }).click();
  await settle(page);
  check(tag('Clear restores rows'), (await rowsOf().count()) === listRows, String(await rowsOf().count()));

  await rowsOf().filter({ hasText: firstCve }).first().click();
  await page.waitForURL(`**/vuln-repo/org-cves/${firstCve}`);
  await page.locator('.cve-assessment-page').waitFor({ timeout: 15000 });
  check(tag('row opens workbench at /vuln-repo/org-cves/:id'), new URL(page.url()).pathname === `/vuln-repo/org-cves/${firstCve}`, here(page));
  await settle(page);
  await shot(page, `workbench-overview_${theme}`);
  for (const tab of ['Affected Entities', 'Fixes', 'Overview']) {
    await page.locator('.cvd2-tab', { hasText: tab }).click();
    await settle(page);
  }
  check(tag('workbench tabs switch'), await visible(page.locator('.cvd2-tab.active', { hasText: 'Overview' })));
  const cvePath = (suffix) => `/cve-detail/${firstCve}${suffix}`;

  // Investigation save → reopen keeps it.
  const investigationButton = page.getByRole('button', { name: /Investigation/ }).first();
  if (await visible(investigationButton)) {
    await investigationButton.click();
    const save = page.getByRole('button', { name: 'Save Investigation' });
    await save.waitFor({ timeout: 10000 }).catch(() => null);
    if (await visible(save)) {
      await page.waitForFunction(() => [...document.querySelectorAll('button')].some((b) => b.textContent === 'Save Investigation' && !b.disabled), null, { timeout: 10000 }).catch(() => null);
      requests.length = 0;
      await save.click();
      await page.getByText('Investigation saved.').waitFor({ timeout: 10000 }).catch(() => null);
      const runbook = requests.filter((request) => apiPath(request.url()) === cvePath('/investigation/runbook') && request.method() !== 'GET');
      const submit = calls(requests, cvePath('/investigation/submit'), 'POST');
      check(tag('investigation save writes runbook then submits'), runbook.length === 1 && submit.length === 1 && (await statusOf(submit[0])) < 300, `${runbook.length}/${submit.length} ${await statusOf(submit[0])}`);
      await shot(page, `investigation_${theme}`);
      await page.goto(`${base}/vuln-repo/org-cves/${firstCve}`, { waitUntil: 'networkidle' });
      await settle(page);
      check(tag('investigation reopen shows saved state'), await visible(page.getByRole('button', { name: /1 Investigation|Investigation/ })));
    } else {
      check(tag('investigation panel opens'), false, 'Save Investigation not shown');
    }
  } else {
    check(tag('investigation entry visible'), false, 'no Investigation button on overview');
  }

  // Applicability and analyst impact, VEX disclosure, partial assessment.
  await page.goto(`${base}/vuln-repo/org-cves/${firstCve}`, { waitUntil: 'networkidle' });
  await settle(page);
  const review = page.getByRole('button', { name: /Review Applicability/ }).first();
  if (await visible(review)) {
    await review.click();
    await page.getByRole('button', { name: 'Save Assessment' }).waitFor({ timeout: 10000 });
    const appGroups = page.getByRole('group', { name: /^Applicability for / });
    const impactGroups = page.getByRole('group', { name: /^Impact disposition for / });
    check(tag('applicability and impact are separate controls'), (await appGroups.count()) >= 1 && (await impactGroups.count()) >= 1, `${await appGroups.count()}/${await impactGroups.count()}`);
    const vexOpen = page.getByRole('button', { name: 'View VEX evidence' }).first();
    if (await visible(vexOpen)) {
      requests.length = 0;
      await vexOpen.click();
      await settle(page);
      const vexCall = requests.find((request) => apiPath(request.url()) === cvePath('/vex-evidence'));
      check(tag('VEX disclosure fetches component-scoped evidence'), vexCall && new URL(vexCall.url()).searchParams.has('componentId') && (await statusOf(vexCall)) < 500, vexCall?.url());
      await page.getByRole('button', { name: 'Hide VEX evidence' }).first().click();
      await vexOpen.click();
      await settle(page);
      check(tag('VEX reopen served from cache'), requests.filter((request) => apiPath(request.url()) === cvePath('/vex-evidence')).length === 1);
      await page.getByRole('button', { name: 'Hide VEX evidence' }).first().click();
    }
    const impactBefore = await impactGroups.count();
    await appGroups.first().getByRole('button', { name: 'Not Applicable', exact: true }).click();
    check(tag('Not Applicable removes one impact control'), (await impactGroups.count()) === impactBefore - 1);
    await appGroups.first().getByRole('button', { name: 'Applicable', exact: true }).click();
    check(tag('restored applicability re-adds impact control'), (await impactGroups.count()) === impactBefore);
    await impactGroups.first().getByRole('button', { name: 'Impacted', exact: true }).click();
    const rationale = page.getByPlaceholder('Document your assessment rationale...');
    await rationale.fill('Live P8 qualification: partial review of disposable demo data.');
    await shot(page, `applicability_${theme}`);
    requests.length = 0;
    await page.getByRole('button', { name: 'Save Assessment' }).click();
    await page.getByRole('button', { name: 'Proceed to Findings' }).or(page.getByText('Impacted Assets')).first().waitFor({ timeout: 15000 }).catch(() => null);
    const proceed = page.getByRole('button', { name: 'Proceed to Findings' });
    if (await visible(proceed)) await proceed.click();
    await page.getByText('Impacted Assets').first().waitFor({ timeout: 15000 }).catch(() => null);
    const submit = calls(requests, cvePath('/assessment/submit'), 'POST').at(-1);
    const body = bodyOf(submit);
    check(tag('partial assessment persists with separate impact/disposition maps'), (await statusOf(submit)) < 300 && body?.componentImpactDecisions && body?.componentAnalystDispositions
      && Object.values(body.componentAnalystDispositions).includes('IMPACTED'), `${await statusOf(submit)} ${JSON.stringify(body)?.slice(0, 200)}`);
    await shot(page, `impacted-assets_${theme}`);

    // Configured creation, ServiceNow ticket partial failure (connector unconfigured → local error), duplicate result.
    const create = page.getByRole('button', { name: /^Create Findings$/ });
    if (await visible(create)) {
      await create.click();
      await page.getByLabel('Notes').waitFor({ timeout: 10000 });
      await page.getByLabel('Notes').fill('Created by live P8 qualification (disposable tenant)');
      const ticketBox = page.getByRole('checkbox', { name: 'Create tickets in ServiceNow' });
      if ((await ticketBox.count()) && !(await ticketBox.isChecked())) await ticketBox.check();
      await page.getByRole('radio', { name: /CVE \+ Fix/ }).check();
      requests.length = 0;
      // The assessment-save notice is still shown here; wait for the creation result to replace it.
      const previousStatus = await page.getByRole('status').first().innerText().catch(() => '');
      await page.getByRole('button', { name: /^Create Findings \(\d+\)$/ }).click();
      await page.waitForFunction((previous) => {
        const text = document.querySelector('[role="status"]')?.textContent?.trim();
        return Boolean(text) && text !== previous.trim();
      }, previousStatus, { timeout: 30000 }).catch(() => null);
      await settle(page);
      const status = await page.getByRole('status').first().innerText().catch(() => '');
      const creates = calls(requests, cvePath('/manual-finding'), 'POST');
      const tickets = calls(requests, cvePath('/servicenow-incident'), 'POST');
      // First run creates findings and reports the ServiceNow failure; re-runs get the duplicate result.
      const duplicate = /already open .*No duplicates created/i.test(status);
      check(tag(duplicate ? 'duplicate result reported, nothing re-created' : 'creation succeeds and ticket failure is reported'),
        duplicate ? creates.length === 1 && tickets.length === 0 : /Created \d+ finding/i.test(status) && /ServiceNow/i.test(status), status);
      check(tag('ticket failure does not duplicate creation'), creates.length === 1 && tickets.length <= 1, `${creates.length}/${tickets.length}`);
      check(tag('creation payload keeps CVE + Fix mode and existing-finding behaviour'), bodyOf(creates[0])?.findingCreationMode === 'CVE_FIX' && bodyOf(creates[0])?.existingFindingBehavior === 'ADD_TO_EXISTING', JSON.stringify(bodyOf(creates[0]))?.slice(0, 200));
      check(tag('ServiceNow ticket fails locally as not configured (no delivery)'), tickets.length === 0 || (await statusOf(tickets[0])) === 503, `${await statusOf(tickets[0])}`);
      await shot(page, `findings-created_${theme}`);
    } else {
      check(tag('Create Findings available after assessment'), false, 'button not shown');
    }
  } else {
    check(tag('Review Applicability available'), false, 'button not shown on overview');
  }

  // Fixes tab and notification drafts (no delivery).
  await page.goto(`${base}/vuln-repo/org-cves/${firstCve}`, { waitUntil: 'networkidle' });
  await page.locator('.cvd2-tab', { hasText: 'Fixes' }).click();
  await settle(page);
  await shot(page, `fixes_${theme}`);
  await page.locator('.cvd2-tab', { hasText: 'Overview' }).click();
  const notify = page.getByRole('button', { name: /Notify Groups/ }).first();
  if (await visible(notify)) {
    await notify.click();
    check(tag('notify groups says delivery is not connected'), await visible(page.getByText(/Email delivery is not connected/)));
    const download = page.waitForEvent('download', { timeout: 8000 }).catch(() => null);
    await page.getByRole('button', { name: 'Download notification drafts' }).click();
    check(tag('notification draft export downloads'), Boolean(await download));
    check(tag('export does not claim delivery'), (await page.getByText(/Email queued|sent successfully/i).count()) === 0);
  } else {
    check(tag('Notify Groups available'), false, 'button not shown');
  }

  // Second finding-creation entry path: overview card → dedicated assets route; duplicate result.
  await page.goto(`${base}/vuln-repo/org-cves/${firstCve}`, { waitUntil: 'networkidle' });
  const card = page.locator('.cvd2-wf-card', { hasText: 'Create Findings' });
  if (await visible(card)) {
    await card.click();
    await page.waitForURL(`**/vuln-repo/org-cves/${firstCve}/assets`, { timeout: 10000 }).catch(() => null);
    check(tag('overview card opens dedicated assets route'), new URL(page.url()).pathname === `/vuln-repo/org-cves/${firstCve}/assets`, here(page));
    await settle(page);
    await shot(page, `cve-assets_${theme}`);
  } else {
    check(tag('overview Create Findings card visible'), false, 'card not shown');
  }
  await page.goto(`${base}/vuln-repo/org-cves/${firstCve}/software`, { waitUntil: 'networkidle' });
  check(tag('dedicated software route renders'), new URL(page.url()).pathname === `/vuln-repo/org-cves/${firstCve}/software` && errors.length === 0);
  // Intel detail is platform-scoped: a tenant user is denied in place rather than crashing.
  await page.goto(`${base}/vuln-repo/intel/${firstCve}`, { waitUntil: 'networkidle' });
  await page.getByText('Forbidden', { exact: true }).first().waitFor({ timeout: 15000 }).catch(() => null);
  check(tag('platform-scoped intel detail denies tenant user in place'), await visible(page.getByText('Forbidden', { exact: true })) && errors.length === 0, here(page));

  // The ServiceNow 503 is the intended "not configured" ticket failure exercised above.
  const unexpected = failures.filter((failure) => !/\/servicenow-incident$/.test(failure));
  check(tag('no unexpected 5xx API responses'), unexpected.length === 0, unexpected.join(' | '));
  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();
}

async function inventoryJourney(theme) {
  const tag = (name) => `inventory: ${name} [${theme}]`;
  const { context, page, requests, failures, errors } = await signedInPage(theme);
  await page.goto(`${base}/inventory`, { waitUntil: 'networkidle' });
  check(tag('overview renders lifecycle breakdown'), await visible(page.getByText('Lifecycle breakdown')));

  await page.goto(`${base}/inventory/hosts`, { waitUntil: 'networkidle' });
  const hostRows = page.locator('.inventory-table tbody tr');
  await hostRows.first().waitFor({ timeout: 15000 });
  const hosts = await hostRows.count();
  check(tag('hosts list renders'), hosts > 0, String(hosts));
  const hostButton = hostRows.first().getByRole('button').first();
  const hostName = (await hostButton.innerText()).trim();
  await page.getByPlaceholder('hostname, OS, software...').fill(hostName);
  await settle(page);
  check(tag('host search narrows'), (await hostRows.count()) >= 1 && (await hostRows.count()) <= hosts, String(await hostRows.count()));
  await page.getByPlaceholder('hostname, OS, software...').fill('');
  await settle(page);
  await page.getByRole('button', { name: hostName, exact: true }).first().click();
  await page.waitForURL(/\/inventory\/hosts\/[^/?]+\?returnTo=/, { timeout: 10000 }).catch(() => null);
  check(tag('host opens detail with returnTo'), new URL(page.url()).searchParams.get('returnTo') === '/inventory/hosts', here(page));
  await settle(page);
  await shot(page, `host-detail_${theme}`);
  const cvesTab = page.getByText('Applicable CVEs').first();
  if (await visible(cvesTab)) {
    await cvesTab.click();
    check(tag('host tabs switch'), await visible(page.locator('.fd3-tab--active', { hasText: 'Applicable CVEs' })));
  }
  await page.getByLabel('Close host detail').click();
  await page.waitForURL(/\/inventory\/hosts$/, { timeout: 10000 }).catch(() => null);
  check(tag('close returns to hosts'), here(page) === '/inventory/hosts', here(page));

  requests.length = 0;
  await page.goto(`${base}/inventory/software-identities?lifecycle=eol`, { waitUntil: 'networkidle' });
  const eol = calls(requests, '/inventory/software-identities').at(-1);
  check(tag('lifecycle facet serialised'), eol && new URL(eol.url()).searchParams.get('lifecycle') === 'eol', eol?.url());
  const eolRows = await page.locator('tr.si-identity-row').count();
  await page.goto(`${base}/inventory/software-identities`, { waitUntil: 'networkidle' });
  const identityRows = page.locator('tr.si-identity-row');
  await identityRows.first().waitFor({ timeout: 15000 });
  const identities = await identityRows.count();
  check(tag('lifecycle facet narrows identities'), eolRows <= identities, `${eolRows} <= ${identities}`);
  requests.length = 0;
  await identityRows.first().click();
  await page.locator('tr.si-version-row').first().waitFor({ timeout: 10000 }).catch(() => null);
  check(tag('row expands versions'), (await page.locator('tr.si-version-row').count()) > 0);
  check(tag('expansion fetches identity detail once'), requests.filter((request) => /^\/inventory\/software-identities\/[^/]+$/.test(apiPath(request.url()))).length === 1);
  await identityRows.first().locator('button').first().click();
  await page.waitForURL(/\/inventory\/software-identities\/[^/]+/, { timeout: 10000 }).catch(() => null);
  check(tag('identity opens detail'), /^\/inventory\/software-identities\/[^/]+$/.test(new URL(page.url()).pathname), here(page));
  await page.getByRole('tablist', { name: 'Software identity sections' }).waitFor({ timeout: 15000 }).catch(() => null);
  check(tag('identity detail shows sections'), await visible(page.getByRole('tablist', { name: 'Software identity sections' })), here(page));
  await shot(page, `software-identity_${theme}`);
  await page.getByRole('button', { name: '← Back to Software Entities' }).click();
  check(tag('back returns to identities'), new URL(page.url()).pathname === '/inventory/software-identities', here(page));

  await page.goto(`${base}/inventory/ai`, { waitUntil: 'networkidle' });
  check(tag('AI inventory renders for entitled tenant'), new URL(page.url()).pathname === '/inventory/ai');
  await page.goto(`${base}/inventory/ai/declared-resources`, { waitUntil: 'networkidle' });
  await settle(page);
  await shot(page, `declared-resources_${theme}`);
  const declared = page.locator('table tbody tr').filter({ hasNot: page.getByText(/No .*found/i) });
  if (await declared.count()) {
    await declared.first().locator('button, a').first().click();
    await page.waitForURL(/\/inventory\/ai\/declared-resources\/[^/]+/, { timeout: 10000 }).catch(() => null);
    check(tag('declared resource opens detail'), /\/inventory\/ai\/declared-resources\/[^/]+$/.test(new URL(page.url()).pathname), here(page));
    await settle(page);
    await shot(page, `declared-resource-detail_${theme}`);
    const history = page.getByRole('button', { name: 'Retired history' });
    if (await visible(history)) {
      requests.length = 0;
      await history.click();
      await settle(page);
      const call = requests.find((request) => /\/bom\/declared-resources\/[^/]+\/correlation$/.test(apiPath(request.url())));
      check(tag('retired history requests history=true'), call && new URL(call.url()).searchParams.get('history') === 'true', call?.url());
    }
    await page.getByRole('button', { name: 'Back to declared resources' }).click();
    check(tag('back returns to declared resources'), new URL(page.url()).pathname === '/inventory/ai/declared-resources', here(page));
  } else {
    skip(tag('declared resource detail / retired history'), 'no declared resources projected in this tenant (fixture journey covers it)');
  }
  check(tag('no 5xx API responses'), failures.length === 0, failures.join(' | '));
  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();
}

async function authorityJourney(theme) {
  const tag = (name) => `authority: ${name} [${theme}]`;
  // Tenant admin: tenant controls, no platform controls.
  const tenant = await signedInPage(theme);
  const { page, requests } = tenant;
  await page.goto(`${base}/policies`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('tenant policies route renders'), new URL(page.url()).pathname === '/policies' && await visible(page.getByText('Framework risk coverage')));
  await shot(page, `policies_${theme}`);
  await page.goto(`${base}/admin/users`, { waitUntil: 'networkidle' });
  const memberRows = page.locator('.um-table-scroll .data-table tbody tr');
  await memberRows.first().waitFor({ timeout: 15000 });
  check(tag('admin lists tenant members incl. the signed-in owner'), await visible(memberRows.filter({ hasText: tenantCredentials.email })), String(await memberRows.count()));
  check(tag('members load for the actor tenant only'), requests.some((request) => /^\/tenants\/[0-9a-f-]+\/members$/.test(apiPath(request.url()))));
  await page.getByRole('button', { name: 'Invite user' }).click();
  const invite = page.locator('.um-modal');
  await invite.waitFor();
  check(tag('invite form offers only customer roles'), !(await invite.innerText()).match(/PLATFORM_OWNER|SERVICE_ACCOUNT/));
  await invite.getByRole('button', { name: /Cancel|Close/ }).first().click().catch(() => page.keyboard.press('Escape'));
  for (const [view, text] of [['invites', 'Pending Invitations'], ['roles', 'Role Model'], ['service-accounts', 'Service Accounts'], ['audit', 'Audit']]) {
    await page.goto(`${base}/admin/${view}`, { waitUntil: 'networkidle' });
    check(tag(`/admin/${view} renders`), await visible(page.getByRole('heading', { name: new RegExp(text) })));
  }
  await page.goto(`${base}/platform/tenants`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('tenant admin is denied the platform console'), await visible(page.getByText('Platform console access requires the Platform Owner role.')));
  await page.goto(`${base}/authorized-workspaces`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('tenant admin redirected from /authorized-workspaces'), new URL(page.url()).pathname !== '/authorized-workspaces', here(page));
  check(tag('tenant: no 5xx'), tenant.failures.length === 0, tenant.failures.join(' | '));
  check(tag('tenant: no page errors'), tenant.errors.length === 0, tenant.errors.join(' | '));
  await tenant.context.close();

  if (!platformCredentials) return;
  // Platform owner: platform scope, tenant routes require selection, lifecycle with confirmation.
  const platform = await signedInPage(theme, 1440, platformCredentials);
  const pp = platform.page;
  check(tag('platform owner lands on platform console'), new URL(pp.url()).pathname.startsWith('/platform'), here(pp));
  await pp.goto(`${base}/findings`, { waitUntil: 'networkidle' });
  await settle(pp);
  check(tag('platform scope redirects tenant routes'), new URL(pp.url()).pathname === '/platform/tenants', here(pp));
  await pp.goto(`${base}/platform/tenants`, { waitUntil: 'networkidle' });
  await pp.getByText('UI2 Qual Disposable 2').first().waitFor({ timeout: 15000 });
  check(tag('tenant lifecycle lists the disposable tenant'), await visible(pp.getByText('UI2 Qual Disposable 2')));
  await shot(pp, `platform-tenants_${theme}`);
  const slug = `ui2-qual-live-${theme}-${Date.now().toString(36)}`;
  platform.requests.length = 0;
  await pp.getByLabel('Tenant name').fill(`UI2 Qual Live ${slug.slice(-6)}`);
  await pp.getByLabel('Tenant slug').fill(slug);
  await pp.getByRole('button', { name: 'Create Tenant' }).click();
  await settle(pp);
  const created = calls(platform.requests, '/platform/tenants', 'POST').at(-1);
  check(tag('create tenant posts and is accepted (async PROVISIONING)'), bodyOf(created)?.slug === slug && (await statusOf(created)) === 202, `${await statusOf(created)} ${created?.postData()}`);
  await pp.getByLabel('Tenant name').fill('Duplicate');
  await pp.getByLabel('Tenant slug').fill(slug);
  await pp.getByRole('button', { name: 'Create Tenant' }).click();
  await pp.getByRole('alert').first().waitFor({ timeout: 10000 }).catch(() => null);
  const conflict = await pp.getByRole('alert').first().innerText().catch(() => '');
  check(tag('slug conflict surfaces the server message'), /already in use|conflict/i.test(conflict), conflict);

  // Lifecycle restriction with confirmation, on the dedicated ACTIVE disposable lifecycle tenant; restored afterwards.
  await pp.reload({ waitUntil: 'networkidle' });
  const row = () => pp.locator('.section-block .table-scroll').first().locator('tbody tr', { hasText: 'UI2 Qual Lifecycle' });
  const block = row().getByRole('button', { name: 'Block access' });
  if (await visible(block)) {
    platform.requests.length = 0;
    await block.click();
    const dialog = pp.locator('dialog.confirm-dialog');
    await dialog.waitFor();
    check(tag('block access asks for confirmation'), /block all tenant users/i.test(await dialog.innerText()), await dialog.innerText());
    await dialog.getByRole('button', { name: 'Block Access' }).click();
    await settle(pp);
    const patch = platform.requests.find((request) => /\/platform\/tenants\/[^/]+\/status$/.test(apiPath(request.url())) && request.method() === 'PATCH');
    check(tag('confirm sends SUSPENDED'), bodyOf(patch)?.status === 'SUSPENDED' && (await statusOf(patch)) < 300, `${await statusOf(patch)} ${patch?.postData()}`);
    const restore = row().getByRole('button', { name: /Restore|Unblock|Reactivate/ });
    await restore.first().waitFor({ timeout: 10000 }).catch(() => null);
    if (await visible(restore)) {
      platform.requests.length = 0;
      await restore.first().click();
      const confirm = pp.locator('dialog.confirm-dialog');
      if (await visible(confirm)) await confirm.getByRole('button').filter({ hasNotText: /Cancel/ }).last().click();
      await settle(pp);
      const back = platform.requests.find((request) => /\/platform\/tenants\/[^/]+\/status$/.test(apiPath(request.url())) && request.method() === 'PATCH');
      check(tag('restore sends ACTIVE'), bodyOf(back)?.status === 'ACTIVE' && (await statusOf(back)) < 300, `${await statusOf(back)} ${back?.postData()}`);
    } else {
      check(tag('suspended tenant offers restore'), false, 'no restore control');
    }
  } else {
    skip(tag('block access with confirmation'), 'no ACTIVE "UI2 Qual Lifecycle" tenant row');
  }
  await pp.goto(`${base}/platform/ai-policies`, { waitUntil: 'networkidle' });
  await settle(pp);
  check(tag('platform AI policy studio renders'), new URL(pp.url()).pathname === '/platform/ai-policies' && platform.errors.length === 0);
  await shot(pp, `platform-ai-policies_${theme}`);
  check(tag('platform: no 5xx'), platform.failures.length === 0, platform.failures.join(' | '));
  check(tag('platform: no page errors'), platform.errors.length === 0, platform.errors.join(' | '));
  await platform.context.close();
}

async function connectJourney(theme) {
  const tag = (name) => `connect: ${name} [${theme}]`;
  const { context, page, requests, failures, errors } = await signedInPage(theme);
  const card = (name) => page.locator('.connect-source-card', { has: page.locator('.connect-source-name', { hasText: new RegExp(`^${name}$`) }) });
  await page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await page.locator('.connect-source-card').first().waitFor({ timeout: 15000 });
  check(tag('catalog renders connector cards'), (await page.locator('.connect-source-card').count()) >= 5, String(await page.locator('.connect-source-card').count()));
  check(tag('no patch-management cards'), (await page.getByText(/BigFix|Tanium|Patch Management/i).count()) === 0);
  await shot(page, `connect_${theme}`);

  await card('ServiceNow').click();
  await page.getByRole('button', { name: 'Save Connector' }).waitFor({ timeout: 10000 });
  check(tag('card opens ?connectSource=servicenow-cmdb'), here(page) === '/connect?connectSource=servicenow-cmdb', here(page));
  const baseUrl = page.getByLabel(/ServiceNow Base URL/);
  await baseUrl.fill('not a url');
  requests.length = 0;
  await page.getByRole('button', { name: 'Save Connector' }).click();
  await page.locator('.notice.error').first().waitFor({ timeout: 10000 }).catch(() => null);
  const invalid = calls(requests, '/connectors/servicenow-cmdb', 'PUT').at(-1);
  check(tag('invalid base URL rejected with a validation message'), (await page.locator('.notice.error').count()) > 0, invalid ? `${await statusOf(invalid)}` : 'no PUT (client-side validation)');
  check(tag('form keeps the rejected value'), (await baseUrl.inputValue()) === 'not a url');
  check(tag('save payload carries no blank secret'), !invalid || !('credentialSecret' in (bodyOf(invalid) ?? {})), invalid?.postData());
  await shot(page, `servicenow-invalid_${theme}`);
  // A reserved host passes client checks but the server's SSRF guard rejects it: the message must reach the user.
  await baseUrl.fill('https://cmdb.example.test');
  requests.length = 0;
  await page.getByRole('button', { name: 'Save Connector' }).click();
  await page.locator('.notice.error').first().waitFor({ timeout: 10000 }).catch(() => null);
  const guarded = calls(requests, '/connectors/servicenow-cmdb', 'PUT').at(-1);
  const guardText = await page.locator('.notice.error').first().innerText().catch(() => '');
  check(tag('server-side endpoint guard rejects non-public host and is shown'), (await statusOf(guarded)) === 400 && /approved public HTTPS endpoint|required/i.test(guardText), `${await statusOf(guarded)} ${guardText}`);
  await shot(page, `servicenow-guard_${theme}`);
  skip(tag('successful save / test connection / sync run'), 'needs a real public ServiceNow endpoint (outbound delivery not exercised); fixture journey covers save/test/failure/retry');
  await page.keyboard.press('Escape');
  await settle(page);
  check(tag('Escape returns to catalog'), here(page) === '/connect', here(page));

  await page.goto(`${base}/connect?connectSource=sccm-cmdb`, { waitUntil: 'networkidle' });
  check(tag('SCCM stays contained'), await visible(page.getByText('SCCM live JDBC is disabled', { exact: false })));
  await page.goto(`${base}/connect?connectSource=sccm-patch&keep=1`, { waitUntil: 'networkidle' });
  check(tag('retired patch connector id is dropped'), here(page) === '/connect?keep=1', here(page));
  await page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await page.locator('.connect-filter-btn', { hasText: 'Run History' }).click();
  await page.getByText('Inventory Run Queue').waitFor({ timeout: 10000 });
  check(tag('run history route'), here(page) === '/connect/run-history', here(page));
  requests.length = 0;
  await page.getByRole('button', { name: 'Refresh Queue' }).click();
  await settle(page);
  check(tag('refresh refetches runs'), calls(requests, '/sync-runs').length >= 1);
  await shot(page, `run-history_${theme}`);

  // Existing settings: SLA threshold save then restore the original value.
  await page.goto(`${base}/configurations/sla`, { waitUntil: 'networkidle' });
  await page.getByText('Critical Risk').waitFor({ timeout: 10000 });
  const saveButton = page.locator('.config-content').getByRole('button', { name: 'Save' });
  const loadedErrors = await page.locator('.config-content').getByText(/must be between/).allInnerTexts();
  if (await saveButton.isDisabled()) {
    // Known pre-existing defect: the demo dataset seeds thresholds on a 0-100 scale; the page validates 0-10.
    check(tag('SLA settings load valid and saveable'), false, `Save disabled on load: ${loadedErrors.join(' ')}`);
  } else {
    const threshold = page.locator('.config-content input').first();
    const original = await threshold.inputValue();
    const changed = String(Number(original) === 8.5 ? 8.6 : 8.5);
    await threshold.fill(changed);
    requests.length = 0;
    await saveButton.click();
    await settle(page);
    const saved = requests.filter((request) => apiPath(request.url()) === '/risk-policy' && request.method() !== 'GET').at(-1);
    check(tag('SLA save persists criticalThreshold'), bodyOf(saved)?.criticalThreshold === Number(changed) && (await statusOf(saved)) < 300, `${await statusOf(saved)} ${saved?.postData()?.slice(0, 120)}`);
    await page.reload({ waitUntil: 'networkidle' });
    await page.getByText('Critical Risk').waitFor();
    check(tag('SLA value survives reload'), (await page.locator('.config-content input').first().inputValue()) === changed, await page.locator('.config-content input').first().inputValue());
    await page.locator('.config-content input').first().fill(original);
    await saveButton.click();
    await settle(page);
  }
  for (const [view, marker] of [['ownership', /Ownership/], ['suppress', /Suppression/], ['automation', /Auto-close|Automation/], ['triage', /Prioritization|Triage/]]) {
    await page.goto(`${base}/configurations/${view}`, { waitUntil: 'networkidle' });
    check(tag(`/configurations/${view} renders`), await visible(page.locator('.config-content').getByText(marker)));
  }
  check(tag('no 5xx API responses'), failures.length === 0, failures.join(' | '));
  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();
}

const runners = { findings: findingsJourney, ai: aiFindingsJourney, cve: cveJourney, inventory: inventoryJourney, authority: authorityJourney, connect: connectJourney };
for (const theme of themes) {
  for (const [name, run] of Object.entries(runners)) {
    if (!journeys.has(name)) continue;
    // A thrown step ends that journey only; it is recorded as a failed check, not swallowed.
    await run(theme).catch((error) => check(`${name}: journey completed [${theme}]`, false,
      error.message.split('\n').filter((line) => /locator|Timeout|Error/.test(line)).slice(0, 3).join(' ')));
  }
}

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
const skipped = results.filter((result) => result.skipped);
console.log(`${results.length - failed.length - skipped.length}/${results.length - skipped.length} checks passed, ${skipped.length} skipped`);
skipped.forEach((result) => console.log(`SKIP ${result.name} ${result.detail}`));
failed.forEach((result) => console.log(`FAIL ${result.name} ${result.detail}`));
process.exitCode = failed.length ? 1 : 0;
