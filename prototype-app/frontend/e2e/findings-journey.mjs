#!/usr/bin/env node
// UI 2.0 P2 — Findings family browser journey (plan "Minimum critical browser journeys" 1 and 2).
//
// Runs the same deterministic journey against any build (legacy or UI 2.0) so behaviour can be
// compared, records request URLs to verify scope/serialisation, and saves screenshots.
// Fixture-backed only: this is NOT authenticated staging evidence.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node findings-journey.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext } from './browser.mjs';
import { unexpectedFailures } from './known-failures.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';

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
  results.push({ name, ok: Boolean(ok), detail });
}

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});

async function newPage(theme, width, actorOverride = actor) {
  const context = await newContext(browser, { viewport: { width, height: 1000 } });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  const requests = [];
  await routeFixtures(context, { actorOverride, onRequest: (request) => requests.push(request.url()) });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  return { context, page, requests, errors };
}

const apiPath = (url) => new URL(url).pathname.replace(/^\/api/, '');
const lastRequest = (requests, pathname) => [...requests].reverse().map((url) => new URL(url)).find((url) => apiPath(url.href) === pathname);
// AI pages fade in (ai-security-reveal, 360ms); wait so captures are not taken mid-animation.
const shot = async (page, name) => {
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(out, `${label}_${name}.png`), fullPage: true });
};
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
/** Runs `action` and resolves with the next request to `pathname` it causes. */
async function requestFrom(page, pathname, action) {
  const pending = page.waitForRequest((request) => apiPath(request.url()) === pathname, { timeout: 8000 }).catch(() => null);
  await action();
  const request = await pending;
  await page.waitForTimeout(400);
  return request ? new URL(request.url()) : null;
}

for (const theme of themes) {
  const tag = (name) => `${name}_${theme}`;
  const { context, page, requests, errors } = await newPage(theme, 1440);

  // ── Vulnerability Findings list ────────────────────────────────────────────
  await page.goto(`${base}/findings`, { waitUntil: 'networkidle' });
  await page.locator('.fpl-tr').first().waitFor();
  check(tag('list renders 25 rows (cursor page size)'), (await page.locator('.fpl-tr').count()) === 25);
  const pagerText = () => page.getByRole('navigation', { name: 'Findings pages' }).innerText();
  const scopeText = () => page.locator('.fpl-list-bar .queue-result-scope').innerText();
  check(tag('list page info'), /Page 1 of 3/.test(await pagerText()) && /Showing 1–25 of 62 findings/.test(await scopeText()), `${await pagerText()} | ${await scopeText()}`);
  await shot(page, tag('findings-list'));

  // Severity widget narrows the table only; aggregates keep queue scope.
  requests.length = 0;
  const narrowed = await requestFrom(page, '/findings', () => page.locator('.fpl-legend-row', { hasText: 'CRITICAL' }).first().click());
  check(tag('severity widget sends severity=CRITICAL'), narrowed?.searchParams.getAll('severity').join() === 'CRITICAL', narrowed?.search);
  const aggregates = requests.filter((url) => /\/findings\/(summary|distributions|backlog-health)/.test(url));
  check(tag('aggregates not re-requested with severity'), aggregates.every((url) => !new URL(url).searchParams.has('severity')), aggregates.map((url) => new URL(url).search).join(' | '));
  check(tag('severity widget marks legend active'), await page.locator('.fpl-legend-row--active', { hasText: 'CRITICAL' }).count() === 1);
  check(tag('severity widget marks widget active'), await page.locator('.fpl-widget--active').count() >= 1);
  await shot(page, tag('findings-widget-active'));
  // The unfiltered page is usually served from the query cache, so assert visible state, not a request.
  await page.locator('.fpl-legend-row', { hasText: 'CRITICAL' }).first().click();
  await page.waitForTimeout(600);
  check(tag('same severity again toggles off'), await page.locator('.fpl-legend-row--active').count() === 0 && /of 62 findings/.test(await scopeText()));

  // Column multi-select filter popover (Status), two values accumulate.
  await page.waitForTimeout(500);
  const popover = page.locator('.fpl-col-filter-popover');
  await page.locator('.fpl-th', { hasText: 'Status' }).locator('.fpl-filter-btn').click();
  if (!(await popover.isVisible())) await page.locator('.fpl-th', { hasText: 'Status' }).locator('.fpl-filter-btn').click();
  await popover.waitFor();
  await requestFrom(page, '/findings', () => popover.locator('.fpl-col-filter-check', { hasText: /^\s*Open\s*$/i }).first().click());
  const statusRequest = await requestFrom(page, '/findings', () => popover.locator('.fpl-col-filter-check', { hasText: /Resolved/i }).first().click());
  check(tag('status column values accumulate'), statusRequest?.searchParams.getAll('status').sort().join() === 'OPEN,RESOLVED', statusRequest?.search);
  await shot(page, tag('findings-column-filter'));
  await page.keyboard.press('Escape');
  await page.mouse.click(1300, 40);
  const chips = page.getByRole('group', { name: 'Active filters' });
  check(tag('filter chip shown'), (await chips.locator('.queue-filter-chip').count()) >= 1);
  await requestFrom(page, '/findings', () => chips.getByRole('button', { name: 'Clear filters' }).click());

  // Cursor paging next/back.
  const nextRequest = await requestFrom(page, '/findings', () => page.getByRole('button', { name: 'Next' }).click());
  check(tag('next page sends cursor'), nextRequest?.searchParams.get('cursor') === 'c1', nextRequest?.search);
  check(tag('page 2 info'), /Page 2 of 3/.test(await pagerText()) && /Showing 26–50 of 62/.test(await scopeText()));
  await page.getByRole('button', { name: 'Previous' }).click();
  await page.waitForTimeout(600);
  check(tag('prev returns to page 1'), /Page 1 of 3/.test(await pagerText()));

  // Row click selects (does not navigate).
  const firstRow = page.locator('.fpl-tr').first();
  await firstRow.locator('td').nth(3).click();
  check(tag('row click selects'), (await firstRow.getAttribute('class')).includes('fpl-tr--selected'));
  check(tag('row click stays on list'), new URL(page.url()).pathname === '/findings');
  check(tag('selected badge'), (await scopeText()).includes('1 selected on this page'));
  await shot(page, tag('findings-selected'));

  // Group by severity: server group aggregates.
  await page.locator('.multi-groupby-trigger').first().click();
  const groupRequest = await requestFrom(page, '/findings/groups', () => page.locator('.multi-groupby-option', { hasText: 'Severity' }).first().click());
  check(tag('group-by requests server groups'), groupRequest?.searchParams.get('field') === 'severity', groupRequest?.search);
  await page.locator('.fpl-group-item').first().waitFor({ timeout: 5000 }).catch(() => null);
  check(tag('group cards render'), (await page.locator('.fpl-group-item').count()) > 0);
  check(tag('group aggregates carry no ad-hoc table filters'), groupRequest && !groupRequest.searchParams.has('severity') && !groupRequest.searchParams.has('cursor'), groupRequest?.search);
  await shot(page, tag('findings-grouped'));

  // Finding ID link opens detail with router state; back returns.
  const findingId = (await page.locator('.finding-id-link').first().innerText()).trim();
  await page.locator('.finding-id-link').first().click();
  await page.locator('.fd3-topbar').waitFor();
  check(tag('finding link opens detail'), new URL(page.url()).pathname === `/findings/${findingId}`);
  await page.waitForLoadState('networkidle');
  await shot(page, tag('finding-detail'));
  await page.locator('.fd3-tab', { hasText: 'Affected Assets' }).click();
  await shot(page, tag('finding-detail-assets'));
  await page.locator('.fd3-back-btn').click();
  await page.locator('.fpl-tr').first().waitFor();
  check(tag('back returns to findings'), new URL(page.url()).pathname === '/findings');

  // ── AI Findings ────────────────────────────────────────────────────────────
  requests.length = 0;
  await page.goto(`${base}/findings/ai`, { waitUntil: 'networkidle' });
  check(tag('ai list default OPEN'), lastRequest(requests, '/ai-security/findings')?.searchParams.get('status') === 'OPEN');
  await shot(page, tag('ai-findings'));
  const providerRequest = await requestFrom(page, '/ai-security/findings', () => page.getByLabel('Cloud provider').selectOption('AWS'));
  check(tag('ai provider sent'), providerRequest?.searchParams.get('provider') === 'AWS' && providerRequest?.searchParams.get('status') === 'OPEN', providerRequest?.search);
  await page.getByLabel('Cloud provider').selectOption('');
  await page.waitForTimeout(600);
  await page.locator('.ai-security-table-panel').nth(1).locator('tbody tr').first().click();
  await page.locator('.fd3-topbar').waitFor();
  const aiDetailUrl = new URL(page.url());
  check(tag('ai row navigates to detail with returnTo'), aiDetailUrl.pathname.startsWith('/findings/ai/') && aiDetailUrl.searchParams.get('returnTo') === '/findings/ai', aiDetailUrl.href.replace(base, ''));
  await page.waitForLoadState('networkidle');
  await shot(page, tag('ai-finding-detail'));
  await page.locator('.fd3-back-btn').click();
  await page.waitForURL(`${base}/findings/ai`);
  check(tag('ai detail back returns'), new URL(page.url()).pathname === '/findings/ai');

  const vulnRequest = await requestFrom(page, '/findings', () => page.getByRole('button', { name: 'Software Vulnerabilities' }).click());
  check(tag('ai vulnerabilities scope'), vulnRequest?.searchParams.getAll('findingKind').join() === 'VULNERABILITY' && vulnRequest?.searchParams.get('hasAffectedAiResource') === 'true' && vulnRequest?.searchParams.get('status') === 'OPEN', vulnRequest?.search);
  await shot(page, tag('ai-vulnerabilities'));
  const vulnAll = await requestFrom(page, '/findings', () => page.getByLabel('Finding status').selectOption(''));
  check(tag('ai vulnerabilities keeps scope on status change'), vulnAll?.searchParams.getAll('findingKind').join() === 'VULNERABILITY' && vulnAll?.searchParams.get('hasAffectedAiResource') === 'true' && !vulnAll?.searchParams.has('status'), vulnAll?.search);

  await page.goto(`${base}/findings/ai/exposures`, { waitUntil: 'networkidle' });
  await shot(page, tag('ai-exposures'));
  await page.locator('.ai-security-table-panel tbody tr').first().getByRole('link').click();
  await page.waitForURL(/\/findings\/ai\/exposures\/exposure-1$/, { timeout: 5000 }).catch(() => null);
  await page.locator('.ai-exposure-grid').waitFor({ timeout: 5000 }).catch(() => null);
  check(tag('exposure row opens detail'), new URL(page.url()).pathname === '/findings/ai/exposures/exposure-1' && await page.locator('.ai-exposure-grid').count() === 1);
  await shot(page, tag('ai-exposure-detail'));

  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();

  // ── Narrow viewport overflow ───────────────────────────────────────────────
  const narrow = await newPage(theme, 390);
  for (const route of ['/findings', '/findings/ai', '/findings/ai/vulnerabilities', '/findings/ai/exposures', '/findings/ai/exposures/exposure-1']) {
    await narrow.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
    await narrow.page.waitForTimeout(300);
    check(tag(`390px no page overflow ${route}`), !(await overflow(narrow.page)));
    await narrow.page.screenshot({ path: path.join(out, `${label}_${route.replace(/\W+/g, '-').replace(/^-|-$/g, '')}_${theme}_390.png`) });
  }
  await narrow.context.close();
}

// ── Entitlement unavailable ──────────────────────────────────────────────────
const denied = await newPage('dark', 1440, { ...actor, entitlements: { 'ai.security': false } });
await denied.page.goto(`${base}/findings/ai`, { waitUntil: 'networkidle' });
const redirected = await denied.page.waitForURL((url) => url.pathname === '/exposure', { timeout: 10000 }).then(() => true, () => false);
check('ai findings redirect without entitlement', redirected, denied.page.url().replace(base, ''));
await denied.context.close();

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
console.log(`${results.length - failed.length}/${results.length} checks passed`);
failed.forEach((result) => console.log(`FAIL ${result.name} ${result.detail}`));
process.exitCode = unexpectedFailures(results).length ? 1 : 0;
failOnUnexpectedApi();
