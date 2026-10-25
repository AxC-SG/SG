#!/usr/bin/env node
// UI 2.0 P6 — Connectors and configuration browser journey (plan "Minimum critical browser
// journeys" 6: supported provider form → validation → test/save → sync/run failure/retry →
// existing risk/SLA/ownership/suppression settings), plus contained-connector and platform
// vulnerability-intelligence checks.
//
// Runs the same deterministic journey against any build (legacy or UI 2.0) so behaviour can be
// compared, records request URLs and bodies to verify serialisation, and saves screenshots.
// Fixture-backed only: this is NOT authenticated staging evidence, and no write is persisted.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node connect-journey.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { actor, routeFixtures } from './fixtures.mjs';
import { platformActor } from './governance-fixtures.mjs';
import {
  AWS_TARGET_FAILURE_MESSAGE,
  CORRELATION_DISABLED_SOURCES,
  FAILING_AWS_TARGET_ID,
  SERVICENOW_INVALID_BASE_URL,
  SERVICENOW_VALIDATION_FIELD_MESSAGE,
  SUPPRESSION_RULE_IDS,
} from './connect-fixtures.mjs';

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

async function newPage(theme, width, actorOverride = actor) {
  const context = await browser.newContext({ viewport: { width, height: 1000 } });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  const requests = [];
  await routeFixtures(context, {
    actorOverride,
    onRequest: (request) => requests.push({ url: request.url(), method: request.method(), body: request.postData() }),
  });
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
const card = (page, name) => page.locator('.connect-source-card', { has: page.locator('.connect-source-name', { hasText: new RegExp(`^${name}$`) }) });

for (const theme of themes) {
  const tag = (name) => `${name}_${theme}`;

  // ── Catalog: sections, health dots, accordion ──────────────────────────
  const tenant = await newPage(theme, 1440);
  const { page, requests, errors } = tenant;
  await page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await page.locator('.connect-source-card').first().waitFor();
  await settle(page);
  check(tag('catalog renders 10 connector cards'), (await page.locator('.connect-source-card').count()) === 10, String(await page.locator('.connect-source-card').count()));
  check(tag('inventory then BOM sections'), (await page.locator('.connect-source-section-head h4').allTextContents()).join('|') === 'Inventory|BOM Management');
  const dot = (name) => card(page, name).locator('.connect-source-dot');
  check(tag('ServiceNow dot reports last sync'), /^Last sync · /.test(await dot('ServiceNow').getAttribute('aria-label') ?? ''), await dot('ServiceNow').getAttribute('aria-label'));
  check(tag('SCCM dot reports failure'), /^Last sync failed/.test(await dot('SCCM\\/MECM').getAttribute('aria-label') ?? ''), await dot('SCCM\\/MECM').getAttribute('aria-label'));
  check(tag('Azure dot reports not configured'), (await dot('Azure').getAttribute('aria-label')) === 'Not configured');
  check(tag('dot classes carry health'), (await dot('SCCM\\/MECM').getAttribute('class')).includes('connect-source-dot--fail')
    && (await dot('ServiceNow').getAttribute('class')).includes('connect-source-dot--ok'));
  check(tag('no patch-management cards'), (await page.getByText(/BigFix|Tanium|Patch/i).count()) === 0);
  check(tag('vulnerability intelligence accordion expanded'), (await page.locator('.config-accordion-toggle').getAttribute('aria-expanded')) === 'true');
  const sourceSwitches = page.getByRole('switch');
  check(tag('9 tenant source switches'), (await sourceSwitches.count()) === 9, String(await sourceSwitches.count()));
  const disabledSources = await page.locator('button[role="switch"][aria-checked="false"]').count();
  check(tag('correlation-disabled sources render Disabled'), disabledSources === CORRELATION_DISABLED_SOURCES.length, String(disabledSources));
  await shot(page, tag('catalog'));

  requests.length = 0;
  await page.getByRole('switch', { name: 'NVD source' }).click();
  await settle(page);
  const nvdSave = calls(requests, '/connectors/vulnerability-sources/nvd', 'PUT').at(-1);
  check(tag('NVD switch sends enabledForCorrelation false'), nvdSave && body(nvdSave).enabledForCorrelation === false, nvdSave?.body);

  await page.locator('.config-accordion-toggle').click();
  check(tag('accordion collapses'), (await page.locator('.config-accordion-toggle').getAttribute('aria-expanded')) === 'false'
    && (await page.getByRole('switch').count()) === 0);
  await page.locator('.config-accordion-toggle').click();

  // ── ServiceNow: validation failure retains values, then save payload ─────
  await card(page, 'ServiceNow').click();
  await page.getByRole('button', { name: 'Save Connector' }).waitFor();
  check(tag('card opens ?connectSource=servicenow-cmdb'), here(page) === '/connect?connectSource=servicenow-cmdb', here(page));
  await shot(page, tag('servicenow'));
  const baseUrl = page.getByLabel(/ServiceNow Base URL/);
  await baseUrl.fill(SERVICENOW_INVALID_BASE_URL);
  requests.length = 0;
  await page.getByRole('button', { name: 'Save Connector' }).click();
  await page.locator('.notice.error').first().waitFor();
  const invalidSave = calls(requests, '/connectors/servicenow-cmdb', 'PUT').at(-1);
  check(tag('invalid save sends the typed baseUrl'), invalidSave && body(invalidSave).baseUrl === SERVICENOW_INVALID_BASE_URL, invalidSave?.body);
  check(tag('validation message shown'), (await page.locator('.notice.error').first().textContent()).includes(SERVICENOW_VALIDATION_FIELD_MESSAGE), await page.locator('.notice.error').first().textContent());
  check(tag('form keeps the rejected value'), (await baseUrl.inputValue()) === SERVICENOW_INVALID_BASE_URL);
  check(tag('save payload carries no blank secret'), invalidSave && !('credentialSecret' in (body(invalidSave) ?? {})), invalidSave?.body);
  await shot(page, tag('servicenow-validation'));
  await baseUrl.fill('https://cmdb.example.test');
  requests.length = 0;
  await page.getByRole('button', { name: 'Save Connector' }).click();
  await settle(page);
  const validSave = calls(requests, '/connectors/servicenow-cmdb', 'PUT').at(-1);
  check(tag('valid save succeeds without error'), validSave && (await page.locator('.notice.error').count()) === 0, validSave?.body);
  requests.length = 0;
  await page.getByRole('button', { name: 'Test Connection' }).click();
  await settle(page);
  check(tag('test connection posts'), calls(requests, '/connectors/servicenow-cmdb/test', 'POST').length === 1);
  await page.keyboard.press('Escape');
  await settle(page);
  check(tag('Escape returns to catalog'), here(page) === '/connect' && (await page.locator('.connect-source-card').count()) === 10, here(page));

  // ── AWS: multi-account target test failure ──────────────────────────────
  await page.goto(`${base}/connect?connectSource=aws-discovery`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: 'Multi-Account' }).click();
  await settle(page);
  const sandboxRow = page.locator('tr', { hasText: '444455556666' });
  requests.length = 0;
  await sandboxRow.getByRole('button', { name: 'Test' }).click();
  await settle(page);
  check(tag('target test posts for the sandbox target'), calls(requests, `/connectors/aws-discovery/targets/${FAILING_AWS_TARGET_ID}/test`, 'POST').length === 1);
  check(tag('target failure message shown'), (await page.getByText(AWS_TARGET_FAILURE_MESSAGE).count()) > 0);
  await shot(page, tag('aws-targets'));

  // ── Contained and platform-owned connectors ────────────────────────────
  await page.goto(`${base}/connect?connectSource=sccm-cmdb`, { waitUntil: 'networkidle' });
  check(tag('SCCM is contained read-only'), await page.getByText('SCCM live JDBC is disabled for the assisted pilot.', { exact: false }).isVisible()
    && (await page.locator('.connector-page-back-row ~ *').getByRole('button', { name: /Save|Test|Sync|Run/ }).count()) === 0);
  await page.goto(`${base}/connect?connectSource=azure-discovery`, { waitUntil: 'networkidle' });
  check(tag('Azure is contained read-only'), await page.getByText('Disabled for the pilot. Existing inventory and saved settings are retained.').isVisible()
    && (await page.locator('.connector-page-back-row ~ *').getByRole('button', { name: /Save|Test|Sync|Run/ }).count()) === 0);
  await page.goto(`${base}/connect?connectSource=nvd-api`, { waitUntil: 'networkidle' });
  check(tag('tenant NVD feed stays platform-owned'), await page.getByText(/Central vulnerability repository feeds are platform-owned/).isVisible());
  await page.goto(`${base}/connect?connectSource=sccm-patch&keep=1`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('retired patch connector id is dropped'), here(page) === '/connect?keep=1', here(page));

  // ── Run history ─────────────────────────────────────────────────────────
  await page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await page.locator('.connect-filter-btn', { hasText: 'Run History' }).click();
  await page.getByText('Inventory Run Queue').waitFor();
  await settle(page);
  check(tag('run history route'), here(page) === '/connect/run-history', here(page));
  const runRows = await page.locator('.table-scroll tbody tr').count();
  check(tag('run queue lists runs and jobs'), runRows >= 10, String(runRows));
  check(tag('failed run status visible'), (await page.locator('.status-pill', { hasText: 'FAILED' }).count()) >= 2);
  requests.length = 0;
  await page.getByRole('button', { name: 'Refresh Queue' }).click();
  await settle(page);
  check(tag('refresh refetches runs'), calls(requests, '/sync-runs').length >= 1);
  await shot(page, tag('run-history'));

  // ── Configurations ──────────────────────────────────────────────────────
  await page.goto(`${base}/configurations/sla`, { waitUntil: 'networkidle' });
  await page.getByText('Critical Risk').waitFor();
  check(tag('SLA renders thresholds'), await page.getByText('Score ≥ 9 → Critical').isVisible());
  const thresholdInput = page.locator('.config-content input').first();
  await thresholdInput.fill('8.5');
  requests.length = 0;
  await page.locator('.config-content').getByRole('button', { name: 'Save' }).click();
  await settle(page);
  const policySave = calls(requests, '/risk-policy', 'POST').at(-1);
  check(tag('SLA save sends criticalThreshold 8.5'), policySave && body(policySave).criticalThreshold === 8.5, policySave?.body ?? requests.map((r) => `${r.method} ${apiPath(r.url)}`));
  await shot(page, tag('sla'));
  await page.goto(`${base}/configurations/ownership`, { waitUntil: 'networkidle' });
  await page.getByText('Payments services').waitFor();
  check(tag('ownership lists 3 rules'), (await page.locator('.config-content tbody tr').count()) === 3);
  await page.goto(`${base}/configurations/suppress`, { waitUntil: 'networkidle' });
  await page.getByText('Low severity on development assets').waitFor();
  check(tag('suppression lists 3 rules'), (await page.locator('.config-content tbody tr').count()) === 3);
  requests.length = 0;
  await page.locator('tr', { hasText: 'Low severity on development assets' }).getByRole('button', { name: 'Execute Now' }).click();
  await settle(page);
  check(tag('execute posts the approved rule'), calls(requests, `/suppression-rules/${SUPPRESSION_RULE_IDS[0]}/execute`, 'POST').length === 1);
  check(tag('in-review rule cannot execute'), await page.locator('tr', { hasText: 'Vendor-disputed CVE' }).getByRole('button', { name: 'Execute Now' }).isDisabled());
  await shot(page, tag('suppress'));
  await page.goto(`${base}/configurations/triage`, { waitUntil: 'networkidle' });
  await settle(page);
  await shot(page, tag('triage'));
  check(tag('no page errors on tenant journey'), errors.length === 0, errors);
  await tenant.context.close();

  // ── Roles and entitlements ──────────────────────────────────────────────
  const auditor = await newPage(theme, 1440, { ...actor, roles: ['READ_ONLY_AUDITOR'] });
  await auditor.page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await auditor.page.locator('.connect-source-card').first().waitFor();
  await settle(auditor.page);
  const switches = auditor.page.getByRole('switch');
  check(tag('auditor source switches are disabled'), (await switches.count()) === 0 || (await switches.evaluateAll((els) => els.every((el) => el.disabled))), String(await switches.count()));
  await auditor.page.goto(`${base}/connect?connectSource=aws-discovery`, { waitUntil: 'networkidle' });
  await auditor.page.getByRole('button', { name: 'Multi-Account' }).click();
  await settle(auditor.page);
  check(tag('auditor cannot test AWS targets'), await auditor.page.locator('tr', { hasText: '444455556666' }).getByRole('button', { name: 'Test' }).isDisabled());
  await auditor.context.close();

  const unentitled = await newPage(theme, 1440, { ...actor, entitlements: { 'ai.security': false } });
  await unentitled.page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await unentitled.page.locator('.connect-source-card').first().waitFor();
  check(tag('AI connectors hidden without entitlement'), (await unentitled.page.locator('.connect-source-card').count()) === 7
    && (await card(unentitled.page, 'AWS Bedrock').count()) === 0);
  await unentitled.page.goto(`${base}/connect/copilot-studio`, { waitUntil: 'networkidle' });
  await settle(unentitled.page);
  check(tag('copilot route redirects without entitlement'), here(unentitled.page) === '/exposure', here(unentitled.page));
  await unentitled.context.close();

  // ── Copilot Studio standalone route ─────────────────────────────────────
  const copilot = await newPage(theme, 1440);
  await copilot.page.goto(`${base}/connect/copilot-studio`, { waitUntil: 'networkidle' });
  await copilot.page.getByText('Configured organizations').waitFor();
  copilot.requests.length = 0;
  await copilot.page.getByRole('button', { name: 'Run discovery' }).click();
  await copilot.page.getByRole('status').filter({ hasText: /Discovery (already queued|queued)/ }).waitFor();
  check(tag('copilot run discovery posts and reports the job'), copilot.requests.some((r) => r.method === 'POST' && /copilot-studio\/[^/]+\/run$/.test(apiPath(r.url))));
  await shot(copilot.page, tag('copilot'));
  await copilot.context.close();

  // ── Platform owner: /connect redirects, vuln-intel feeds ────────────────
  const owner = await newPage(theme, 1440, platformActor);
  await owner.page.goto(`${base}/connect`, { waitUntil: 'networkidle' });
  await settle(owner.page);
  check(tag('platform owner /connect redirects to vuln-intel'), here(owner.page) === '/platform/vuln-intel', here(owner.page));
  await owner.page.getByText('NVD Vulnerability Feed').first().waitFor();
  check(tag('feed catalog shows the GHSA failure'), await owner.page.locator('.platform-feed-card', { hasText: 'GitHub Advisory Database (GHSA)' }).getByText('Sync failed').isVisible());
  await shot(owner.page, tag('platform-feeds'));
  await owner.page.locator('.platform-feed-card', { hasText: 'NVD Vulnerability Feed' }).click();
  await settle(owner.page);
  check(tag('feed card opens the NVD detail'), /feed=/.test(here(owner.page)), here(owner.page));
  await shot(owner.page, tag('platform-feed-detail'));
  check(tag('no page errors on platform journey'), owner.errors.length === 0, owner.errors);
  await owner.context.close();

  // ── Narrow viewport ─────────────────────────────────────────────────────
  for (const [who, routes] of [[actor, ['/connect', '/connect?connectSource=aws-discovery', '/connect?connectSource=bom-management', '/connect/run-history', '/connect/copilot-studio',
    '/configurations/sla', '/configurations/triage', '/configurations/ownership', '/configurations/findings-score', '/configurations/suppress', '/configurations/auto-findings']],
  [platformActor, ['/platform/vuln-intel']]]) {
    const narrow = await newPage(theme, 390, who);
    for (const route of routes) {
      await narrow.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
      await settle(narrow.page);
      check(tag(`no page overflow at 390px ${route}`), !(await overflow(narrow.page)));
    }
    if (who === actor) await shot(narrow.page, tag('auto-findings_390'));
    await narrow.page.goto(`${base}${routes[0]}`, { waitUntil: 'networkidle' });
    await shot(narrow.page, tag(`${who === actor ? 'catalog' : 'platform-feeds'}_390`));
    await narrow.context.close();
  }
}

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
console.log(`${label}: ${results.length - failed.length}/${results.length} passed`);
for (const result of failed) console.log(`FAIL ${result.name} ${result.detail}`);
