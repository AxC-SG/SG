#!/usr/bin/env node
// UI 2.0 P4 — Inventory and lifecycle browser journey (plan "Minimum critical browser journeys" 4:
// list/facets → expanded versions → detail/provenance → lifecycle → AI/declared-resource graph →
// back/return and entitlement states).
//
// Runs the same deterministic journey against any build (legacy or UI 2.0) so behaviour can be
// compared, records request URLs to verify serialisation, and saves screenshots.
// Fixture-backed only: this is NOT authenticated staging evidence.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node inventory-journey.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext } from './browser.mjs';
import { unexpectedFailures } from './known-failures.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import {
  PRIMARY_AI_ASSET_ID,
  PRIMARY_DECLARED_RESOURCE_ID,
  PRIMARY_HOST_ID,
  PRIMARY_SOFTWARE_IDENTITY_ID,
} from './inventory-fixtures.mjs';

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
  const context = await newContext(browser, { viewport: { width, height: 1000 } });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  const requests = [];
  await routeFixtures(context, { actorOverride, onRequest: (request) => requests.push({ url: request.url(), method: request.method() }) });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  return { context, page, requests, errors };
}

const apiPath = (url) => new URL(url).pathname.replace(/^\/api/, '');
const params = (request) => new URL(request.url).searchParams;
const calls = (requests, pathname, method = 'GET') => requests.filter((request) => apiPath(request.url) === pathname && request.method === method);
const shot = async (page, name) => {
  await page.waitForTimeout(400);
  await page.screenshot({ path: path.join(out, `${label}_${name}.png`), fullPage: true });
};
const overflow = (page) => page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
const settle = (page) => page.waitForTimeout(500);
const here = (page) => { const url = new URL(page.url()); return url.pathname + url.search; };

for (const theme of themes) {
  const tag = (name) => `${name}_${theme}`;
  const { context, page, requests, errors } = await newPage(theme, 1440);

  // ── Overview ──────────────────────────────────────────────────────────────
  await page.goto(`${base}/inventory`, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: 'Lifecycle breakdown', exact: true }).waitFor();
  await settle(page);
  check(tag('overview renders funnel and lifecycle'), await page.getByRole('heading', { name: 'Lifecycle breakdown', exact: true }).isVisible());
  await shot(page, tag('overview'));

  // ── Hosts list → detail → return ──────────────────────────────────────────
  await page.goto(`${base}/inventory/hosts`, { waitUntil: 'networkidle' });
  await page.getByText('prod-api-gw-01').first().waitFor();
  const hostRows = await page.locator('.inventory-table tbody tr').count();
  check(tag('hosts list renders 12 hosts'), hostRows === 12, String(hostRows));
  await page.getByPlaceholder('hostname, OS, software...').fill('vpn-edge');
  await settle(page);
  const searched = await page.locator('.inventory-table tbody tr').count();
  check(tag('host search narrows rows locally'), searched > 0 && searched < hostRows, String(searched));
  await page.getByPlaceholder('hostname, OS, software...').fill('');
  await settle(page);
  await shot(page, tag('hosts'));
  await page.getByRole('link', { name: 'prod-api-gw-01', exact: true }).first().click();
  await page.waitForURL(/\/inventory\/hosts\/host-prod-api-gw-01/);
  check(tag('host row opens detail with returnTo'), here(page) === `/inventory/hosts/${PRIMARY_HOST_ID}?returnTo=%2Finventory%2Fhosts`, here(page));
  await page.getByRole('tab', { name: /Installed software/ }).first().waitFor().catch(() => {});
  await settle(page);
  await shot(page, tag('host-detail'));

  requests.length = 0;
  await page.getByRole('button', { name: 'Suggest' }).first().click();
  await page.locator('.upgrade-rec-result').first().waitFor();
  check(tag('upgrade suggestion posts once'), calls(requests, '/upgrade-recommendation', 'POST').length === 1);
  await page.getByText('Applicable CVEs').first().click();
  await settle(page);
  check(tag('host tabs switch'), await page.locator('.fd3-tab--active', { hasText: 'Applicable CVEs' }).count() === 1);
  await shot(page, tag('host-detail-cves'));
  await page.getByLabel('Close host detail').click();
  await page.waitForURL(/\/inventory\/hosts$/);
  check(tag('close host detail returns to hosts'), here(page) === '/inventory/hosts', here(page));

  // Same component under the vulnerability repository route.
  await page.goto(`${base}/vuln-repo/host-assets/${PRIMARY_HOST_ID}`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('vuln-repo host asset route renders host detail'), await page.locator('.host-detail-page.ui2-inventory-family, .host-detail-page').first().isVisible());

  // ── Software identities: lifecycle facet, expanded versions, detail ───────
  requests.length = 0;
  await page.goto(`${base}/inventory/software-identities?lifecycle=eol`, { waitUntil: 'networkidle' });
  await settle(page);
  const eolCall = calls(requests, '/inventory/software-identities').at(-1);
  check(tag('lifecycle facet serialised as lifecycle=eol'), eolCall && params(eolCall).get('lifecycle') === 'eol', eolCall?.url);
  const eolRows = await page.locator('tr.si-identity-row').count();
  check(tag('lifecycle facet narrows identities'), eolRows === 13, String(eolRows));
  await page.goto(`${base}/inventory/software-identities`, { waitUntil: 'networkidle' });
  await page.locator('tr.si-identity-row').first().waitFor();
  check(tag('software identities list renders 29 rows'), (await page.locator('tr.si-identity-row').count()) === 29);
  requests.length = 0;
  await page.locator('tr.si-identity-row', { hasText: 'log4j-core' }).first().click();
  await page.locator('tr.si-version-row').first().waitFor();
  check(tag('row expands 4 version rows'), (await page.locator('tr.si-version-row').count()) === 4);
  check(tag('expansion fetches identity detail once'), calls(requests, `/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`).length === 1);
  await shot(page, tag('software-identities-expanded'));
  await page.locator('tr.si-identity-row', { hasText: 'log4j-core' }).first().getByRole('link', { name: 'log4j-core', exact: true }).click();
  await page.waitForURL(new RegExp(`/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`));
  check(tag('identity link opens detail'), new URL(page.url()).pathname === `/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`, here(page));
  await settle(page);
  check(tag('identity detail shows versions'), await page.getByRole('tablist', { name: 'Software identity sections' }).isVisible());
  await shot(page, tag('software-identity-detail'));
  await page.getByRole('tab', { name: /Installed Assets/ }).or(page.locator('.fd3-tab', { hasText: 'Installed Assets' })).first().click();
  await settle(page);
  check(tag('identity tabs switch'), await page.locator('.fd3-tab--active', { hasText: 'Installed Assets' }).count() === 1);
  await page.getByRole('button', { name: '← Back to Software Entities' }).click();
  await settle(page);
  check(tag('back returns to software identities'), new URL(page.url()).pathname === '/inventory/software-identities', here(page));

  // ── Component views and BOM ───────────────────────────────────────────────
  await page.goto(`${base}/inventory/container-images`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('container images paginate'), await page.getByText('Page 1 of 2').first().isVisible());
  await shot(page, tag('container-images'));
  await page.goto(`${base}/inventory/sbom`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('sbom application cards render'), await page.getByText('Applications Risk Overview').first().isVisible());
  await shot(page, tag('sbom'));
  await page.goto(`${base}/inventory/bom-components`, { waitUntil: 'networkidle' });
  await settle(page);
  await shot(page, tag('bom-components'));
  requests.length = 0;
  await page.goto(`${base}/inventory/bom-inventory`, { waitUntil: 'networkidle' });
  await settle(page);
  await page.getByRole('button', { name: 'Next' }).first().click();
  await settle(page);
  const bomNext = calls(requests, '/bom/inventory').at(-1);
  check(tag('BOM inventory Next requests page=1&size=50'), bomNext && params(bomNext).get('page') === '1' && params(bomNext).get('size') === '50', bomNext?.url);
  await shot(page, tag('bom-inventory'));

  // ── AI inventory categories ───────────────────────────────────────────────
  await page.goto(`${base}/inventory/ai`, { waitUntil: 'networkidle' });
  await settle(page);
  check(tag('AI overview renders severity grid'), await page.locator('.ai-severity-grid--compact').count() > 0);
  await shot(page, tag('ai-overview'));
  requests.length = 0;
  await page.goto(`${base}/inventory/ai/assets`, { waitUntil: 'networkidle' });
  await page.getByText('Showing 1–50 of 62 assets').waitFor();
  await page.getByLabel('Cloud provider').selectOption('AZURE');
  await settle(page);
  const providerCall = calls(requests, '/ai-security/artifact-summaries').at(-1);
  check(tag('provider filter sends provider=AZURE page=0'), providerCall && params(providerCall).get('provider') === 'AZURE' && params(providerCall).get('page') === '0', providerCall?.url);
  await page.getByLabel('Cloud provider').selectOption('');
  await settle(page);
  requests.length = 0;
  await page.getByRole('button', { name: 'Next' }).click();
  await settle(page);
  const assetsNext = calls(requests, '/ai-security/artifact-summaries').at(-1);
  check(tag('AI assets Next requests page=1'), assetsNext && params(assetsNext).get('page') === '1', assetsNext?.url);
  check(tag('AI assets shows Page 2 of 2'), await page.getByText('Page 2 of 2').isVisible());
  await page.getByRole('button', { name: 'Previous' }).click();
  await settle(page);
  await shot(page, tag('ai-assets'));
  requests.length = 0;
  await page.goto(`${base}/inventory/ai/agents`, { waitUntil: 'networkidle' });
  await page.getByLabel('Search agents').fill('claims');
  await settle(page);
  const agentsCall = calls(requests, '/ai-security/artifact-summaries').at(-1);
  check(tag('agents search sends search + inventoryView=AGENTS'), agentsCall && params(agentsCall).get('search') === 'claims' && params(agentsCall).get('inventoryView') === 'AGENTS', agentsCall?.url);
  await shot(page, tag('ai-agents'));
  for (const [route, text] of [['/inventory/ai/mcp', 'MCP Inventory'], ['/inventory/ai/knowledge-data', 'Knowledge & Data']]) {
    await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
    await settle(page);
    check(tag(`${route} renders table`), (await page.getByText(text).first().isVisible()) && (await page.locator('.data-table tbody tr').count()) > 0);
    await shot(page, tag(route.replace(/\W+/g, '-').replace(/^-|-$/g, '')));
  }

  // ── AI asset detail, relationship graph and nested return ─────────────────
  await page.goto(`${base}/inventory/ai/assets`, { waitUntil: 'networkidle' });
  await page.getByText('claims-triage-agent', { exact: true }).first().click();
  await page.waitForURL(new RegExp(`/inventory/ai/${PRIMARY_AI_ASSET_ID}\\?returnTo=`));
  check(tag('AI row opens detail with returnTo'), new URL(page.url()).searchParams.get('returnTo') === '/inventory/ai/assets', here(page));
  await settle(page);
  await shot(page, tag('ai-asset-detail'));
  await page.locator('.fd3-tab', { hasText: 'Relationships' }).click();
  await page.locator('.react-flow__pane').first().waitFor();
  const nodes = await page.locator('.ai-dependency-graph-node').count();
  check(tag('relationship graph renders nodes'), nodes >= 5, String(nodes));
  await shot(page, tag('ai-asset-relationships'));
  await page.getByRole('button', { name: 'List', exact: true }).click();
  const relationshipRows = await page.getByRole('table', { name: 'AI artifact relationships' }).locator('tbody tr').count();
  check(tag('relationship list alternative renders edges'), relationshipRows > 0, String(relationshipRows));
  await page.getByLabel('Close AI asset detail').click();
  await page.waitForURL(/\/inventory\/ai\/assets/);
  check(tag('close AI asset detail returns to list'), new URL(page.url()).pathname === '/inventory/ai/assets', here(page));

  // ── Declared resources ────────────────────────────────────────────────────
  await page.goto(`${base}/inventory/ai/declared-resources`, { waitUntil: 'networkidle' });
  await settle(page);
  await shot(page, tag('declared-resources'));
  await page.getByText('fixture-text-model-v2', { exact: true }).first().click();
  await page.waitForURL(new RegExp(`/inventory/ai/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}`));
  check(tag('declared resource row opens detail'), new URL(page.url()).pathname === `/inventory/ai/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}`, here(page));
  await settle(page);
  requests.length = 0;
  await page.getByRole('button', { name: 'Retired history' }).click();
  await settle(page);
  const history = calls(requests, `/bom/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}/correlation`).at(-1);
  check(tag('retired history requests history=true'), history && params(history).get('history') === 'true', history?.url);
  await shot(page, tag('declared-resource-detail'));
  await page.getByRole('button', { name: 'Back to declared resources' }).click();
  await settle(page);
  check(tag('back returns to declared resources'), new URL(page.url()).pathname === '/inventory/ai/declared-resources', here(page));

  check(tag('no page errors'), errors.length === 0, errors.join(' | '));
  await context.close();

  // ── Entitlement: ai.security off redirects every AI inventory route ───────
  const gated = await newPage(theme, 1440, { ...actor, entitlements: { 'ai.security': false } });
  for (const route of ['/inventory/ai', `/inventory/ai/${PRIMARY_AI_ASSET_ID}`, '/inventory/ai/declared-resources', `/inventory/ai/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}`]) {
    await gated.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
    await settle(gated.page);
    check(tag(`ai.security=false redirects ${route} to /exposure`), new URL(gated.page.url()).pathname === '/exposure', here(gated.page));
  }
  await gated.page.goto(`${base}/inventory/hosts`, { waitUntil: 'networkidle' });
  await settle(gated.page);
  check(tag('ai.security=false keeps host inventory'), new URL(gated.page.url()).pathname === '/inventory/hosts');
  await gated.context.close();

  // ── Narrow viewport: no page-level horizontal overflow ────────────────────
  const narrow = await newPage(theme, 390);
  for (const route of ['/inventory', '/inventory/hosts', '/inventory/software-identities', '/inventory/container-images', '/inventory/bom-components', '/inventory/bom-inventory', '/inventory/ai', '/inventory/ai/assets', '/inventory/ai/mcp', '/inventory/ai/declared-resources', `/inventory/ai/declared-resources/${PRIMARY_DECLARED_RESOURCE_ID}`, `/inventory/ai/${PRIMARY_AI_ASSET_ID}`, `/inventory/hosts/${PRIMARY_HOST_ID}`, `/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`]) {
    await narrow.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
    await settle(narrow.page);
    check(tag(`no page overflow at 390px ${route}`), !(await overflow(narrow.page)));
    await narrow.page.screenshot({ path: path.join(out, `${label}_${route.replace(/\W+/g, '-').replace(/^-|-$/g, '')}_${theme}_390.png`), fullPage: false });
  }
  await narrow.context.close();
}

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
console.log(`${label}: ${results.length - failed.length}/${results.length} passed`);
for (const failure of failed) console.log(`  FAIL ${failure.name} ${failure.detail}`);
process.exitCode = unexpectedFailures(results).length ? 1 : 0;
failOnUnexpectedApi();
