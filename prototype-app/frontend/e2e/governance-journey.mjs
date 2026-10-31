#!/usr/bin/env node
// UI 2.0 P5 — Governance and platform administration browser journey (plan "Minimum critical
// browser journeys" 5: authorized tenant selection → tenant controls versus platform controls →
// policy lifecycle/cohort → identity/admin forms → audit/role/lifecycle restrictions).
//
// Runs the same deterministic journey against any build (legacy or UI 2.0) so behaviour can be
// compared, records request URLs and bodies to verify serialisation, and saves screenshots.
// Fixture-backed only: this is NOT authenticated staging evidence, and no write is persisted.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node governance-journey.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext } from './browser.mjs';
import { unexpectedFailures } from './known-failures.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import {
  ACTIVE_TENANT_ID,
  APPROVED_PLATFORM_POLICY_ID,
  FIXTURE_TENANT_ID,
  PENDING_GRANT_ID,
  PRIMARY_PLATFORM_POLICY_ID,
  PRIMARY_POLICY_ID,
  TAKEN_SLUG,
  platformActor,
} from './governance-fixtures.mjs';

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
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

for (const theme of themes) {
  const tag = (name) => `${name}_${theme}`;

  // ── Tenant scope: AI policies and framework coverage ──────────────────────
  const tenant = await newPage(theme, 1440);
  const { page, requests } = tenant;
  await page.goto(`${base}/policies`, { waitUntil: 'networkidle' });
  await page.getByText('Framework risk coverage').waitFor();
  await settle(page);
  const policyRows = () => page.locator('.ai-security-table-panel .data-table tbody tr').count();
  check(tag('policies list renders 8 policies'), (await policyRows()) === 8, String(await policyRows()));
  check(tag('framework coverage renders both frameworks'), (await page.getByText('OWASP Top 10 for LLM Applications 2025').isVisible())
    && (await page.getByText('OWASP Agentic Security Top 10').isVisible()));
  check(tag('coverage blockers are user-readable'), await page.getByText('Required connector data is unavailable: diagnostic logging configuration.').first().isVisible());
  check(tag('policy insights show estate 8'), (await page.locator('.ai-policy-insight-card', { hasText: 'Policy estate' }).locator('.ai-policy-insight-value').textContent()) === '8');
  await shot(page, tag('policies'));

  requests.length = 0;
  await page.locator('.ai-policy-severity-pill', { hasText: 'Critical' }).click();
  await settle(page);
  check(tag('severity filter narrows locally to 1'), (await policyRows()) === 1 && calls(requests, '/ai-policies').length === 0, String(await policyRows()));
  await page.locator('.ai-policy-severity-pill', { hasText: 'All' }).click();
  await page.getByLabel('Search policies').fill('knowledge');
  await settle(page);
  check(tag('policy search narrows locally to 2'), (await policyRows()) === 2, String(await policyRows()));
  await page.getByLabel('Search policies').fill('');
  await settle(page);

  check(tag('execute disabled with no selection'), await page.getByRole('button', { name: 'Execute now' }).isDisabled());
  await page.getByLabel('Select Model endpoint allows public access').check();
  await page.getByLabel('Select Agent identity is explicitly configured').check();
  check(tag('selection status counts 2'), await page.getByText('2 policies selected for assessment.').isVisible());
  requests.length = 0;
  await page.getByRole('button', { name: 'Execute now' }).click();
  await page.getByRole('status').filter({ hasText: /Assessment/ }).first().waitFor();
  const execute = calls(requests, '/ai-assessments/execute', 'POST').at(-1);
  check(tag('execute posts the selected policy IDs'), execute && same(body(execute).policyIds, [PRIMARY_POLICY_ID, 'policy.multi_cloud.6']), execute?.body);
  check(tag('selection clears after execution'), !(await page.getByText(/selected for assessment/).isVisible()));

  requests.length = 0;
  await page.locator('.ai-security-table-panel tbody tr', { hasText: 'Guardrail contains a non-blocking filter' }).locator('.ai-policy-toggle').click();
  await settle(page);
  const selection = calls(requests, '/ai-policies/policy.azure.1/selection', 'PUT').at(-1);
  check(tag('enable toggle sends selection DISABLED'), selection && body(selection).selection === 'DISABLED', selection?.body);

  await page.locator('.ai-security-table-panel .data-table tbody tr', { hasText: 'Model endpoint allows public access' }).locator('td').nth(1).click();
  await page.waitForURL(new RegExp(`/policies/${PRIMARY_POLICY_ID.replace('.', '\\.')}`));
  check(tag('policy row opens detail'), new URL(page.url()).pathname === `/policies/${PRIMARY_POLICY_ID}`, here(page));
  await page.locator('.cvd2-tab', { hasText: 'Overview' }).waitFor();
  await settle(page);
  check(tag('policy detail overview is active'), (await page.locator('.cvd2-tab.active').textContent()) === 'Overview');
  await shot(page, tag('policy-detail'));
  await page.locator('.cvd2-tab', { hasText: 'Governance' }).click();
  await settle(page);
  check(tag('policy detail governance tab switches'), (await page.locator('.cvd2-tab.active').textContent()) === 'Governance');
  await shot(page, tag('policy-detail-governance'));
  await page.locator('.cvd2-tab', { hasText: /^Findings/ }).click();
  await settle(page);
  check(tag('policy detail findings tab lists its finding'), await page.getByText('AIF-209C7BD1').first().isVisible().catch(() => false));
  await page.getByRole('button', { name: '← Back to Policies' }).click();
  await page.waitForURL(/\/policies$/);
  check(tag('back returns to policies'), here(page) === '/policies', here(page));

  // ── Tenant administration ─────────────────────────────────────────────────
  await page.goto(`${base}/admin/users`, { waitUntil: 'networkidle' });
  await page.getByText('Fixture Analyst').first().waitFor();
  const memberRows = () => page.locator('.um-table-scroll .data-table tbody tr').count();
  check(tag('admin lists 5 members'), (await memberRows()) === 5, String(await memberRows()));
  check(tag('members load for the actor tenant'), calls(requests, `/tenants/${FIXTURE_TENANT_ID}/members`).length > 0);
  await page.getByLabel('Search users').fill('priya');
  await settle(page);
  check(tag('member search narrows locally to 1'), (await memberRows()) === 1, String(await memberRows()));
  await page.getByLabel('Search users').fill('');
  await page.getByLabel('Filter members by status').selectOption({ label: 'Disabled' }).catch(() => page.getByLabel('Filter members by status').selectOption('DISABLED'));
  await settle(page);
  check(tag('member status filter narrows to 1'), (await memberRows()) === 1, String(await memberRows()));
  await page.getByLabel('Filter members by status').selectOption({ index: 0 });
  await settle(page);
  await shot(page, tag('admin-users'));

  await page.getByRole('button', { name: 'Invite user' }).click();
  const invite = page.locator('.um-modal');
  await invite.waitFor();
  await shot(page, tag('admin-invite-dialog'));
  await invite.locator('input[name="email"]').fill('new.analyst@example.test');
  await invite.locator('input[name="displayName"]').fill('New Analyst');
  requests.length = 0;
  await invite.getByRole('button', { name: 'Send invite' }).click();
  await settle(page);
  const created = calls(requests, `/tenants/${FIXTURE_TENANT_ID}/invites`, 'POST').at(-1);
  check(tag('invite posts email, name and default role'), created && body(created).email === 'new.analyst@example.test' && body(created).role === 'SECURITY_ANALYST', created?.body);

  for (const [view, text, name] of [['invites', 'Pending Invitations', 'admin-invites'], ['roles', 'Role Model', 'admin-roles'], ['service-accounts', 'Service Accounts', 'admin-service-accounts'], ['audit', 'Audit Events', 'admin-audit']]) {
    await page.goto(`${base}/admin/${view}`, { waitUntil: 'networkidle' });
    await settle(page);
    check(tag(`/admin/${view} renders ${text}`), await page.getByRole('heading', { name: text }).isVisible());
    await shot(page, tag(name));
  }
  check(tag('no tenant page errors'), tenant.errors.length === 0, tenant.errors.join(' | '));
  await tenant.context.close();

  // ── Role and entitlement restrictions ─────────────────────────────────────
  const auditor = await newPage(theme, 1440, { ...actor, roles: ['READ_ONLY_AUDITOR'] });
  await auditor.page.goto(`${base}/policies`, { waitUntil: 'networkidle' });
  await auditor.page.getByText('Framework risk coverage').waitFor();
  await settle(auditor.page);
  const toggles = auditor.page.locator('.ai-policy-toggle input');
  const disabledToggles = await toggles.evaluateAll((inputs) => inputs.filter((input) => input.disabled).length);
  check(tag('read-only auditor cannot toggle policies'), disabledToggles === (await toggles.count()) && disabledToggles === 8, String(disabledToggles));
  await auditor.page.getByLabel('Select Model endpoint allows public access').check();
  check(tag('read-only auditor cannot execute'), await auditor.page.getByRole('button', { name: 'Execute now' }).isDisabled());
  await auditor.page.goto(`${base}/admin/users`, { waitUntil: 'networkidle' });
  await settle(auditor.page);
  check(tag('non-admin is redirected from /admin to /exposure'), new URL(auditor.page.url()).pathname === '/exposure', here(auditor.page));
  await auditor.page.goto(`${base}/platform/tenants`, { waitUntil: 'networkidle' });
  await settle(auditor.page);
  check(tag('tenant user sees platform-owner requirement'), await auditor.page.getByText('Platform console access requires the Platform Owner role.').isVisible());
  await auditor.page.goto(`${base}/authorized-workspaces`, { waitUntil: 'networkidle' });
  await settle(auditor.page);
  check(tag('tenant user is redirected from /authorized-workspaces'), new URL(auditor.page.url()).pathname === '/exposure', here(auditor.page));
  await auditor.context.close();

  const gated = await newPage(theme, 1440, { ...actor, entitlements: { 'ai.security': false } });
  for (const route of ['/policies', `/policies/${PRIMARY_POLICY_ID}`]) {
    await gated.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
    await settle(gated.page);
    check(tag(`ai.security=false redirects ${route} to /exposure`), new URL(gated.page.url()).pathname === '/exposure', here(gated.page));
  }
  await gated.page.goto(`${base}/admin/users`, { waitUntil: 'networkidle' });
  await settle(gated.page);
  check(tag('ai.security=false keeps tenant administration'), new URL(gated.page.url()).pathname === '/admin/users');
  await gated.context.close();

  // ── Platform scope: tenant lifecycle ──────────────────────────────────────
  const platform = await newPage(theme, 1440, platformActor);
  const pp = platform.page;
  const preq = platform.requests;
  await pp.goto(`${base}/platform/tenants`, { waitUntil: 'networkidle' });
  await pp.getByText('Acme Corporation').first().waitFor();
  await settle(pp);
  const tenantRows = await pp.locator('.section-block .table-scroll').first().locator('tbody tr').count();
  check(tag('tenant lifecycle lists 5 tenants'), tenantRows === 5, String(tenantRows));
  check(tag('provisioning failure shows schema message'), await pp.getByText('Migration V42 failed: relation "ai_policy_scope" already exists.').isVisible());
  check(tag('tenants rail item is active'), (await pp.locator('.platform-console-nav-btn.active span').textContent()) === 'Tenants');
  await shot(pp, tag('platform-tenants'));

  preq.length = 0;
  await pp.getByLabel('Tenant name').fill('Hooli Labs');
  await pp.getByLabel('Tenant slug').fill('hooli-labs');
  await pp.getByLabel('Billing reference').fill('BILL-HOOLI');
  await pp.getByRole('button', { name: 'Create Tenant' }).click();
  await settle(pp);
  const createTenant = calls(preq, '/platform/tenants', 'POST').at(-1);
  check(tag('create tenant posts name, slug and billing reference'), createTenant && same(
    [body(createTenant).name, body(createTenant).slug, body(createTenant).billingRef, body(createTenant).addDemoData], ['Hooli Labs', 'hooli-labs', 'BILL-HOOLI', false]), createTenant?.body);
  await pp.getByLabel('Tenant name').fill('Duplicate');
  await pp.getByLabel('Tenant slug').fill(TAKEN_SLUG);
  await pp.getByRole('button', { name: 'Create Tenant' }).click();
  await pp.getByRole('alert').filter({ hasText: 'already in use' }).waitFor();
  check(tag('slug conflict surfaces the server message'), await pp.getByText(`Tenant slug "${TAKEN_SLUG}" is already in use.`).isVisible());
  await shot(pp, tag('platform-tenants-create-error'));

  preq.length = 0;
  await pp.locator('.section-block .table-scroll').first().locator('tbody tr', { hasText: 'Acme Corporation' }).getByRole('button', { name: 'Block access' }).click();
  const dialog = pp.locator('dialog .confirm-dialog');
  await dialog.waitFor();
  check(tag('block access asks for confirmation'), await dialog.getByText('Temporarily block all tenant users from Acme Corporation? Tenant data will be retained.').isVisible());
  await shot(pp, tag('platform-block-dialog'));
  await dialog.getByRole('button', { name: 'Block Access' }).click();
  await settle(pp);
  const status = calls(preq, `/platform/tenants/${ACTIVE_TENANT_ID}/status`, 'PATCH').at(-1);
  check(tag('confirm sends status SUSPENDED'), status && body(status).status === 'SUSPENDED', status?.body);

  for (const [rail, route, text] of [['Users', '/platform/users', 'new.operator@example.test'], ['Platform Audit', '/platform/platform-audit', 'PLATFORM_USER_LOGIN_FAILED'], ['Demo Requests', '/platform/demo-requests', 'Jordan Rivera']]) {
    await pp.locator('.platform-console-nav-btn', { hasText: rail }).click();
    await pp.waitForURL(new RegExp(`${route}$`));
    await settle(pp);
    check(tag(`rail opens ${route}`), new URL(pp.url()).pathname === route, here(pp));
    check(tag(`${route} renders fixture rows`), await pp.locator('td', { hasText: text }).first().isVisible());
    await shot(pp, tag(route.replace(/\W+/g, '-').replace(/^-|-$/g, '')));
  }
  preq.length = 0;
  await pp.goto(`${base}/platform/users`, { waitUntil: 'networkidle' });
  await pp.locator('tr', { hasText: 'new.operator@example.test' }).getByRole('button', { name: 'Set Password' }).click();
  await settle(pp);
  await pp.waitForURL(/\/setup(\/|$)/, { waitUntil: 'commit' });
  check(tag('set password issues one setup link'), calls(preq, '/platform/users/pu-3/setup-link', 'POST').length === 1);
  // The setup page then removes the token from the address bar, leaving /setup.
  check(tag('set password opens the setup link in this tab'), /^\/setup(\/|$)/.test(new URL(pp.url()).pathname), here(pp));

  // ── Platform EOL console ──────────────────────────────────────────────────
  await pp.goto(`${base}/platform/eol`, { waitUntil: 'networkidle' });
  await settle(pp);
  check(tag('platform EOL renders the catalog'), await pp.getByText('10 matching products').waitFor({ timeout: 10_000 }).then(() => true, () => false));
  await shot(pp, tag('platform-eol'));

  // ── Platform policy distribution and lifecycle ────────────────────────────
  preq.length = 0;
  await pp.goto(`${base}/platform/ai-policies`, { waitUntil: 'networkidle' });
  await pp.getByText('6 of 6 policies').waitFor();
  check(tag('studio lists 6 catalog policies'), (await pp.locator('.policy-catalog-row').count()) === 6);
  check(tag('studio shows shipping blocker'), await pp.getByText('aws.kb.cross-account-read: digest mismatch against approved package').isVisible());
  await shot(pp, tag('platform-ai-policies'));
  await pp.getByLabel('Provider').selectOption('AZURE');
  await settle(pp);
  check(tag('provider filter narrows locally to 2'), (await pp.getByText('2 of 6 policies').isVisible()) && calls(preq, '/platform/ai-grid/policies').length === 1);
  await pp.getByRole('button', { name: 'Clear filters' }).click();
  await settle(pp);
  check(tag('clear filters restores 6'), await pp.getByText('6 of 6 policies').isVisible());
  await pp.locator('.policy-rollout-panel tr', { hasText: APPROVED_PLATFORM_POLICY_ID }).getByRole('button', { name: 'Retry' }).click();
  await settle(pp);
  check(tag('retry posts the failed rollout'), calls(preq, '/platform/ai-grid/policy-rollouts/rollout-1/retry', 'POST').length === 1);

  await pp.getByRole('link', { name: 'Open policy: Unrestricted agent tool permissions', exact: true }).click();
  await pp.waitForURL(new RegExp(`/platform/ai-policies/${PRIMARY_PLATFORM_POLICY_ID}`));
  check(tag('open policy navigates to platform detail'), new URL(pp.url()).pathname === `/platform/ai-policies/${PRIMARY_PLATFORM_POLICY_ID}`, here(pp));
  await pp.getByText('Platform Governance').waitFor();
  await settle(pp);
  await shot(pp, tag('platform-policy-detail'));
  await pp.locator('.cvd2-tab', { hasText: 'Governance' }).click();
  await settle(pp);
  const approve = pp.getByRole('button', { name: 'Approve policy' });
  check(tag('approve requires an evidence note'), await approve.isDisabled());
  await pp.getByPlaceholder('Describe the review evidence supporting approval or rollout').fill('Dev/test cohort passed with no false positives.');
  preq.length = 0;
  await pp.getByLabel('Canary tenants').selectOption([ACTIVE_TENANT_ID]);
  await pp.getByRole('button', { name: 'Deploy to dev/test' }).click();
  await settle(pp);
  const deploy = calls(preq, `/platform/ai-grid/validation/policies/${PRIMARY_PLATFORM_POLICY_ID}/dev-deploy`, 'POST').at(-1);
  check(tag('dev/test deploy posts cohort and note'), deploy && same(body(deploy), { targetTenantIds: [ACTIVE_TENANT_ID], testNote: 'Dev/test cohort passed with no false positives.' }), deploy?.body);
  await approve.click();
  await pp.getByRole('status').filter({ hasText: 'Policy approved successfully.' }).waitFor();
  const approval = calls(preq, `/platform/ai-grid/validation/policies/${PRIMARY_PLATFORM_POLICY_ID}/approve`, 'POST').at(-1);
  check(tag('approve posts the evidence note'), approval && body(approval).tenantTestNote === 'Dev/test cohort passed with no false positives.', approval?.body);
  check(tag('publish stays disabled while VALIDATED'), await pp.getByRole('button', { name: 'Publish to all active tenants' }).isDisabled());
  await shot(pp, tag('platform-policy-governance'));
  await pp.getByRole('button', { name: '← Back to Policy distribution' }).click();
  await pp.waitForURL(/\/platform\/ai-policies$/);
  check(tag('back returns to policy distribution'), new URL(pp.url()).pathname === '/platform/ai-policies', here(pp));

  preq.length = 0;
  await pp.goto(`${base}/platform/ai-policies/${APPROVED_PLATFORM_POLICY_ID}`, { waitUntil: 'networkidle' });
  await pp.locator('.cvd2-tab', { hasText: 'Governance' }).click();
  await pp.getByRole('button', { name: 'Publish to all active tenants' }).click();
  const publishDialog = pp.getByRole('dialog', { name: 'Publish to all active tenants?' });
  await publishDialog.waitFor();
  check(tag('publish all is reviewed before sending'), calls(preq, `/platform/ai-grid/validation/policies/${APPROVED_PLATFORM_POLICY_ID}/publish`, 'POST').length === 0);
  await publishDialog.getByRole('button', { name: 'Publish to all' }).click();
  await settle(pp);
  const publish = calls(preq, `/platform/ai-grid/validation/policies/${APPROVED_PLATFORM_POLICY_ID}/publish`, 'POST').at(-1);
  check(tag('publish all sends publishAll with no cohort'), publish && same(body(publish), { targetTenantIds: [], publishAll: true }), publish?.body);
  check(tag('suspended tenants are not canary options'), !(await pp.getByLabel('Canary tenants').locator('option', { hasText: 'Globex' }).count()));

  // ── Authorized workspace selection ────────────────────────────────────────
  preq.length = 0;
  await pp.goto(`${base}/authorized-workspaces`, { waitUntil: 'networkidle' });
  await pp.getByText('Pending support invitations').waitFor();
  await settle(pp);
  check(tag('authorized workspaces lists 2 workspaces'), (await pp.locator('.data-table').first().locator('tbody tr').count()) === 2);
  await shot(pp, tag('authorized-workspaces'));
  await pp.getByRole('button', { name: 'Accept' }).click();
  await settle(pp);
  check(tag('accept posts the pending grant'), calls(preq, `/auth/support-grants/${PENDING_GRANT_ID}/accept`, 'POST').length === 1);
  await pp.getByRole('button', { name: 'Open workspace' }).click();
  await pp.waitForURL((url) => url.pathname !== '/authorized-workspaces');
  const select = calls(preq, '/auth/tenant-context', 'POST').at(-1);
  check(tag('open workspace posts the selected tenant'), select && body(select).tenantId === ACTIVE_TENANT_ID, select?.body);
  check(tag('open workspace stores the context token'), (await pp.evaluate(() => localStorage.getItem('vulnwatch.authToken'))) === 'fixture-workspace-token');
  check(tag('no platform page errors'), platform.errors.length === 0, platform.errors.join(' | '));
  await platform.context.close();

  // ── Narrow viewport: no page-level horizontal overflow ────────────────────
  for (const [who, routes] of [
    [actor, ['/policies', `/policies/${PRIMARY_POLICY_ID}`, '/admin/users', '/admin/invites', '/admin/roles', '/admin/service-accounts', '/admin/audit']],
    [platformActor, ['/platform/tenants', '/platform/users', '/platform/platform-audit', '/platform/demo-requests', '/platform/eol', '/platform/ai-policies', `/platform/ai-policies/${PRIMARY_PLATFORM_POLICY_ID}`, '/authorized-workspaces']],
  ]) {
    const narrow = await newPage(theme, 390, who);
    for (const route of routes) {
      await narrow.page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
      await settle(narrow.page);
      check(tag(`no page overflow at 390px ${route}`), !(await overflow(narrow.page)));
      await narrow.page.screenshot({ path: path.join(out, `${label}_${route.replace(/\W+/g, '-').replace(/^-|-$/g, '')}_${theme}_390.png`), fullPage: false });
    }
    await narrow.context.close();
  }
}

await browser.close();
writeFileSync(path.join(out, `${label}_journey.json`), JSON.stringify(results, null, 2));
const failed = results.filter((result) => !result.ok);
console.log(`${label}: ${results.length - failed.length}/${results.length} passed`);
for (const failure of failed) console.log(`  FAIL ${failure.name} ${failure.detail}`);
process.exitCode = unexpectedFailures(results).length ? 1 : 0;
failOnUnexpectedApi();
