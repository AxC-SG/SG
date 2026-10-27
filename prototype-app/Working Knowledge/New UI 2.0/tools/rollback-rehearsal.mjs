// Rollback rehearsal with the frozen Step 5 UI 1 artifact against the local backend (current data in
// scout_ui2_qual). The artifact is not rebuilt: its sha256 is checked, it is extracted to a fresh
// folder and served as is. Its baked production API base (https://api.scoutgrid.io/api) is answered
// by the local backend through the browser's request routing; every other non-local host is
// aborted and counted, so nothing leaves the machine.
// Usage: node rollback-rehearsal.mjs <frontend dir> <checkpoints dir> <artifact name> <extract dir> <out.json>
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [fe, checkpoints, name, extractDir, outFile] = process.argv.slice(2);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { serveArtifact } = await imp('e2e/serve.mjs');
const result = { artifact: name, checks: [], external: [], apiStatus: {} };
const check = (label, ok, detail = '') => { result.checks.push({ label, ok: !!ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${detail ? ` — ${detail}` : ''}`); };

const archive = path.join(checkpoints, `${name}.tar.gz`);
const expected = readFileSync(`${archive}.sha256`, 'utf8').split(/\s+/)[0];
const actual = createHash('sha256').update(readFileSync(archive)).digest('hex');
check('archive sha256 matches the recorded value', actual === expected, actual);
execFileSync('tar', ['-xzf', archive, '-C', extractDir]);
const manifest = JSON.parse(readFileSync(path.join(checkpoints, `${name}-manifest.json`), 'utf8'));
const mismatched = manifest.files.filter((f) => createHash('sha256').update(readFileSync(path.join(extractDir, f.path))).digest('hex') !== f.sha256);
check('every extracted file matches the manifest', mismatched.length === 0, `${manifest.files.length} files, ${mismatched.length} mismatched`);

const server = await serveArtifact(path.join(extractDir, 'dist'), 5180);
const browser = await chromium.launch();
const LOCAL = new Set(['127.0.0.1', 'localhost']);
async function session(credentialsFile) {
  const credentials = JSON.parse(readFileSync(credentialsFile, 'utf8'));
  const context = await browser.newContext({ baseURL: server.url, viewport: { width: 1440, height: 1000 } });
  await context.route(() => true, async (route) => {
    const url = new URL(route.request().url());
    if (LOCAL.has(url.hostname)) return route.continue();
    if (url.hostname === 'api.scoutgrid.io') {
      const response = await route.fetch({ url: `http://127.0.0.1:8080${url.pathname}${url.search}` });
      const key = `${route.request().method()} ${response.status()}`;
      result.apiStatus[key] = (result.apiStatus[key] ?? 0) + 1;
      return route.fulfill({ response });
    }
    result.external.push(`${url.hostname}${url.pathname}`);
    return route.abort('blockedbyclient');
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto('/login', { waitUntil: 'networkidle' });
  await page.getByLabel('Email').fill(credentials.email);
  await page.getByLabel('Password', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: /sign in/i }).click();
  await page.waitForURL((url) => url.pathname !== '/login', { timeout: 20000 }).catch(() => {});
  return { context, page, errors };
}
async function visit(page, errors, route, label) {
  const before = errors.length;
  await page.goto(route, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  const state = await page.evaluate(() => ({
    dataUi: document.documentElement.getAttribute('data-ui'),
    path: location.pathname,
    text: (document.querySelector('.content') ?? document.body).innerText.trim().length,
    shell: !!document.querySelector('.app-shell'),
  }));
  check(`${label} ${route}: UI 1 presentation, renders, no page errors`,
    state.dataUi === null && state.text > 40 && errors.length === before && state.path !== '/login',
    `path ${state.path}, data-ui ${state.dataUi}, text ${state.text} chars, shell ${state.shell}, errors ${errors.length - before}`);
}
try {
  const tenant = await session(process.env.LIVE_CREDENTIALS);
  check('tenant sign-in through the frozen UI 1 login form', new URL(tenant.page.url()).pathname !== '/login', new URL(tenant.page.url()).pathname);
  for (const route of ['/exposure', '/findings', '/vuln-repo', '/vuln-repo/org-cves', '/vuln-repo/vulnerabilities', '/vuln-repo/campaigns', '/inventory', '/inventory/hosts', '/connect', '/configurations/sla', '/admin/users']) {
    await visit(tenant.page, tenant.errors, route, 'tenant');
  }
  await tenant.context.close();
  const platform = await session(process.env.LIVE_PLATFORM_CREDENTIALS);
  check('platform-owner sign-in through the frozen UI 1 login form', new URL(platform.page.url()).pathname !== '/login', new URL(platform.page.url()).pathname);
  for (const route of ['/platform/tenants', '/platform/operations', '/platform/ai-policies']) await visit(platform.page, platform.errors, route, 'platform');
  await platform.context.close();
} finally {
  await browser.close();
  await server.close();
}
check('no request left the machine', result.external.length === 0, `${result.external.length} blocked: ${[...new Set(result.external)].slice(0, 5).join(', ')}`);
const serverErrors = Object.entries(result.apiStatus).filter(([key]) => / 5\d\d$/.test(key)).reduce((sum, [, n]) => sum + n, 0);
check('no API call answered with a server error', serverErrors === 0, JSON.stringify(result.apiStatus));
writeFileSync(outFile, JSON.stringify(result, null, 1));
const failed = result.checks.filter((c) => !c.ok).length;
console.log(`${result.checks.length - failed}/${result.checks.length} rollback checks passed`);
process.exit(failed ? 1 : 0);
