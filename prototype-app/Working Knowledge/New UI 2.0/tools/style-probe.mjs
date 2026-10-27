// Records computed styles of the UI 2.0 foundation targets on every e2e route, from a cold direct
// link and after a client-side navigation sequence (which loads the lazy route sheets first), then
// after Back/Forward. Also checks the data-ui boundary on /demo during navigation.
// Usage: node style-probe.mjs <frontend dir> <ui2|legacy> <out.json> [--widths 1280,390]
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [fe, version, outFile] = process.argv.slice(2);
const widthsArg = process.argv.indexOf('--widths');
const widths = (widthsArg > 0 ? process.argv[widthsArg + 1] : '1280,390').split(',').map(Number);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { newContext } = await imp('e2e/browser.mjs');
const { actor, routeFixtures } = await imp('e2e/fixtures.mjs');
const { platformActor } = await imp('e2e/governance-fixtures.mjs');
const { ALL_ROUTES } = await imp('e2e/routes.mjs');
const { PRIMARY_AI_ASSET_ID, PRIMARY_HOST_ID } = await imp('e2e/inventory-fixtures.mjs');
const { ARTIFACTS, serveArtifact } = await imp('e2e/serve.mjs');

const SELECTORS = ['.sidebar', '.nav-btn', '.nav-btn.active', '.nav-sub-btn', '.nav-sub-btn.active', '.nav-expand-toggle', '.brand-mark', '.brand',
  '.topbar', '.topbar-copy h1', '.tenant-context-pill', '.test-persona-pill', '.theme-icon-btn', '.content',
  '.section-tab-row', '.section-tab-btn', '.section-tab-btn.active', '.fd3-tab-bar', '.fd3-tab', '.fd3-tab--active', '.cvd2-tab-bar', '.cvd2-tab', '.cvd2-tab.active',
  '.cd-tabnav', '.cd-tab', '.cd-tab.active', '.campaigns-tab-row', '.inventory-workspace-tabs', '.connector-tab-btn', '.connect-filter-btn.active',
  '.btn', '.btn-primary', '.btn-secondary', '.btn-ghost', '.btn-sm', '.btn:disabled', '.panel', '.panel h3', '.panel-caption',
  '.notice', '.notice.error', '.notice.success', '.notice.warning', '.empty-state', '.empty-state strong',
  '.severity-pill', '.severity-critical', '.status-pill', '.match-pill', '.status-investigating', '[class*="risk-score-badge--"]',
  'th', 'td', 'tr.table-row-selected td', '.table-settings-btn',
  "input:not([type='checkbox']):not([type='radio'])", 'input:disabled', "input[type='checkbox']", 'select', 'select:disabled', 'textarea', 'label',
  '.modal-backdrop', '.fd3-modal', '.confirm-dialog', '.settings-menu', '.public-demo-shell', '.public-form-panel input'];
const PSEUDO = ['.section-tab-btn.active', '.fd3-tab--active', '.connector-tab-btn--active', '.connect-filter-btn.active', '.nav-btn.active'];
const PROPS = ['color', 'background-color', 'background-image', 'border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color',
  'border-top-width', 'border-bottom-width', 'border-left-width', 'border-top-style', 'border-bottom-style', 'border-top-left-radius', 'border-bottom-right-radius', 'box-shadow',
  'font-family', 'font-size', 'font-weight', 'line-height', 'letter-spacing', 'text-transform', 'white-space', 'padding-top', 'padding-left', 'padding-right', 'margin-bottom',
  'min-height', 'height', 'width', 'gap', 'display', 'flex-wrap', 'justify-content', 'align-items', 'overflow-x', 'position', 'opacity', 'cursor', 'outline-style',
  'accent-color', 'backdrop-filter', 'grid-template-columns', 'z-index', 'top', 'left', 'right', 'bottom', 'content', 'flex-grow'];

async function collect(page) {
  return page.evaluate(({ SELECTORS, PSEUDO, PROPS }) => {
    const pick = (cs) => Object.fromEntries(PROPS.map((p) => [p, cs.getPropertyValue(p)]));
    const out = { dataUi: document.documentElement.getAttribute('data-ui'), theme: document.documentElement.getAttribute('data-theme'), vars: {}, els: {} };
    const rootCs = getComputedStyle(document.documentElement);
    for (const sheet of document.styleSheets) {
      try { for (const rule of sheet.cssRules) if (rule.style) for (const name of rule.style) if (name.startsWith('--')) out.vars[name] = rootCs.getPropertyValue(name).trim(); } catch { /* cross-origin */ }
    }
    for (const sel of SELECTORS) {
      const nodes = [...document.querySelectorAll(sel)].slice(0, 4);
      if (!nodes.length) continue;
      out.els[sel] = nodes.map((n) => pick(getComputedStyle(n)));
      if (PSEUDO.includes(sel)) out.els[`${sel}::after`] = nodes.map((n) => pick(getComputedStyle(n, '::after')));
      if (sel === '.nav-btn.active') out.els[`${sel}::before`] = nodes.map((n) => pick(getComputedStyle(n, '::before')));
    }
    out.sheets = [...document.styleSheets].map((s) => (s.href || 'inline').replace(/.*\/assets\//, '').replace(/-[\w-]{8}\.css$/, '.css'));
    return out;
  }, { SELECTORS, PSEUDO, PROPS });
}

async function interact(page) {
  // Hover the first visible nav button, tab and primary button and focus the first text input, so
  // the hover/focus rules are measured too. Elements hidden or off-screen (narrow widths) are skipped.
  const states = {};
  const read = (n) => { const c = getComputedStyle(n); return [n.tagName, c.backgroundColor, c.color, c.borderTopColor, c.boxShadow, c.outlineStyle].join('|'); };
  const targets = [
    ['navHover', '.nav-btn', 'hover'],
    ['tabHover', '.section-tab-btn:not(.active), .fd3-tab:not(.fd3-tab--active)', 'hover'],
    ['inputFocus', "input:not([type='checkbox']):not([type='radio']):not([type='range']):not(:disabled), select:not(:disabled), textarea:not(:disabled)", 'focus'],
    ['primaryHover', '.btn-primary:not(:disabled)', 'hover'],
  ];
  for (const [name, selector, action] of targets) {
    const handle = await page.evaluateHandle((sel) => [...document.querySelectorAll(sel)].find((n) => {
      const r = n.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && r.top >= 0 && r.left >= 0 && r.bottom <= innerHeight && r.right <= innerWidth && getComputedStyle(n).visibility !== 'hidden';
    }) || null, selector);
    const el = handle.asElement();
    if (!el) { states[name] = 'none'; continue; }
    try {
      if (action === 'hover') await el.hover({ timeout: 2000 }); else await el.focus();
      states[name] = await el.evaluate(read);
    } catch (error) { states[name] = `error: ${error.name}`; }
    await page.mouse.move(0, 0);
    if (action === 'focus') await page.evaluate(() => document.activeElement?.blur());
  }
  return states;
}

const settle = async (page) => { await page.waitForLoadState('networkidle'); await page.evaluate(() => document.fonts.ready); await page.waitForTimeout(150); };
const clientNav = async (page, to) => { await page.evaluate((p) => { history.pushState({}, '', p); dispatchEvent(new PopStateEvent('popstate')); }, to); await settle(page); };
const WARM = { tenant: ['/findings', `/inventory/ai/${PRIMARY_AI_ASSET_ID}`, `/inventory/hosts/${PRIMARY_HOST_ID}`, '/vuln-repo/vulnerabilities'], platform: ['/platform/ai-policies', '/platform/operations', '/platform/tenants'] };

const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
const browser = await chromium.launch();
const result = { version, widths, runs: {}, boundary: [] };
async function page(theme, width, who) {
  const context = await newContext(browser, { baseURL: server.url, viewport: { width, height: 900 } });
  await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
  await routeFixtures(context, { actorOverride: who === 'platform' ? platformActor : actor });
  if (who === 'signedOut') await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
  return { context, page: await context.newPage() };
}
try {
  for (const theme of ['dark', 'light']) for (const width of widths) for (const [route, who] of ALL_ROUTES) {
    const key = `${route}|${theme}|${width}`;
    const cold = await page(theme, width, who);
    await cold.page.goto(route); await settle(cold.page);
    const entry = { cold: await collect(cold.page), coldStates: await interact(cold.page) };
    await cold.context.close();
    if (who !== 'signedOut') {
      const nav = await page(theme, width, who);
      const warm = WARM[who];
      await nav.page.goto(warm[0]); await settle(nav.page);
      for (const step of warm.slice(1)) await clientNav(nav.page, step);
      await clientNav(nav.page, route);
      entry.nav = await collect(nav.page);
      entry.navStates = await interact(nav.page);
      // Public boundary mid-sequence, then Back to the route and Forward again.
      await clientNav(nav.page, '/demo');
      const onDemo = await nav.page.evaluate(() => document.documentElement.getAttribute('data-ui'));
      await nav.page.goBack(); await settle(nav.page);
      entry.back = await collect(nav.page);
      await nav.page.goForward(); await settle(nav.page);
      const forward = await nav.page.evaluate(() => document.documentElement.getAttribute('data-ui'));
      result.boundary.push({ key, onDemo, back: entry.back.dataUi, forward });
      await nav.context.close();
    }
    result.runs[key] = entry;
    process.stdout.write('.');
  }
} finally {
  await browser.close();
  await server.close();
}
writeFileSync(outFile, JSON.stringify(result));
console.log(`\n${Object.keys(result.runs).length} route/theme/width entries written to ${outFile}`);
