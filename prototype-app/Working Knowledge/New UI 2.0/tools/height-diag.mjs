// Finds which elements change between a cold direct link and a client-side navigation sequence.
// Usage: node height-diag.mjs <frontend dir> <ui2|legacy> <route> <warm route,warm route,...>
// Prints elements whose computed layout styles differ (or, if none, whose heights differ).
import path from 'node:path'; import { pathToFileURL } from 'node:url';
const [fe, version, route, warmCsv] = process.argv.slice(2);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { newContext } = await imp('e2e/browser.mjs'); const { actor, routeFixtures } = await imp('e2e/fixtures.mjs');
const { ARTIFACTS, serveArtifact } = await imp('e2e/serve.mjs');
const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port); const browser = await chromium.launch();
const settle = async (p) => { await p.waitForLoadState('networkidle'); await p.evaluate(() => document.fonts.ready); await p.waitForTimeout(200); };
async function snap(warm) {
  const ctx = await newContext(browser, { baseURL: server.url, viewport: { width: 1280, height: 900 } });
  await ctx.addInitScript(() => localStorage.setItem('scoutai-theme', 'dark')); await routeFixtures(ctx, { actorOverride: actor });
  const p = await ctx.newPage(); await p.goto(warm[0] ?? route); await settle(p);
  for (const w of [...warm.slice(1), ...(warm.length ? [route] : [])]) { await p.evaluate((x) => { history.pushState({}, '', x); dispatchEvent(new PopStateEvent('popstate')); }, w); await settle(p); }
  const r = await p.evaluate(() => { const path = (n) => { const a = []; while (n && n !== document.body) { a.unshift(n.tagName.toLowerCase() + (n.className && typeof n.className === 'string' ? '.' + n.className.trim().split(/\s+/).join('.') : '') + ':' + [...(n.parentNode?.children || [])].indexOf(n)); n = n.parentElement; } return a.join(' > '); };
    return [...document.querySelectorAll('.content *')].map((n) => { const c = getComputedStyle(n); const b = n.getBoundingClientRect(); return [path(n), Math.round(b.height * 10) / 10, c.lineHeight, c.fontSize, c.paddingTop, c.marginTop, c.borderTopWidth, c.display, c.minHeight]; }); });
  await ctx.close(); return r;
}
const cold = await snap([]); const nav = await snap(warmCsv.split(','));
const m = new Map(cold.map((x) => [x[0], x])); let shown = 0;
for (const x of nav) { const y = m.get(x[0]); if (!y) continue; const diff = x.slice(2).some((v, i) => v !== y[i + 2]); if (diff && shown++ < 8) console.log('STYLE', x[0].slice(-160), '\n  cold', y.slice(1).join(' '), '\n  nav ', x.slice(1).join(' ')); }
if (!shown) { for (const x of nav) { const y = m.get(x[0]); if (y && y[1] !== x[1] && shown++ < 6) console.log('HEIGHT', x[0].slice(-160), y[1], '->', x[1]); } }
console.log('elements cold', cold.length, 'nav', nav.length);
await browser.close(); await server.close();
