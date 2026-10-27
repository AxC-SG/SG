// Automated aid for the keyboard and 200% zoom review (not a replacement for the human review).
// Keyboard: on every e2e route at 1280px, presses Tab up to 40 times and records each focus stop:
// whether it is on screen and whether it shows a focus indicator (outline, or a box-shadow /
// border / background that differs from the unfocused element). Zoom: loads every route at
// 640x450 CSS px with deviceScaleFactor 2 (what a 1280x900 window shows at 200% zoom) and records
// horizontal page overflow and page errors.
// Usage: node keyboard-zoom.mjs <frontend dir> <ui2|legacy> <out.json>
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [fe, version, outFile] = process.argv.slice(2);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { newContext } = await imp('e2e/browser.mjs');
const { actor, routeFixtures } = await imp('e2e/fixtures.mjs');
const { platformActor } = await imp('e2e/governance-fixtures.mjs');
const { ALL_ROUTES } = await imp('e2e/routes.mjs');
const { ARTIFACTS, serveArtifact } = await imp('e2e/serve.mjs');

const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
const browser = await chromium.launch();
const result = { version, keyboard: {}, zoom: {} };
async function open(route, who, options) {
  const context = await newContext(browser, { baseURL: server.url, ...options });
  await context.addInitScript(() => localStorage.setItem('scoutai-theme', 'dark'));
  await routeFixtures(context, { actorOverride: who === 'platform' ? platformActor : actor });
  if (who === 'signedOut') await context.route((url) => url.pathname.endsWith('/api/me'), (r) => r.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.goto(route, { waitUntil: 'networkidle' });
  return { context, page, errors };
}
try {
  for (const [route, who] of ALL_ROUTES) {
    const { context, page } = await open(route, who, { viewport: { width: 1280, height: 900 } });
    const stops = [];
    for (let i = 0; i < 40; i++) {
      await page.keyboard.press('Tab');
      const stop = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el || el === document.body) return null;
        const r = el.getBoundingClientRect();
        const focused = getComputedStyle(el);
        const visibleOutline = focused.outlineStyle !== 'none' && parseFloat(focused.outlineWidth) > 0;
        const snapshot = [focused.boxShadow, focused.borderTopColor, focused.backgroundColor, focused.outlineColor].join('|');
        el.blur();
        const plain = getComputedStyle(el);
        const plainSnapshot = [plain.boxShadow, plain.borderTopColor, plain.backgroundColor, plain.outlineColor].join('|');
        el.focus({ preventScroll: true });
        return {
          id: `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ''}.${String(el.className).trim().split(/\s+/).slice(0, 2).join('.')}`.slice(0, 80),
          onScreen: r.width > 0 && r.height > 0 && r.bottom > 0 && r.top < innerHeight && r.right > 0 && r.left < innerWidth,
          indicator: visibleOutline || snapshot !== plainSnapshot,
        };
      });
      if (!stop) break;
      stops.push(stop);
    }
    const unique = new Set(stops.map((s) => s.id)).size;
    result.keyboard[route] = {
      stops: stops.length, unique,
      offScreen: stops.filter((s) => !s.onScreen).map((s) => s.id),
      noIndicator: [...new Set(stops.filter((s) => !s.indicator).map((s) => s.id))],
    };
    await context.close();
    const zoom = await open(route, who, { viewport: { width: 640, height: 450 }, deviceScaleFactor: 2 });
    result.zoom[route] = await zoom.page.evaluate(() => ({ overflow: document.documentElement.scrollWidth - innerWidth }));
    result.zoom[route].errors = zoom.errors.length;
    await zoom.context.close();
    process.stdout.write('.');
  }
} finally {
  await browser.close();
  await server.close();
}
writeFileSync(outFile, JSON.stringify(result, null, 1));
const k = Object.entries(result.keyboard);
console.log(`\n${version} keyboard: ${k.length} routes; routes with focus stops off screen: ${k.filter(([, v]) => v.offScreen.length).length}; routes with stops lacking a focus indicator: ${k.filter(([, v]) => v.noIndicator.length).length}; routes with fewer than 3 distinct stops: ${k.filter(([, v]) => v.unique < 3).map(([r]) => r).join(', ') || 'none'}`);
const z = Object.entries(result.zoom);
console.log(`${version} 200% zoom approximation: ${z.length} routes; horizontal overflow > 1px: ${z.filter(([, v]) => v.overflow > 1).map(([r, v]) => `${r} (+${v.overflow}px)`).join(', ') || 'none'}; page errors: ${z.reduce((s, [, v]) => s + v.errors, 0)}`);
