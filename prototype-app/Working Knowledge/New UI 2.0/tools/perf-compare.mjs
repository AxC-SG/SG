// Runtime load comparison of two builds on the fixture-backed routes (no backend). Each build is
// served the same way, every route is loaded cold in a fresh context several times, and the
// medians of DOMContentLoaded, load, largest contentful paint, transferred script/style bytes and
// JS heap are reported. Requests to other hosts are blocked for both builds alike. The clock is
// not frozen here (unlike the visual runs) so the timings are real.
// Usage: node perf-compare.mjs <frontend dir> <out.json> <label>=<artifact dir> <label>=<artifact dir> [--runs 7]
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [fe, outFile, ...rest] = process.argv.slice(2);
const runsArg = rest.indexOf('--runs');
const runs = runsArg >= 0 ? Number(rest[runsArg + 1]) : 7;
const builds = rest.filter((arg, index) => arg.includes('=') && rest[index - 1] !== '--runs').map((arg) => arg.split('='));
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { actor, routeFixtures } = await imp('e2e/fixtures.mjs');
const { serveArtifact } = await imp('e2e/serve.mjs');
const ROUTES = ['/login', '/exposure', '/findings', '/vuln-repo/org-cves', '/inventory', '/connect'];
const LOCAL = new Set(['127.0.0.1', 'localhost']);
const median = (values) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.floor(sorted.length / 2)]; };

const browser = await chromium.launch();
const result = { runs, routes: ROUTES, builds: {} };
let port = 5300;
try {
  for (const [label, dir] of builds) {
    const server = await serveArtifact(dir, port++);
    result.builds[label] = {};
    for (const route of ROUTES) {
      const samples = [];
      for (let run = 0; run < runs + 1; run++) {
        const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'en-US', timezoneId: 'UTC' });
        await context.route((url) => !LOCAL.has(url.hostname), (r) => r.abort('blockedbyclient'));
        await routeFixtures(context, { actorOverride: actor });
        if (route === '/login') await context.route((url) => url.pathname.endsWith('/api/me'), (r) => r.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
        await context.addInitScript(() => {
          window.__lcp = 0;
          new PerformanceObserver((list) => { for (const entry of list.getEntries()) window.__lcp = entry.startTime; }).observe({ type: 'largest-contentful-paint', buffered: true });
        });
        const page = await context.newPage();
        await page.goto(server.url + route, { waitUntil: 'networkidle' });
        await page.waitForTimeout(300);
        const sample = await page.evaluate(() => {
          const nav = performance.getEntriesByType('navigation')[0];
          const resources = performance.getEntriesByType('resource');
          const bytes = (type) => resources.filter((r) => r.name.endsWith(`.${type}`)).reduce((sum, r) => sum + r.encodedBodySize, 0);
          return { dcl: nav.domContentLoadedEventEnd, load: nav.loadEventEnd, lcp: window.__lcp, js: bytes('js'), css: bytes('css'), heap: performance.memory?.usedJSHeapSize ?? 0 };
        });
        await context.close();
        if (run > 0) samples.push(sample); // the first run warms the server and the browser
      }
      result.builds[label][route] = Object.fromEntries(Object.keys(samples[0]).map((key) => [key, Math.round(median(samples.map((s) => s[key])))]));
    }
    await server.close();
  }
} finally {
  await browser.close();
}
writeFileSync(outFile, JSON.stringify(result, null, 1));
const labels = Object.keys(result.builds);
console.log(`median of ${runs} cold loads per route; ms for dcl/load/lcp, bytes for js/css/heap`);
for (const route of ROUTES) {
  console.log(route);
  for (const label of labels) console.log(`  ${label.padEnd(12)} ${Object.entries(result.builds[label][route]).map(([k, v]) => `${k} ${v}`).join('  ')}`);
}
