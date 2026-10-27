// Measures states the general probe does not reach: sub-navigation hover (active and inactive) and
// the three modal scrims (.modal-backdrop, .fd3-modal-overlay, dialog.confirm-dialog::backdrop),
// injected into a real app page so only the stylesheet decides their look.
// Usage: node state-check.mjs <frontend dir> <artifact dir> <port> <out.json>
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [fe, dir, port, outFile] = process.argv.slice(2);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { newContext } = await imp('e2e/browser.mjs');
const { actor, routeFixtures } = await imp('e2e/fixtures.mjs');
const { serveArtifact } = await imp('e2e/serve.mjs');
const server = await serveArtifact(dir, Number(port));
const browser = await chromium.launch();
const out = {};
const read = (n, pseudo) => { const c = getComputedStyle(n, pseudo); return [c.backgroundColor, c.color, c.boxShadow, c.transform, c.fontWeight].join('|'); };
try {
  for (const theme of ['dark', 'light']) for (const route of ['/findings', '/inventory/hosts', '/vuln-repo/org-cves', '/connect', '/admin/users']) {
    const ctx = await newContext(browser, { baseURL: server.url, viewport: { width: 1280, height: 900 } });
    await ctx.addInitScript((v) => localStorage.setItem('scoutai-theme', v), theme);
    await routeFixtures(ctx, { actorOverride: actor });
    const page = await ctx.newPage();
    await page.goto(route); await page.waitForLoadState('networkidle');
    const key = `${route}|${theme}`;
    out[key] = { dataUi: await page.evaluate(() => document.documentElement.getAttribute('data-ui')), sub: [] };
    // Open every collapsed nav group so its sub-items render.
    const toggles = page.locator(".nav-expand-toggle[aria-label^='Expand']");
    while (await toggles.count()) await toggles.first().click();
    await page.mouse.move(0, 0);
    const subs = page.locator('.nav-sub-btn');
    for (let i = 0; i < Math.min(await subs.count(), 12); i++) {
      const el = subs.nth(i);
      if (!(await el.isVisible())) continue;
      await el.hover();
      out[key].sub.push(await el.evaluate((n, src) => `${n.className}: ${new Function('return ' + src)()(n)}`, read.toString()));
    }
    await page.mouse.move(0, 0);
    out[key].scrims = await page.evaluate(() => {
      const r = (n, p) => getComputedStyle(n, p).backgroundColor;
      const a = document.createElement('div'); a.className = 'modal-backdrop'; document.body.append(a);
      const b = document.createElement('div'); b.className = 'fd3-modal-overlay'; document.body.append(b);
      const d = document.createElement('dialog'); d.className = 'confirm-dialog'; d.textContent = 'x'; document.body.append(d); d.showModal();
      const res = { modalBackdrop: r(a), fd3Overlay: r(b), dialogBackdrop: r(d, '::backdrop'), dialog: [r(d), getComputedStyle(d).borderTopColor].join('|') };
      d.close(); a.remove(); b.remove(); d.remove();
      return res;
    });
    await ctx.close();
  }
} finally { await browser.close(); await server.close(); }
writeFileSync(outFile, JSON.stringify(out, null, 1));
console.log(Object.entries(out).map(([k, v]) => `${k} data-ui=${v.dataUi} sub=${v.sub.length} scrim=${v.scrims.dialogBackdrop}`).join('\n'));
