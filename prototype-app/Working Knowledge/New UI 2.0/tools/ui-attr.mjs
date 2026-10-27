// Serves an artifact folder and prints data-ui on a few routes (UI 1 builds must print null).
// Usage: node ui-attr.mjs <frontend dir> <artifact dir> <port>
import path from 'node:path'; import { pathToFileURL } from 'node:url';
const [fe, dir, port] = process.argv.slice(2);
const imp = (p) => import(pathToFileURL(path.join(fe, p)).href);
const { chromium } = await imp('node_modules/@playwright/test/index.mjs');
const { serveArtifact } = await imp('e2e/serve.mjs');
const server = await serveArtifact(dir, Number(port)); const browser = await chromium.launch();
const page = await browser.newPage();
await page.route((u) => !['127.0.0.1', 'localhost'].includes(u.hostname), (r) => r.abort());
for (const p of ['/login', '/findings', '/inventory', '/demo']) {
  await page.goto(server.url + p); await page.waitForTimeout(800);
  console.log(p, 'data-ui =', await page.evaluate(() => document.documentElement.getAttribute('data-ui')));
}
await browser.close(); await server.close();
