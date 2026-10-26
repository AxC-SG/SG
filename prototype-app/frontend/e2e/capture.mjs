#!/usr/bin/env node
// UI 2.0 visual fixture capture.
//
// Drives a local Vite dev server with every /api request answered from deterministic
// fixtures (no backend, no token, no customer data). Screenshots are visual-review
// evidence only: they are NOT authenticated or persistence verification.
//
// Usage:
//   [CHROMIUM_PATH=<chromium>] \
//   node capture.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--routes /exposure,/findings]
import { chromium } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext } from './browser.mjs';
import { failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);

const base = args.base ?? 'http://127.0.0.1:5175';
const out = args.out ?? 'screenshots';
const label = args.label ?? 'capture';
const routes = (args.routes ?? '/exposure,/findings,/findings/ai,/vuln-repo/vulnerabilities,/inventory,/connect,/configurations,/admin').split(',');
const themes = (args.themes ?? 'dark,light').split(',');
const widths = (args.widths ?? '1440,390').split(',').map(Number);

mkdirSync(out, { recursive: true });
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const log = [];
for (const theme of themes) {
  for (const width of widths) {
    const context = await newContext(browser, { viewport: { width, height: 900 } });
    await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
    await routeFixtures(context);
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    for (const route of routes) {
      await page.goto(base + route, { waitUntil: 'networkidle' });
      await page.waitForTimeout(400);
      const name = `${label}_${route.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'root'}_${theme}_${width}.png`;
      await page.screenshot({ path: path.join(out, name), fullPage: false });
      const uiAttr = await page.evaluate(() => document.documentElement.getAttribute('data-ui'));
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
      log.push({ route, theme, width, finalUrl: page.url(), dataUi: uiAttr, horizontalOverflow: overflow, file: name, pageErrors: [...errors] });
      errors.length = 0;
    }
    await context.close();
  }
}
await browser.close();
writeFileSync(path.join(out, `${label}_log.json`), JSON.stringify(log, null, 2));
console.log(JSON.stringify(log.map(({ route, theme, width, finalUrl, dataUi, horizontalOverflow, pageErrors }) => ({ route, theme, width, finalUrl: finalUrl.replace(base, ''), dataUi, horizontalOverflow, errors: pageErrors.length })), null, 0));
process.exitCode = log.some((entry) => entry.pageErrors.length) ? 1 : 0;
failOnUnexpectedApi();
