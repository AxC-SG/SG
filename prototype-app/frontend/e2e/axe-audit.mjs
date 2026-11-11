#!/usr/bin/env node
// UI 2.0 P8 — axe-core accessibility audit over representative tenant/platform/public routes, fixture-backed.
// Compare a UI 2.0 run to a legacy run to separate regressions from pre-existing violations.
// Usage: [CHROMIUM_PATH=<chromium>] \
//   node axe-audit.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light] [--widths 1280,390]
//   [--routes /findings,/login] [--inject-css <file>]
// --routes replaces the default route list (every routes.mjs route plus AUDIT_ONLY); each path
// takes its actor from routes.mjs.
// --inject-css appends a stylesheet after load, to measure a proposed token change without rebuilding.
import { createRequire } from 'node:module';
import { chromium } from '@playwright/test';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { newContext, waitForPageReady } from './browser.mjs';
import { actor, failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import { platformActor } from './governance-fixtures.mjs';
import { ALL_ROUTES, routeEntry } from './routes.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((p, v, i, a) => (v.startsWith('--') && p.push([v.slice(2), a[i + 1]]), p), []));
const base = args.base ?? 'http://127.0.0.1:5175';
const out = args.out ?? 'axe';
const label = args.label ?? 'axe';
const themes = (args.themes ?? 'dark,light').split(',');
const widths = (args.widths ?? '1280,390').split(',').map(Number);
const axeSource = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8');
const injectCss = args['inject-css'] ? readFileSync(args['inject-css'], 'utf8') : null;
mkdirSync(out, { recursive: true });

// The default audits every route in routes.mjs, so e2e:affected never meets a route the baseline
// has not seen, plus routes audited here only.
const AUDIT_ONLY = ['/admin/audit', '/configurations/suppress'];
const selected = (args.routes?.split(',') ?? [...ALL_ROUTES.map(([route]) => route), ...AUDIT_ONLY]).map(routeEntry);
const groups = [[actor, selected.filter(([, who]) => who === 'tenant').map(([route]) => route), false],
  [platformActor, selected.filter(([, who]) => who === 'platform').map(([route]) => route), false],
  [actor, selected.filter(([, who]) => who === 'signedOut').map(([route]) => route), true]];

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const rows = [];
const pageErrors = [];
for (const theme of themes) for (const width of widths) {
  for (const [who, routes, signedOut] of groups) {
    if (!routes.length) continue;
    const context = await newContext(browser, { viewport: { width, height: 1000 } });
    await context.addInitScript((v) => localStorage.setItem('scoutai-theme', v), theme);
    await routeFixtures(context, { actorOverride: who });
    if (signedOut) await context.route((u) => u.pathname.endsWith('/api/me'), (r) => r.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
    const page = await context.newPage();
    page.on('pageerror', (error) => pageErrors.push(`${theme} ${page.url().replace(base, '')}: ${error.message}`));
    for (const route of routes) {
      await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
      await waitForPageReady(page);
      if (injectCss) await page.addStyleTag({ content: injectCss });
      await page.waitForTimeout(600);
      await page.evaluate(axeSource);
      const result = await page.evaluate(() => window.axe.run(document, { resultTypes: ['violations'] }));
      for (const v of result.violations) rows.push({ theme, width, route, rule: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target?.join(' '), targets: v.nodes.map((n) => n.target.join(' ')), contrast: v.id === 'color-contrast' ? v.nodes.map((n) => { const d = n.any[0]?.data ?? {}; return { target: n.target.join(' '), fg: d.fgColor, bg: d.bgColor, ratio: d.contrastRatio, size: d.fontSize }; }) : undefined });
    }
    await context.close();
  }
}
await browser.close();
writeFileSync(path.join(out, `${label}_axe.json`), JSON.stringify(rows, null, 2));
const by = {};
for (const r of rows) { const k = `${r.impact}:${r.rule}`; by[k] = by[k] ?? { routes: new Set(), nodes: 0 }; by[k].routes.add(r.theme + r.route); by[k].nodes += r.nodes; }
console.log(`${label}: ${rows.length} violation entries`);
for (const [k, v] of Object.entries(by).sort((a, b) => b[1].nodes - a[1].nodes)) console.log(`${k} pages=${v.routes.size} nodes=${v.nodes}`);
// Violations are judged against the reviewed baseline by axe-compare.mjs; this run fails only
// when a page could not be audited as intended.
for (const error of pageErrors) console.log(`ERROR ${error}`);
process.exitCode = pageErrors.length ? 1 : 0;
failOnUnexpectedApi();
