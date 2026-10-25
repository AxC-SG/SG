#!/usr/bin/env node
// UI 2.0 P8 — axe-core accessibility audit over representative tenant/platform/public routes, fixture-backed.
// Compare a UI 2.0 run to a legacy run to separate regressions from pre-existing violations.
// Usage: PLAYWRIGHT_DIR=<dir> AXE_PATH=<axe.min.js> [CHROMIUM_PATH=<chromium>] \
//   node axe-audit.mjs --base http://127.0.0.1:5175 --out <dir> --label ui2 [--themes dark,light] [--inject-css <file>]
// --inject-css appends a stylesheet after load, to measure a proposed token change without rebuilding.
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { actor, routeFixtures } from './fixtures.mjs';
import { APPROVED_PLATFORM_POLICY_ID, PRIMARY_POLICY_ID, platformActor } from './governance-fixtures.mjs';
import { PRIMARY_CVE } from './cve-fixtures.mjs';
import { PRIMARY_AI_ASSET_ID, PRIMARY_HOST_ID, PRIMARY_SOFTWARE_IDENTITY_ID } from './inventory-fixtures.mjs';
import { PRIMARY_CAMPAIGN_ID } from './experience-fixtures.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((p, v, i, a) => (v.startsWith('--') && p.push([v.slice(2), a[i + 1]]), p), []));
const require = createRequire(path.join(process.env.PLAYWRIGHT_DIR ?? process.cwd(), 'noop.js'));
const { chromium } = require('playwright');
const base = args.base ?? 'http://127.0.0.1:5175';
const out = args.out ?? 'axe';
const label = args.label ?? 'axe';
const themes = (args.themes ?? 'dark,light').split(',');
const axeSource = readFileSync(process.env.AXE_PATH, 'utf8');
const injectCss = args['inject-css'] ? readFileSync(args['inject-css'], 'utf8') : null;
mkdirSync(out, { recursive: true });

const tenant = ['/exposure', '/findings', '/findings/F-10420', '/findings/ai', '/policies', `/policies/${PRIMARY_POLICY_ID}`, '/vuln-repo/org-cves',
  `/vuln-repo/org-cves/${PRIMARY_CVE}`, `/vuln-repo/org-cves/${PRIMARY_CVE}/assets`, '/vuln-repo/campaigns', `/vuln-repo/campaigns/${PRIMARY_CAMPAIGN_ID}`,
  '/inventory/hosts', `/inventory/hosts/${PRIMARY_HOST_ID}`, `/inventory/software-identities/${PRIMARY_SOFTWARE_IDENTITY_ID}`, `/inventory/ai/${PRIMARY_AI_ASSET_ID}`,
  '/connect', '/admin/users', '/admin/audit', '/configurations/sla', '/configurations/suppress'];
const platform = ['/platform/tenants', '/platform/operations', '/platform/ai-policies', `/platform/ai-policies/${APPROVED_PLATFORM_POLICY_ID}`];
const pub = ['/login', '/setup'];

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const rows = [];
for (const theme of themes) {
  for (const [who, routes, signedOut] of [[actor, tenant, false], [platformActor, platform, false], [actor, pub, true]]) {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    await context.addInitScript((v) => localStorage.setItem('scoutai-theme', v), theme);
    await routeFixtures(context, { actorOverride: who });
    if (signedOut) await context.route((u) => u.pathname.endsWith('/api/me'), (r) => r.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
    const page = await context.newPage();
    for (const route of routes) {
      await page.goto(`${base}${route}`, { waitUntil: 'networkidle' });
      if (injectCss) await page.addStyleTag({ content: injectCss });
      await page.waitForTimeout(600);
      await page.evaluate(axeSource);
      const result = await page.evaluate(() => window.axe.run(document, { resultTypes: ['violations'] }));
      for (const v of result.violations) rows.push({ theme, route, rule: v.id, impact: v.impact, nodes: v.nodes.length, sample: v.nodes[0]?.target?.join(' '), contrast: v.id === 'color-contrast' ? v.nodes.map((n) => { const d = n.any[0]?.data ?? {}; return { target: n.target.join(' '), fg: d.fgColor, bg: d.bgColor, ratio: d.contrastRatio, size: d.fontSize }; }) : undefined });
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
