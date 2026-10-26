#!/usr/bin/env node
// Builds both presentation versions into separate artifact folders and checks each one.
//
// UI 2 is built with VITE_UI_VERSION=2 and UI 1 with VITE_UI_VERSION set explicitly empty, so
// neither inherits a value from the shell or a .env file. `npm run build` includes the
// production-bundle security check for both. VITE_API_BASE=/api keeps every API call on the
// artifact's own origin, where the fixtures answer it; without it a production build calls the
// production API. Each copied folder is then served on its own port and checked route by route:
// app and auth routes carry data-ui="2" only in the UI 2 build, and the public marketing, blog
// and demo routes never carry it.
//
// Usage: node e2e/build-artifacts.mjs [--versions ui2,legacy]
import { spawnSync } from 'node:child_process';
import { cpSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { newContext } from './browser.mjs';
import { failOnUnexpectedApi, routeFixtures } from './fixtures.mjs';
import { ARTIFACTS, serveArtifact } from './serve.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);
const versions = (args.versions ?? 'ui2,legacy').split(',');
const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const UI_VERSION = { ui2: '2', legacy: '' };

// Signed-in app routes, auth entry routes (signed out) and the excluded public routes.
const APP_ROUTES = ['/exposure', '/findings', '/vuln-repo/org-cves', '/inventory', '/connect', '/configurations/sla'];
const AUTH_ROUTES = ['/login', '/setup/fixture-token', '/invite/fixture-token', '/tenant-invite/fixture-token'];
const PUBLIC_ROUTES = ['/demo', '/demo/blog', '/demo/blog/mythos-readiness', '/demo/request', '/demo/expired'];

function build(version) {
  console.log(`building ${version} (VITE_UI_VERSION=${JSON.stringify(UI_VERSION[version])})`);
  const result = spawnSync('npm', ['run', 'build'], {
    cwd: frontend, stdio: 'inherit', env: { ...process.env, VITE_UI_VERSION: UI_VERSION[version], VITE_API_BASE: '/api' },
  });
  if (result.status !== 0) throw new Error(`${version} build failed`);
  rmSync(ARTIFACTS[version].dir, { recursive: true, force: true });
  cpSync(path.join(frontend, 'dist'), ARTIFACTS[version].dir, { recursive: true });
}

async function checkBoundary(browser, version) {
  const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
  const failures = [];
  try {
    for (const [routes, signedOut] of [[APP_ROUTES, false], [AUTH_ROUTES, true], [PUBLIC_ROUTES, true]]) {
      const context = await newContext(browser);
      await routeFixtures(context);
      if (signedOut) await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
      const page = await context.newPage();
      for (const route of routes) {
        await page.goto(`${server.url}${route}`, { waitUntil: 'networkidle' });
        const actual = await page.evaluate(() => document.documentElement.getAttribute('data-ui'));
        const expected = version === 'ui2' && routes !== PUBLIC_ROUTES ? '2' : null;
        const final = new URL(page.url()).pathname;
        if (actual !== expected) failures.push(`${version} ${route} -> ${final}: data-ui=${actual}, expected ${expected}`);
      }
      await context.close();
    }
  } finally {
    await server.close();
  }
  console.log(`${version}: data-ui boundary ${failures.length ? 'FAILED' : 'passed'} on ${APP_ROUTES.length + AUTH_ROUTES.length + PUBLIC_ROUTES.length} routes`);
  for (const failure of failures) console.log(`  FAIL ${failure}`);
  return failures.length;
}

for (const version of versions) build(version);
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
let failed = 0;
for (const version of versions) failed += await checkBoundary(browser, version);
await browser.close();
process.exitCode = failed ? 1 : 0;
failOnUnexpectedApi();
