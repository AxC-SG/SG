#!/usr/bin/env node
// Builds the current UI 2 candidate and checks its route boundary.
// Legacy comparisons use the checksum-verified frozen Step 5 artifact; never rebuild UI 1.
//
// UI 2 is always active on app routes. `npm run build` includes the production-bundle
// security check. VITE_API_BASE=/api keeps every API call on the artifact's own origin,
// where the fixtures answer it. App and auth routes carry data-ui="2"; public marketing,
// blog and demo routes never carry it.
//
// Usage: node e2e/build-artifacts.mjs [--versions ui2]
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
const versions = (args.versions ?? process.env.E2E_VERSIONS ?? 'ui2').split(',');
if (versions.length !== 1 || versions[0] !== 'ui2') {
  throw new Error('Only UI 2 may be rebuilt. Use the checksum-verified frozen Step 5 artifact for legacy comparisons.');
}
const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Signed-in app routes, auth entry routes (signed out) and the excluded public routes.
const APP_ROUTES = ['/exposure', '/findings', '/vuln-repo/org-cves', '/inventory', '/connect', '/configurations/sla'];
const AUTH_ROUTES = ['/login', '/setup/fixture-token', '/invite/fixture-token', '/tenant-invite/fixture-token'];
const PUBLIC_ROUTES = ['/demo', '/demo/blog', '/demo/blog/mythos-readiness', '/demo/request', '/demo/expired'];

function build(version) {
  console.log(`building ${version}`);
  const result = spawnSync('npm', ['run', 'build'], {
    cwd: frontend, stdio: 'inherit', env: { ...process.env, VITE_API_BASE: '/api' },
  });
  if (result.status !== 0) throw new Error(`${version} build failed`);
  rmSync(ARTIFACTS[version].dir, { recursive: true, force: true });
  cpSync(path.join(frontend, 'dist'), ARTIFACTS[version].dir, { recursive: true });
}

// Permanent public isolation checks run on the built artifact in CI. These use real
// router links and browser history, retaining theme/storage and computed public styles.
async function checkPublicNavigation(browser, server, version, failures) {
  let checks = 0;
  const publicCanvases = new Map();
  for (const theme of ['dark', 'light']) for (const width of [390, 1280]) {
    const context = await newContext(browser, { viewport: { width, height: 900 } });
    try {
      await routeFixtures(context);
      await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
      await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
      const page = await context.newPage();
      const check = async (pathname, publicPage, baseline) => {
        await page.waitForURL((url) => url.pathname === pathname);
        await page.locator(publicPage ? '.public-demo-shell:not(.ui2-experience-family)' : '.public-demo-shell.ui2-experience-family').waitFor({ state: 'visible' });
        await page.waitForLoadState('networkidle');
        const snapshot = await page.evaluate(() => {
          const root = document.documentElement, css = getComputedStyle(root), body = getComputedStyle(document.body);
          // Test the header text against both possible backdrops behind its translucent surface.
          // This catches a fixed light header inheriting dark-theme text, even when axe skips it.
          const canvas = document.createElement('canvas');
          canvas.width = canvas.height = 1;
          const context = canvas.getContext('2d');
          const rgba = (color) => {
            context.clearRect(0, 0, 1, 1);
            context.fillStyle = color;
            context.fillRect(0, 0, 1, 1);
            return [...context.getImageData(0, 0, 1, 1).data];
          };
          const luminance = (channels) => channels.map((value) => {
            const s = value / 255;
            return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
          }).reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
          const background = rgba(getComputedStyle(document.querySelector('.public-demo-nav')).backgroundColor);
          const headerMinContrast = Math.min(...[...document.querySelectorAll('.public-demo-brand strong, .public-demo-links a:not([class])')].flatMap((link) => {
            const text = luminance(rgba(getComputedStyle(link).color).slice(0, 3));
            return [0, 255].map((backdrop) => {
              const surface = luminance(background.slice(0, 3).map((channel) => channel * background[3] / 255 + backdrop * (1 - background[3] / 255)));
              return (Math.max(text, surface) + 0.05) / (Math.min(text, surface) + 0.05);
            });
          }));
          return { ui: root.getAttribute('data-ui'), theme: root.getAttribute('data-theme'), stored: localStorage.getItem('scoutai-theme'),
            appToken: css.getPropertyValue('--dp-accent').trim(), publicToken: css.getPropertyValue('--accent').trim(),
            body: [body.color, body.backgroundImage, body.backgroundColor, body.fontFamily], headerMinContrast };
        });
        checks++;
        const prefix = `${version} ${theme}/${width} ${pathname}`;
        if (snapshot.ui !== (publicPage ? null : '2') || snapshot.theme !== theme || snapshot.stored !== theme) failures.push(`${prefix}: route/theme boundary ${JSON.stringify(snapshot)}`);
        if (publicPage ? snapshot.appToken !== '' || snapshot.publicToken === '' : snapshot.appToken === '' || snapshot.publicToken !== '') failures.push(`${prefix}: token isolation ${JSON.stringify(snapshot)}`);
        if (!publicPage && snapshot.headerMinContrast < 4.5) failures.push(`${prefix}: auth header text contrast ${snapshot.headerMinContrast.toFixed(2)}:1, expected at least 4.5:1`);
        if (baseline && JSON.stringify(snapshot) !== JSON.stringify(baseline)) failures.push(`${prefix}: public styles differ from direct load`);
        return snapshot;
      };
      await page.goto(`${server.url}/demo`, { waitUntil: 'networkidle' });
      const direct = await check('/demo', true);
      const canvas = JSON.stringify(direct.body);
      if (publicCanvases.has(width) && publicCanvases.get(width) !== canvas) failures.push(`${version} ${width}: public canvas changes with the stored theme`);
      publicCanvases.set(width, canvas);
      await page.locator('.public-demo-nav a[href="/login"]').click();
      await check('/login', false);
      await page.locator('a.public-demo-brand[href="/demo"]').click();
      await check('/demo', true, direct);
      await page.goBack();
      await check('/login', false);
      await page.goForward();
      await check('/demo', true, direct);
    } finally {
      await context.close();
    }
  }
  return checks;
}

async function checkBoundary(browser, version) {
  const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
  const failures = [];
  let navigationChecks = 0;
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
    navigationChecks = await checkPublicNavigation(browser, server, version, failures);
  } finally {
    await server.close();
  }
  console.log(`${version}: data-ui boundary ${failures.length ? 'FAILED' : 'passed'} on ${APP_ROUTES.length + AUTH_ROUTES.length + PUBLIC_ROUTES.length} direct routes and ${navigationChecks} public/history checks`);
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
