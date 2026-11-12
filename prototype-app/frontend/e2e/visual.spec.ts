// Visual baselines per UI version (one Playwright project each, own baseline folder).
// Fixture-backed and deterministic (see browser.mjs); not authenticated staging evidence.
// E2E_ROUTES (comma-separated paths) and E2E_WIDTHS narrow the run for e2e:affected.
import { expect, test } from '@playwright/test';
import { prepareContext, waitForPageReady } from './browser.mjs';
import { actor, routeFixtures } from './fixtures.mjs';
import { platformActor } from './governance-fixtures.mjs';
import { ALL_ROUTES, routeEntry } from './routes.mjs';

const routes = process.env.E2E_ROUTES ? process.env.E2E_ROUTES.split(',').map(routeEntry) : ALL_ROUTES;
const widths = (process.env.E2E_WIDTHS ?? '1280,390').split(',').map(Number);
const themes = ['dark', 'light'];
const actors = { tenant: actor, platform: platformActor, signedOut: actor };

const nameOf = (path: string, theme: string, width: number) =>
  `${path.replace(/\W+/g, '-').replace(/^-|-$/g, '') || 'root'}_${theme}_${width}.png`;

for (const [path, who] of routes) {
  for (const theme of themes) {
    for (const width of widths) {
      test(`${path} ${theme} ${width}`, async ({ context, page }) => {
        await prepareContext(context);
        await context.addInitScript((value) => localStorage.setItem('scoutai-theme', value), theme);
        await routeFixtures(context, { actorOverride: actors[who as keyof typeof actors] });
        if (who === 'signedOut') {
          await context.route((url) => url.pathname.endsWith('/api/me'), (route) => route.fulfill({ status: 401, json: { message: 'Unauthorized (fixture)' } }));
        }
        const errors: string[] = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.setViewportSize({ width, height: 900 });
        await page.goto(path, { waitUntil: 'networkidle' });
        await waitForPageReady(page);
        await page.evaluate(() => document.fonts.ready);
        await expect(page).toHaveScreenshot(nameOf(path, theme, width), { fullPage: true });
        expect(errors).toEqual([]);
      });
    }
  }
}
