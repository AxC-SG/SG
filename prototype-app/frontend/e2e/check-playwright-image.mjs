#!/usr/bin/env node
// Visual baselines are only comparable when they are rendered by the same browser build and
// system fonts. This check requires the run to be inside mcr.microsoft.com/playwright:v<X.Y.Z>
// with X.Y.Z equal to the pinned @playwright/test version. The container command or CI job
// declares the image through E2E_PLAYWRIGHT_IMAGE.
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const pinned = JSON.parse(readFileSync(require.resolve('@playwright/test/package.json'), 'utf8')).version;
const image = process.env.E2E_PLAYWRIGHT_IMAGE ?? '';
const match = /^mcr\.microsoft\.com\/playwright:v(\d+\.\d+\.\d+)(?:-[a-z]+)?(?:@sha256:[a-f0-9]{64})?$/.exec(image);

if (!match) {
  console.error(`Visual runs need the Playwright container. Set E2E_PLAYWRIGHT_IMAGE to mcr.microsoft.com/playwright:v${pinned}-noble `
    + `and run inside that image (got ${JSON.stringify(image)}).`);
  process.exit(1);
}
if (match[1] !== pinned) {
  console.error(`Playwright image v${match[1]} does not match the pinned @playwright/test ${pinned}.`);
  process.exit(1);
}
if (!existsSync('/ms-playwright')) {
  console.error('E2E_PLAYWRIGHT_IMAGE is set, but /ms-playwright is missing; this is not the Playwright image.');
  process.exit(1);
}
console.log(`Playwright image v${match[1]} matches @playwright/test ${pinned}.`);

