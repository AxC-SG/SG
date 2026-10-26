// Deterministic browser setup shared by the fixture-backed scripts and the visual spec.
//
// Every context gets the same locale, time zone and fixed clock, requests to other hosts are
// blocked, animations and transitions take zero time, and the Google Fonts import in
// src/styles/base.css is answered from the font files bundled in node_modules (the same Space
// Grotesk and IBM Plex Sans weights it requests). Nothing is masked: scores, IDs, selected states
// and controls render as they do for a user.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { FIXED_TIME } from './time.mjs';

export const CONTEXT_OPTIONS = { locale: 'en-US', timezoneId: 'UTC', reducedMotion: 'reduce' };

const require = createRequire(import.meta.url);
const FONT_HOST = 'https://fonts.gstatic.com/e2e/';
const FONTS = [
  ['Space Grotesk', '@fontsource/space-grotesk', 'space-grotesk', [500, 600, 700]],
  ['IBM Plex Sans', '@fontsource/ibm-plex-sans', 'ibm-plex-sans', [400, 500, 600]],
].flatMap(([family, pkg, slug, weights]) => weights.map((weight) => ({
  family, weight, file: `${slug}-latin-${weight}-normal.woff2`,
  path: require.resolve(`${pkg}/files/${slug}-latin-${weight}-normal.woff2`),
})));
const FONT_CSS = FONTS.map(({ family, weight, file }) => `@font-face { font-family: '${family}'; font-style: normal; `
  + `font-weight: ${weight}; font-display: block; src: url('${FONT_HOST}${file}') format('woff2'); }`).join('\n');

// Animations and transitions take zero time instead of being removed, so each element lands in its
// final state. Removing them would drop fill-mode end states (for example a panel's settled
// transform) and render a layout no user sees.
const NO_MOTION = '*, *::before, *::after { animation-duration: 0s !important; animation-delay: 0s !important; '
  + 'transition-duration: 0s !important; transition-delay: 0s !important; caret-color: transparent !important; }';

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost']);

/** Applies the deterministic settings to a context created with CONTEXT_OPTIONS. */
export async function prepareContext(context) {
  await context.clock.setFixedTime(FIXED_TIME);
  // Nothing leaves the machine: requests to any other host are aborted. Registered first, so the
  // font routes below and the fixture routes added later take precedence for what they answer.
  await context.route((url) => !LOCAL_HOSTS.has(url.hostname), (route) => route.abort('blockedbyclient'));
  await context.addInitScript((css) => {
    const apply = () => {
      const style = document.createElement('style');
      style.dataset.e2e = 'no-motion';
      style.textContent = css;
      document.head.append(style);
    };
    if (document.head) apply();
    else document.addEventListener('DOMContentLoaded', apply, { once: true });
  }, NO_MOTION);
  await context.route('https://fonts.googleapis.com/**', (route) => route.fulfill({ contentType: 'text/css', body: FONT_CSS }));
  await context.route('https://fonts.gstatic.com/**', (route) => {
    const font = FONTS.find(({ file }) => route.request().url() === `${FONT_HOST}${file}`);
    return font
      ? route.fulfill({ contentType: 'font/woff2', body: readFileSync(font.path) })
      : route.fulfill({ status: 404, body: '' });
  });
}

/** A new deterministic context; `options` add to or override CONTEXT_OPTIONS. */
export async function newContext(browser, options = {}) {
  const context = await browser.newContext({ ...CONTEXT_OPTIONS, ...options });
  await prepareContext(context);
  return context;
}
