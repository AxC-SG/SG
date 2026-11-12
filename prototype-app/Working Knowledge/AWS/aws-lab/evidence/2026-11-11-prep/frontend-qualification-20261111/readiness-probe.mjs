import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { chromium } from '/work/node_modules/@playwright/test/index.mjs';
import { waitForPageReady } from '/work/e2e/browser.mjs';
const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  await page.setContent('<main><div id="result">Loading page...</div></main>');
  await page.evaluate(() => setTimeout(() => { document.getElementById('result').textContent = 'Delayed fixture is ready'; }, 750));
  await waitForPageReady(page);
  assert.equal(await page.locator('#result').textContent(), 'Delayed fixture is ready');
  await page.setContent('<main><div hidden>Loading page...</div><p>Ready content</p></main>');
  await waitForPageReady(page);
  await page.setContent('<main><div>Loading page...</div></main>');
  await assert.rejects(waitForPageReady(page), /toHaveCount|Timed out|Timeout/);
  const result = { delayed_render_waited: true, hidden_loading_copy_ignored: true, permanently_loading_page_rejected: true };
  writeFileSync('/evidence/readiness-probe.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
} finally {
  await browser.close();
}
