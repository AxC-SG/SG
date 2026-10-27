import { defineConfig } from '@playwright/test';
import { ARTIFACTS } from './e2e/serve.mjs';
import { CONTEXT_OPTIONS } from './e2e/browser.mjs';

// Visual baselines only. Journeys, the route sweep and axe run as plain scripts (see e2e/run.mjs).
// The UI 2 candidate has its own artifact server and baseline folder. UI 1 baselines stay in the repo.
const versions = (process.env.E2E_VERSIONS ?? 'ui2').split(',') as Array<keyof typeof ARTIFACTS>;
if (versions.length !== 1 || versions[0] !== 'ui2') {
  throw new Error('Candidate visual checks run only on UI 2; UI 1 baselines are retained as historical evidence.');
}

export default defineConfig({
  testDir: './e2e',
  testMatch: 'visual.spec.ts',
  outputDir: './e2e/.results/visual',
  snapshotPathTemplate: '{testDir}/visual-baselines/{projectName}/{arg}{ext}',
  workers: Number(process.env.E2E_WORKERS ?? 2),
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  reporter: [['list'], ['html', { outputFolder: './e2e/.results/visual-report', open: 'never' }]],
  expect: { toHaveScreenshot: { maxDiffPixelRatio: 0.001, animations: 'disabled', caret: 'hide' } },
  use: { ...CONTEXT_OPTIONS, browserName: 'chromium', trace: 'retain-on-failure' },
  projects: versions.map((version) => ({
    name: version,
    use: { baseURL: `http://127.0.0.1:${ARTIFACTS[version].port}` },
  })),
  webServer: versions.map((version) => ({
    command: `node e2e/serve-cli.mjs ${version}`,
    url: `http://127.0.0.1:${ARTIFACTS[version].port}/login`,
    reuseExistingServer: false,
  })),
});
