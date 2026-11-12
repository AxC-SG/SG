import { spawn } from 'node:child_process';
import { ARTIFACTS, serveArtifact } from '/work/e2e/serve.mjs';
const server = await serveArtifact(ARTIFACTS.ui2.dir, ARTIFACTS.ui2.port);
try {
  const statuses = await Promise.all((process.argv.length > 2 ? process.argv.slice(2) : ['inventory', 'connect']).map((name) => new Promise((resolve) => {
    const child = spawn(process.execPath, [`e2e/${name}-journey.mjs`, '--base', server.url,
      '--out', `e2e/.results/ui2/journeys/${name}`, '--label', 'ui2'], {
      cwd: '/work', stdio: 'inherit', env: { ...process.env, E2E_KNOWN_FAILURES: '/work/e2e/journey-baseline/ui2.json' },
    });
    child.once('error', () => resolve(1));
    child.once('close', (code) => resolve(code ?? 1));
  })));
  process.exitCode = statuses.some((status) => status !== 0) ? 1 : 0;
} finally {
  await server.close();
}
