import { spawn } from 'node:child_process';
import { ARTIFACTS, serveArtifact } from '/work/e2e/serve.mjs';
const part = process.argv[2];
const server = await serveArtifact(ARTIFACTS.ui2.dir, ARTIFACTS.ui2.port);
async function run(file, args) {
  const child = spawn(process.execPath, [`e2e/${file}`, ...args], { cwd: '/work', stdio: 'inherit' });
  const code = await new Promise((resolve) => { child.once('error', () => resolve(1)); child.once('close', (c) => resolve(c ?? 1)); });
  if (code) throw new Error(`${file} exited ${code}`);
}
try {
  if (part === 'light') {
    await run('route-sweep.mjs', ['--base', server.url, '--out', 'e2e/.results/qualified/sweep', '--label', 'ui2_light', '--theme', 'light', '--widths', '390,768,1280,1440']);
  } else if (part === 'axe') {
    await run('axe-audit.mjs', ['--base', server.url, '--out', 'e2e/.results/qualified/axe', '--label', 'ui2', '--widths', '390,768,1280,1440']);
    await run('axe-compare.mjs', ['--run', 'e2e/.results/qualified/axe/ui2_axe.json', '--baseline', 'e2e/axe-baseline/ui2.json', '--widths', '390,768,1280,1440']);
  } else throw new Error('Unknown verification part');
} finally { await server.close(); }
