#!/usr/bin/env node
// Runs the fixture-backed checks against the artifacts built by build-artifacts.mjs.
//
//   node e2e/run.mjs journeys [--versions ui2]
//   node e2e/run.mjs sweep    [--versions ui2] [--widths 390,768,1280,1440]
//   node e2e/run.mjs visual   [--versions ui2]
//   node e2e/run.mjs affected --routes /findings,/login [--versions ui2]
//   node e2e/run.mjs update   [--versions ui2]
//
// The UI 2 candidate is served from its artifact folder and port. Output goes to
// e2e/.results/<version>/. The process exits non-zero when any step fails.
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ARTIFACTS, serveArtifact } from './serve.mjs';

const [command, ...rest] = process.argv.slice(2);
const args = Object.fromEntries(
  rest.reduce((pairs, value, index, all) => {
    if (value.startsWith('--')) pairs.push([value.slice(2), all[index + 1]]);
    return pairs;
  }, [])
);
const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, '..');
const versions = (args.versions ?? process.env.E2E_VERSIONS ?? 'ui2').split(',');
if (versions.length !== 1 || versions[0] !== 'ui2') {
  throw new Error('Candidate checks run only on UI 2. Use tools/rollback-rehearsal.mjs for the checksum-verified frozen UI 1 artifact.');
}
const JOURNEYS = ['findings', 'cve', 'inventory', 'governance', 'connect', 'experience'];
const THEMES = ['dark', 'light'];
const AFFECTED_WIDTHS = '1280,390';

const steps = [];
// Children run asynchronously: the artifact server lives in this process and must keep answering.
async function step(name, file, scriptArgs, env = {}) {
  console.log(`\n── ${name}`);
  const child = spawn(process.execPath, [file, ...scriptArgs], { cwd: frontend, stdio: 'inherit', env: { ...process.env, ...env } });
  const status = await new Promise((resolve) => {
    child.once('error', () => resolve(1));
    child.once('close', (code) => resolve(code ?? 1));
  });
  steps.push({ name, status });
}
const playwright = (name, testArgs, env) => step(name, path.join(frontend, 'node_modules/@playwright/test/cli.js'), ['test', ...testArgs], env);
const imageCheck = () => step('playwright image check', path.join(here, 'check-playwright-image.mjs'), []);

async function withServer(version, run) {
  if (!existsSync(ARTIFACTS[version].dir)) throw new Error(`${ARTIFACTS[version].dir} is missing; run npm run e2e:build first.`);
  const server = await serveArtifact(ARTIFACTS[version].dir, ARTIFACTS[version].port);
  try {
    await run(server.url, path.join(here, '.results', version));
  } finally {
    await server.close();
  }
}

async function axe(version, base, out, extra = []) {
  await step(`${version} axe audit`, path.join(here, 'axe-audit.mjs'), ['--base', base, '--out', out, '--label', version, ...extra]);
}
async function axeCompare(version, out, extra = []) {
  await step(`${version} axe compare`, path.join(here, 'axe-compare.mjs'),
    ['--run', path.join(out, `${version}_axe.json`), '--baseline', path.join(here, 'axe-baseline', `${version}.json`), ...extra]);
}

// Journeys judge failures against e2e/journey-baseline/<version>.json when it exists; a version
// without one fails on any failed check.
const journeyBaseline = (version) => path.join(here, 'journey-baseline', `${version}.json`);
async function journeyStep(version, journey, base, out, env = {}) {
  const known = existsSync(journeyBaseline(version)) ? { E2E_KNOWN_FAILURES: journeyBaseline(version) } : {};
  await step(`${version} ${journey} journey`, path.join(here, `${journey}-journey.mjs`),
    ['--base', base, '--out', path.join(out, 'journeys', journey), '--label', version], { ...known, ...env });
}

const visualSteps = async (extraArgs = [], env = {}) => {
  for (const version of versions) await playwright(`${version} visual`, ['--project', version, ...extraArgs], { E2E_VERSIONS: version, ...env });
};

if (command === 'journeys') {
  for (const version of versions) {
    await withServer(version, async (base, out) => {
      for (const journey of JOURNEYS) {
        await journeyStep(version, journey, base, out);
      }
    });
  }
} else if (command === 'sweep') {
  const widths = args.widths ?? '390,768,1280,1440';
  for (const version of versions) {
    await withServer(version, async (base, out) => {
      for (const theme of THEMES) {
        await step(`${version} route sweep (${theme})`, path.join(here, 'route-sweep.mjs'), ['--base', base, '--out', path.join(out, 'sweep'), '--label', `${version}_${theme}`, '--theme', theme, '--widths', widths]);
      }
      await axe(version, base, out, ['--widths', widths]);
      await axeCompare(version, out);
    });
  }
} else if (command === 'visual') {
  await imageCheck();
  if (steps.every((s) => s.status === 0)) await visualSteps();
} else if (command === 'affected') {
  if (!args.routes) {
    console.error('affected needs --routes <comma-separated paths>; an empty selection is an error.');
    process.exit(2);
  }
  await imageCheck();
  if (steps.every((s) => s.status === 0)) {
    await visualSteps([], { E2E_ROUTES: args.routes, E2E_WIDTHS: AFFECTED_WIDTHS });
    for (const version of versions) {
      await withServer(version, async (base, out) => {
        const affectedOut = path.join(out, 'affected');
        mkdirSync(affectedOut, { recursive: true });
        await axe(version, base, affectedOut, ['--routes', args.routes, '--widths', AFFECTED_WIDTHS]);
        await axeCompare(version, affectedOut, ['--routes', args.routes]);
      });
    }
  }
} else if (command === 'update') {
  await imageCheck();
  if (steps.every((s) => s.status === 0)) {
    // Compare first so the report under e2e/.results/visual-report holds the before/after
    // diffs to inspect, then rewrite the baselines.
    await visualSteps();
    steps.length = 0;
    await visualSteps(['--update-snapshots']);
    for (const version of versions) {
      await withServer(version, async (base, out) => {
        for (const journey of JOURNEYS) {
          await journeyStep(version, journey, base, out, { E2E_KNOWN_FAILURES: journeyBaseline(version), E2E_KNOWN_FAILURES_UPDATE: '1' });
        }
        await axe(version, base, out);
        await step(`${version} axe baseline update`, path.join(here, 'axe-compare.mjs'),
          ['--run', path.join(out, `${version}_axe.json`), '--baseline', path.join(here, 'axe-baseline', `${version}.json`), '--update']);
      });
    }
    console.log('\nInspect e2e/.results/visual-report and the baseline diffs before committing them.');
  }
} else {
  console.error('Usage: node e2e/run.mjs <journeys|sweep|visual|affected|update> [options]');
  process.exit(2);
}

const failed = steps.filter((s) => s.status !== 0);
console.log(`\n${steps.length - failed.length}/${steps.length} steps passed`);
for (const s of failed) console.log(`FAIL ${s.name} (exit ${s.status})`);
process.exitCode = failed.length ? 1 : 0;
