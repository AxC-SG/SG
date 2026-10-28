import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runPool } from './runner-pool.mjs';

const pause = () => new Promise((resolve) => setTimeout(resolve, 2));

test('serial and concurrent execution visit the same journeys once', async () => {
  for (const concurrency of [1, 2]) {
    let active = 0, peak = 0;
    const seen = [];
    await runPool([0, 1, 2, 3, 4, 5], concurrency, async (item) => {
      active++;
      peak = Math.max(peak, active);
      await pause();
      seen.push(item);
      active--;
    });
    assert.equal(peak, concurrency);
    assert.deepEqual(seen.sort(), [0, 1, 2, 3, 4, 5]);
  }
});

test('one failure does not prevent later journeys from running', async () => {
  const seen = [];
  await assert.rejects(runPool([0, 1, 2, 3], 2, async (item) => {
    await pause();
    seen.push(item);
    if (item === 0) throw new Error('fixture failure');
  }), AggregateError);
  assert.deepEqual(seen.sort(), [0, 1, 2, 3]);
});

test('invalid limits fail before any journey starts', async () => {
  for (const concurrency of [0, -1, NaN, 1.5]) {
    await assert.rejects(runPool([1], concurrency, () => assert.fail()), /positive integer/);
  }
});

test('invalid sweep selection fails before browser work starts', () => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL('./run.mjs', import.meta.url)), 'sweep', '--checks', 'invalid'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Unknown sweep checks/);
});

test('partial accessibility audits do not mark other widths resolved', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'sg-axe-comparison-'));
  try {
    const entry = { route: '/fixture', theme: 'dark', width: 390, rule: 'label', impact: 'critical', target: '.fixture' };
    const baseline = path.join(directory, 'baseline.json'), run = path.join(directory, 'run.json');
    writeFileSync(baseline, JSON.stringify([entry, { ...entry, width: 768 }]));
    writeFileSync(run, JSON.stringify([{ ...entry, targets: [entry.target] }]));
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('./axe-compare.mjs', import.meta.url)), '--run', run, '--baseline', baseline, '--widths', '390'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /0 resolved/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
