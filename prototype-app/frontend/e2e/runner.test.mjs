import assert from 'node:assert/strict';
import test from 'node:test';
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
