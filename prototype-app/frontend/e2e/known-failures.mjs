// Reviewed known journey failures for one UI version (e2e/journey-baseline/<version>.json), keyed
// by journey + check name. run.mjs names the file through E2E_KNOWN_FAILURES; without it every
// failure counts. Known failures are still printed on every run, so nothing is hidden, and a
// known failure that now passes is reported as resolved without failing the run.
//
// E2E_KNOWN_FAILURES_UPDATE=1 rewrites this journey's entries from the current failures; use it
// only through `npm run e2e:update` and review the diff.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const journey = path.basename(process.argv[1], '.mjs');
const file = process.env.E2E_KNOWN_FAILURES;

/** The failures not covered by the baseline; prints known and resolved entries. */
export function unexpectedFailures(results) {
  const failed = results.filter((result) => !result.ok);
  if (!file) return failed;
  const baseline = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : [];
  if (process.env.E2E_KNOWN_FAILURES_UPDATE === '1') {
    const kept = baseline.filter((entry) => entry.journey !== journey);
    const next = [...kept, ...failed.map(({ name }) => ({ journey, check: name }))]
      .sort((a, b) => a.journey.localeCompare(b.journey) || a.check.localeCompare(b.check));
    writeFileSync(file, `${JSON.stringify(next, null, 1)}\n`);
    console.log(`known failures updated: ${failed.length} for ${journey} in ${file}`);
    return [];
  }
  const known = new Set(baseline.filter((entry) => entry.journey === journey).map((entry) => entry.check));
  const passed = new Set(results.filter((result) => result.ok).map((result) => result.name));
  for (const result of failed.filter(({ name }) => known.has(name))) console.log(`KNOWN FAIL ${result.name}`);
  for (const check of [...known].filter((name) => passed.has(name))) console.log(`RESOLVED ${check}`);
  const unexpected = failed.filter(({ name }) => !known.has(name));
  console.log(`${journey}: ${failed.length - unexpected.length} known, ${unexpected.length} new failures`);
  return unexpected;
}
