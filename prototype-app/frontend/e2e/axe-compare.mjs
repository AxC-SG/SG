#!/usr/bin/env node
// Compares an axe-audit.mjs run with the reviewed baseline for the same UI version.
//
// Each violation is keyed by route + theme + width + rule + affected element, so a fix on one page cannot
// hide a regression on another the way total counts can. The run fails on any violation that is
// not in the baseline; serious and critical ones are listed first. Baseline entries that no longer
// occur are reported as resolved and do not fail the run.
//
// Usage:
//   node axe-compare.mjs --run <dir>/<label>_axe.json --baseline axe-baseline/<version>.json [--routes <list>] [--update]
// --routes and --widths limit comparison to the dimensions a partial run audited.
// --update rewrites the baseline from the run; use it only through `npm run e2e:update`.
import { readFileSync, writeFileSync } from 'node:fs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    const next = all[index + 1];
    if (value.startsWith('--')) pairs.push([value.slice(2), next === undefined || next.startsWith('--') ? 'true' : next]);
    return pairs;
  }, [])
);
if (!args.run || !args.baseline) {
  console.error('Usage: node axe-compare.mjs --run <axe.json> --baseline <baseline.json> [--update]');
  process.exit(2);
}

const SEVERITY = ['critical', 'serious', 'moderate', 'minor'];
const keyOf = (entry) => [entry.route, entry.theme, entry.width, entry.rule, entry.target].join(' | ');

/** One entry per affected element, sorted so the baseline diff stays reviewable. */
function expand(rows) {
  const entries = new Map();
  for (const row of rows) {
    for (const target of row.targets ?? [row.sample]) {
      const entry = { route: row.route, theme: row.theme, width: row.width, rule: row.rule, impact: row.impact, target };
      entries.set(keyOf(entry), entry);
    }
  }
  return [...entries.values()].sort((a, b) => keyOf(a).localeCompare(keyOf(b)));
}

const current = expand(JSON.parse(readFileSync(args.run, 'utf8')));

if (args.update === 'true' && args.routes) {
  console.error('--update rewrites the whole baseline; run it without --routes.');
  process.exit(2);
}
if (args.update === 'true') {
  writeFileSync(args.baseline, `${JSON.stringify(current, null, 1)}\n`);
  console.log(`baseline updated: ${current.length} pre-existing violations in ${args.baseline}`);
  process.exit(0);
}

const audited = args.routes ? new Set(args.routes.split(',')) : null;
const auditedWidths = args.widths ? new Set(args.widths.split(',').map(Number)) : null;
if (auditedWidths && [...auditedWidths].some((width) => !Number.isInteger(width) || width < 1)) throw new Error('Invalid audit widths');
const baseline = JSON.parse(readFileSync(args.baseline, 'utf8')).filter((entry) => (!audited || audited.has(entry.route)) && (!auditedWidths || auditedWidths.has(entry.width)));
const known = new Set(baseline.map(keyOf));
const seen = new Set(current.map(keyOf));
const added = current
  .filter((entry) => !known.has(keyOf(entry)))
  .sort((a, b) => SEVERITY.indexOf(a.impact) - SEVERITY.indexOf(b.impact) || keyOf(a).localeCompare(keyOf(b)));
const resolved = baseline.filter((entry) => !seen.has(keyOf(entry)));
const severe = added.filter((entry) => entry.impact === 'critical' || entry.impact === 'serious');

console.log(`axe compare: ${current.length} current, ${baseline.length} baseline, ${added.length} new `
  + `(${severe.length} serious or critical), ${resolved.length} resolved`);
for (const entry of added) console.log(`NEW ${entry.impact} ${keyOf(entry)}`);
for (const entry of resolved) console.log(`RESOLVED ${entry.impact} ${keyOf(entry)}`);
process.exitCode = added.length ? 1 : 0;
