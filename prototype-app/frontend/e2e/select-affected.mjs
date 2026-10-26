#!/usr/bin/env node
// Resolves changed files to the routes e2e:affected should run, using e2e/affected-routes.json.
//
//   node e2e/select-affected.mjs --base origin/main     # prints routes, FULL_SWEEP or NONE
//   node e2e/select-affected.mjs --files a.css,b.tsx
//   node e2e/select-affected.mjs --audit                # lists presentation files the map misses
//
// Output on stdout is one line: a comma-separated route list, FULL_SWEEP when a presentation file
// is missing from the map, or NONE when no presentation file changed. A selection that resolves to
// an empty route list is an error, never a silent zero-route run.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { FAMILY_ROUTES } from './routes.mjs';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, value, index, all) => {
    const next = all[index + 1];
    if (value.startsWith('--')) pairs.push([value.slice(2), next === undefined || next.startsWith('--') ? 'true' : next]);
    return pairs;
  }, [])
);
const frontend = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const map = JSON.parse(readFileSync(path.join(frontend, 'e2e', 'affected-routes.json'), 'utf8'));
const foundation = map.foundation.map((pattern) => new RegExp(pattern));
const families = Object.entries(map.families).map(([family, patterns]) => [family, patterns.map((pattern) => new RegExp(pattern))]);
const unknownFamily = families.map(([family]) => family).find((family) => !FAMILY_ROUTES[family]);
if (unknownFamily) throw new Error(`affected-routes.json names family ${unknownFamily}, which routes.mjs does not define`);

// Test helpers under src/test/ never render in the app.
const isPresentation = (file) => !file.startsWith('src/test/')
  && (/^src\/.*\.css$/.test(file) || (/^src\/.*\.tsx$/.test(file) && !/\.(test|spec)\.tsx$/.test(file)));

function git(...gitArgs) {
  return execFileSync('git', gitArgs, { cwd: frontend, encoding: 'utf8' }).split('\n').filter(Boolean);
}

/** Families for one file: 'ALL' for foundation, [] when unmapped. */
function familiesFor(file) {
  if (foundation.some((pattern) => pattern.test(file))) return 'ALL';
  return families.filter(([, patterns]) => patterns.some((pattern) => pattern.test(file))).map(([family]) => family);
}

if (args.audit === 'true') {
  const missing = git('ls-files', 'src').filter(isPresentation).filter((file) => familiesFor(file) !== 'ALL' && familiesFor(file).length === 0);
  for (const file of missing) console.log(`UNMAPPED ${file}`);
  console.log(`${missing.length} presentation files are not in affected-routes.json`);
  process.exit(missing.length ? 1 : 0);
}

const changed = args.files
  ? args.files.split(',')
  : git('diff', '--name-only', '--relative', `${args.base ?? 'origin/main'}...HEAD`);
const presentation = changed.filter(isPresentation);
if (!presentation.length) {
  console.log('NONE');
  process.exit(0);
}

const selected = new Set();
for (const file of presentation) {
  const result = familiesFor(file);
  if (result !== 'ALL' && result.length === 0) {
    console.error(`${file} is not in affected-routes.json; running the full sweep.`);
    console.log('FULL_SWEEP');
    process.exit(0);
  }
  for (const family of result === 'ALL' ? Object.keys(FAMILY_ROUTES) : result) selected.add(family);
}
const routes = [...new Set([...selected].flatMap((family) => FAMILY_ROUTES[family].map(([route]) => route)))];
if (!routes.length) {
  console.error(`Changed presentation files resolved to no routes: ${presentation.join(', ')}`);
  process.exit(1);
}
console.log(routes.join(','));
