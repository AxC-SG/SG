// node probe-compare.mjs self <probe.json>           cold vs navigation vs Back, within one run
// node probe-compare.mjs diff <before.json> <after.json>   same mode, before vs after a change
import { readFileSync } from 'node:fs';

const [mode, a, b] = process.argv.slice(2);
const load = (f) => JSON.parse(readFileSync(f, 'utf8'));
function diffSnap(x, y, limit = 12) {
  const out = [];
  if (!x || !y) return [`missing snapshot (${!!x}/${!!y})`];
  if (x.dataUi !== y.dataUi) out.push(`data-ui ${x.dataUi} -> ${y.dataUi}`);
  for (const k of new Set([...Object.keys(x.vars), ...Object.keys(y.vars)])) if ((x.vars[k] ?? '') !== (y.vars[k] ?? '')) out.push(`var ${k}: ${x.vars[k]} -> ${y.vars[k]}`);
  for (const sel of new Set([...Object.keys(x.els), ...Object.keys(y.els)])) {
    const ex = x.els[sel] || [], ey = y.els[sel] || [];
    if (ex.length !== ey.length) { out.push(`${sel}: ${ex.length} -> ${ey.length} elements`); continue; }
    ex.forEach((s, i) => { for (const p of Object.keys(s)) if (s[p] !== ey[i][p]) out.push(`${sel}[${i}] ${p}: ${s[p]} -> ${ey[i][p]}`); });
  }
  return out.slice(0, limit).concat(out.length > limit ? [`… ${out.length - limit} more`] : []);
}
const stateDiff = (x = {}, y = {}) => Object.keys({ ...x, ...y }).filter((k) => x[k] !== y[k]).map((k) => `state ${k}: ${x[k]} -> ${y[k]}`);

let problems = 0, compared = 0;
if (mode === 'self') {
  const r = load(a);
  for (const [key, e] of Object.entries(r.runs)) {
    if (!e.nav) continue;
    for (const [label, other, st] of [['nav', e.nav, e.navStates], ['back', e.back]]) {
      compared++;
      const d = diffSnap(e.cold, other).concat(st ? stateDiff(e.coldStates, st) : []);
      if (d.length) { problems++; console.log(`${r.version} ${key} cold vs ${label}:\n  ${d.join('\n  ')}`); }
    }
  }
  const expected = r.version === 'ui2' ? '2' : null;
  // Back returns to the app route (data-ui set on UI 2); Forward returns to /demo (never set).
  const bad = r.boundary.filter((x) => x.onDemo !== null || x.back !== expected || x.forward !== null);
  console.log(`${r.version}: ${compared} comparisons, ${problems} differ; boundary ${r.boundary.length} sequences, ${bad.length} bad`, bad.slice(0, 5));
  const byUi = {}; for (const [k, e] of Object.entries(r.runs)) (byUi[String(e.cold.dataUi)] ??= new Set()).add(k.split('|')[0]);
  console.log(`${r.version}: cold data-ui by route:`, Object.fromEntries(Object.entries(byUi).map(([v, set]) => [v, v === 'null' && r.version === 'ui2' ? [...set] : set.size])));
} else {
  const x = load(a), y = load(b);
  for (const key of Object.keys(x.runs)) {
    for (const m of ['cold', 'nav', 'back']) {
      if (!x.runs[key][m]) continue;
      compared++;
      const st = m === 'cold' ? stateDiff(x.runs[key].coldStates, y.runs[key]?.coldStates) : m === 'nav' ? stateDiff(x.runs[key].navStates, y.runs[key]?.navStates) : [];
      const d = diffSnap(x.runs[key][m], y.runs[key]?.[m]).concat(st);
      if (d.length) { problems++; console.log(`${x.version} ${key} ${m}:\n  ${d.join('\n  ')}`); }
    }
  }
  console.log(`${x.version}: ${compared} snapshots compared, ${problems} differ`);
}
