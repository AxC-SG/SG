// Read-only cascade map for the UI 2.0 foundation sheets: which rule wins per (subject, property),
// in effective load order. Usage: node cascade-map.mjs <frontend dir> <out.json>
// The load order and the foundation set are written for Step 4; update `main`, `lazy` and
// `foundation` when a later step changes the stylesheet entry points.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';

const fe = process.argv[2];
const require = createRequire(join(fe, 'package.json'));
const postcss = require('postcss');

const S = 'src/styles/';
const main = ['base', 'shared', 'cve-workbench', 'connect', 'eol', 'vuln-repo', 'user-management', 'exposure-dashboard']
  .map((n) => `${S}${n}.css`)
  .concat(['tokens', 'legacy-bridge', 'shell', 'primitives', 'findings', 'cve', 'inventory', 'governance', 'connect', 'experience'].map((n) => `${S}ui2/${n}.css`))
  .concat([`${S}finding-detail.css`, `${S}ai-security.css`]);
const lazy = ['src/components/DataTable.css', `${S}findings-list.css`, 'src/pages/platform-feed-catalog.css', 'node_modules/@xyflow/react/dist/style.css'];
const order = [...main, ...lazy];
const foundation = new Set(['tokens', 'legacy-bridge', 'shell', 'primitives'].map((n) => `${S}ui2/${n}.css`));

function split(list) {
  const out = []; let d = 0, cur = '';
  for (const c of list) { if (c === ',' && d === 0) { out.push(cur.trim()); cur = ''; continue; } if (c === '(') d++; if (c === ')') d--; cur += c; }
  return [...out, cur.trim()].filter(Boolean);
}
function spec(sel) {
  let a = 0, b = 0, c = 0;
  let s = sel.replace(/::?(before|after|placeholder|backdrop|selection|-webkit-[\w-]+)/g, () => { c++; return ''; });
  s = s.replace(/:(is|not|has|where)\(((?:[^()]|\([^()]*\))*)\)/g, (_, fn, args) => {
    if (fn !== 'where') { const best = split(args).map(spec).sort(cmp).pop() || [0, 0, 0]; a += best[0]; b += best[1]; c += best[2]; }
    return '';
  });
  s = s.replace(/\[[^\]]*\]/g, () => { b++; return ''; });
  s = s.replace(/#[\w-]+/g, () => { a++; return ''; });
  s = s.replace(/\.[\w-]+/g, () => { b++; return ''; });
  s = s.replace(/:[\w-]+(\([^)]*\))?/g, () => { b++; return ''; });
  for (const t of s.split(/[\s>+~]+/)) if (/^[a-z][\w-]*$/i.test(t)) c++;
  return [a, b, c];
}
function cmp(x, y) { return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]; }
// Subject = last compound, without pseudo-elements; returns tokens (classes, tag, states).
function subject(sel) {
  const s = sel.replace(/html\[data-ui='2'\]\s*/, '').trim();
  const parts = s.split(/\s*[>+~]\s*|\s+(?![^(]*\))/);
  const last = parts[parts.length - 1].replace(/::?(before|after|placeholder|backdrop|selection)\b.*/, (m) => '§' + m.replace(/^:+/, ''));
  const pe = (last.match(/§(\w+)/) || [])[1] || '';
  const body = last.replace(/§.*/, '');
  const classes = [...body.matchAll(/\.([\w-]+)/g)].map((m) => m[1]);
  const tag = (body.match(/^([a-z][\w-]*)/i) || [])[1] || '';
  const states = [...body.matchAll(/:(hover|focus|active|disabled|focus-visible|checked|nth-child\([^)]*\))/g)].map((m) => m[1]);
  return { classes, tag, states, pe };
}
const fam = (p) => p.split('-').slice(0, p.startsWith('--') ? 99 : 1).join('-');
function related(p, q) { return p === q || (!p.startsWith('--') && fam(p) === fam(q) && (q.startsWith(p + '-') || p.startsWith(q + '-'))); }

const rules = [];
order.forEach((file, fi) => {
  const root = postcss.parse(readFileSync(join(fe, file), 'utf8'));
  root.walkRules((r) => {
    if (r.parent.type === 'atrule' && /keyframes/.test(r.parent.name)) return;
    const media = r.parent.type === 'atrule' ? `@${r.parent.name} ${r.parent.params}` : '';
    const decls = []; r.each((n) => n.type === 'decl' && decls.push({ prop: n.prop, value: n.value, important: !!n.important }));
    for (const sel of split(r.selector)) rules.push({ file, fi, lazy: fi >= main.length, sel, spec: spec(sel), subj: subject(sel), media, decls, line: r.source.start.line });
  });
});

const fRules = rules.filter((r) => foundation.has(r.file));
const others = rules.filter((r) => !foundation.has(r.file));
function sameTarget(f, o) {
  if (f.subj.pe !== o.subj.pe) return false;
  const fc = f.subj.classes, oc = o.subj.classes;
  if (fc.length === 0 && oc.length === 0) return f.subj.tag && f.subj.tag === o.subj.tag;
  if (fc.length === 0) return f.subj.tag && f.subj.tag === o.subj.tag;
  return fc.every((c) => oc.includes(c)) && (!f.subj.tag || !o.subj.tag || f.subj.tag === o.subj.tag);
}
const out = [];
for (const f of fRules) {
  for (const fd of f.decls) {
    if (fd.prop.startsWith('--')) continue;
    for (const o of others) {
      if (!sameTarget(f, o)) continue;
      for (const od of o.decls) {
        if (!related(fd.prop, od.prop)) continue;
        let win, why;
        if (od.important && !fd.important) { win = 'other'; why = '!important'; }
        else if (fd.important && !od.important) { win = 'foundation'; why = '!important'; }
        else { const c = cmp(o.spec, f.spec); if (c > 0) { win = 'other'; why = 'specificity'; } else if (c < 0) { win = 'foundation'; why = 'specificity'; } else { const later = o.lazy || o.fi > f.fi; win = later ? 'other' : 'foundation'; why = o.lazy ? 'tie, lazy sheet loads later' : 'tie, source order'; } }
        if (win !== 'other') continue;
        const scoped = o.sel.startsWith("html[data-ui='2']");
        out.push({ foundation: `${f.file.replace(S, '')}:${f.line} ${f.sel}${f.media ? ' ' + f.media : ''}`, prop: fd.prop, fvalue: fd.value, other: `${o.file.replace(S, '')}:${o.line} ${o.sel}${o.media ? ' ' + o.media : ''}`, ovalue: od.value + (od.important ? ' !important' : ''), why, kind: scoped ? 'ui2-family-override' : o.lazy ? 'lazy-legacy' : 'legacy' });
      }
    }
  }
}
// Bridged custom properties redefined anywhere other than the root theme blocks.
const bridged = new Set(rules.filter((r) => r.file.endsWith('legacy-bridge.css')).flatMap((r) => r.decls.map((d) => d.prop)));
const dpTokens = new Set(rules.filter((r) => r.file.endsWith('tokens.css')).flatMap((r) => r.decls.map((d) => d.prop)));
const rootSel = /^(:root|html|\[data-theme='?(light|dark)'?\]|:root\[data-theme='?(light|dark)'?\]|html\[data-theme='?(light|dark)'?\]|body|html\[data-ui='2'\](\[data-theme='(light|dark)'\])?)$/;
const varRedefs = rules.filter((r) => !r.file.endsWith('legacy-bridge.css') && !r.file.endsWith('tokens.css'))
  .flatMap((r) => r.decls.filter((d) => bridged.has(d.prop) || dpTokens.has(d.prop)).map((d) => ({ at: `${r.file.replace(S, '')}:${r.line}`, sel: r.sel, prop: d.prop, value: d.value, root: rootSel.test(r.sel.replace(/"/g, "'")), lazy: r.lazy })));
// Within the foundation: identical selector+prop+value repeated, and same selector across foundation files.
const seen = new Map(); const dupes = [];
for (const f of fRules) for (const d of f.decls) { const k = `${f.sel}${f.media}|${d.prop}`; if (seen.has(k)) dupes.push({ key: k, first: seen.get(k), again: `${f.file.replace(S, '')}:${f.line}`, value: d.value }); else seen.set(k, `${f.file.replace(S, '')}:${f.line}=${d.value}`); }
// Hardcoded colours in the foundation outside tokens.css.
const colours = fRules.filter((r) => !r.file.endsWith('tokens.css')).flatMap((r) => r.decls.filter((d) => /#[0-9a-f]{3,8}\b|rgba?\(|hsla?\(|\b(white|black)\b/i.test(d.value)).map((d) => ({ at: `${r.file.replace(S, '')}:${r.line}`, sel: r.sel, prop: d.prop, value: d.value })));

const result = { order: { main, lazy }, counts: { foundationRules: fRules.length }, losses: out, varRedefs, dupes, colours };
writeFileSync(process.argv[3], JSON.stringify(result, null, 1));
const by = (k) => out.reduce((m, x) => ((m[x[k]] = (m[x[k]] || 0) + 1), m), {});
console.log('foundation selector entries', fRules.length, 'losses', out.length, by('kind'), by('why'));
console.log('var redefs non-root', varRedefs.filter((v) => !v.root).length, 'root', varRedefs.filter((v) => v.root).length);
console.log('dupes', dupes.length, 'hardcoded colours', colours.length);
