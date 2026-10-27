import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Every UI 2.0 rule must stay behind the html[data-ui='2'] presentation flag so the legacy UI
// renders unchanged by default, and Findings-family rules must stay anchored on that family's
// page roots so shared fpl-/fd3-/ai-security- classes on other pages are not restyled early.
// Read from disk: vitest stubs CSS imports (including ?raw) to empty strings, and jsdom's
// import.meta.url is not a file URL, so resolve from the vitest root (the frontend package).
const directory = join(process.cwd(), 'src', 'styles', 'ui2');
const sheets: Record<string, string> = Object.fromEntries(
  readdirSync(directory).filter((file) => file.endsWith('.css')).map((file) => [`./${file}`, readFileSync(join(directory, file), 'utf8')]),
);

// Splits a selector list on its top-level commas, keeping :is(.a, .b) groups whole.
function splitList(list: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = '';
  for (const char of list) {
    if (char === ',' && depth === 0) {
      parts.push(current.trim());
      current = '';
      continue;
    }
    if (char === '(') depth += 1;
    if (char === ')') depth -= 1;
    current += char;
  }
  return [...parts, current.trim()];
}

function selectors(css: string): string[] {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, '');
  return [...withoutComments.matchAll(/([^{}]+)\{/g)]
    .map((match) => match[1].trim())
    .filter((selector) => !selector.startsWith('@'))
    .flatMap(splitList);
}

// The selector's leading compound: a single root class or an :is() group of root classes.
function anchoredOn(selector: string, roots: string[]): boolean {
  const lead = selector.replace("html[data-ui='2'] ", '').match(/^(:is\(([^)]*)\)|\.[\w-]+)/);
  if (!lead) return false;
  const classes = lead[2] ? lead[2].split(',').map((part) => part.trim()) : [lead[1]];
  return classes.every((name) => roots.some((root) => name === root || name.startsWith(root)));
}

type Rule = { selectors: string[]; declarations: [string, string][]; media: string };

// Parses rules (descending into @media/@supports) into selectors and declarations.
function rules(css: string, media = ''): Rule[] {
  const source = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const out: Rule[] = [];
  let index = 0;
  while (index < source.length) {
    const open = source.indexOf('{', index);
    if (open < 0) break;
    const prelude = source.slice(index, open).trim();
    let depth = 1;
    let end = open + 1;
    for (; end < source.length && depth > 0; end += 1) {
      if (source[end] === '{') depth += 1;
      if (source[end] === '}') depth -= 1;
    }
    const body = source.slice(open + 1, end - 1);
    if (/^@(media|supports)/.test(prelude)) out.push(...rules(body, prelude));
    else if (!prelude.startsWith('@')) {
      const declarations = body.split(';').map((part) => part.trim()).filter(Boolean)
        .map((part) => [part.slice(0, part.indexOf(':')).trim(), part.slice(part.indexOf(':') + 1).trim()] as [string, string]);
      out.push({ selectors: splitList(prelude), declarations, media });
    }
    index = end;
  }
  return out;
}

const declared = (sheet: string, selector: string) =>
  Object.fromEntries(rules(sheets[sheet]).filter((rule) => rule.selectors.includes(selector) && !rule.media).flatMap((rule) => rule.declarations));

// Page and family roots. Foundation sheets (tokens, legacy-bridge, shell, primitives) style shared
// classes on every page, so they must never name one of these.
const FAMILY_ROOTS = ['.fpl-root', '.fd3-page', '.cve-assessment-page', '.vuln-repo-vulnerabilities-shell', '.vuln-repo-assets-shell',
  '.ui2-findings-family', '.ui2-cve-family', '.ui2-inventory-family', '.ui2-governance-family', '.ui2-connect-family', '.ui2-experience-family'];
const FOUNDATION = ['./tokens.css', './legacy-bridge.css', './shell.css', './primitives.css'];
const ROOT_SELECTORS = ["html[data-ui='2']", "html[data-ui='2'][data-theme='light']", "html[data-ui='2'][data-theme='dark']"];
// A colour literal is allowed only as the fallback inside var(--token, <literal>).
const COLOUR_LITERAL = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?)\(/i;
const withoutFallbacks = (value: string) => value.replace(/var\(--[\w-]+,\s*(?:(?:rgba?|hsla?)\([^)]*\)|#[0-9a-f]{3,8})\s*\)/gi, 'var()');

describe('UI 2.0 stylesheet scope', () => {
  it('parses selector lists and anchors', () => {
    expect(selectors(".a{} html[data-ui='2'] .b, .c{}")).toEqual(['.a', "html[data-ui='2'] .b", '.c']);
    expect(selectors(":is(.a, .b) .c, .d{}")).toEqual([':is(.a, .b) .c', '.d']);
    expect(anchoredOn("html[data-ui='2'] :is(.a, .b) .c", ['.a', '.b'])).toBe(true);
    expect(anchoredOn("html[data-ui='2'] :is(.a, .z) .c", ['.a', '.b'])).toBe(false);
    expect(rules('@media (x) { .a { b: c; d: e } } .f { g: h }')).toEqual([
      { selectors: ['.a'], declarations: [['b', 'c'], ['d', 'e']], media: '@media (x)' },
      { selectors: ['.f'], declarations: [['g', 'h']], media: '' },
    ]);
    expect(withoutFallbacks('var(--x, rgba(1, 2, 3, 0.5)) #fff')).toBe('var() #fff');
  });

  // Load order decides ties between equal-specificity rules (for example the Inventory input
  // rule after primitives), so it is part of each sheet's ownership.
  it('loads every UI 2.0 sheet once, foundation first, after the legacy sheets', () => {
    const imports = (file: string) => [...readFileSync(file, 'utf8').matchAll(/@import\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(imports(join(directory, 'index.css'))).toEqual([...FOUNDATION, './findings.css', './cve.css', './inventory.css',
      './governance.css', './connect.css', './experience.css']);
    expect(Object.keys(sheets).filter((file) => file !== './index.css').sort()).toEqual(imports(join(directory, 'index.css')).sort());
    expect(imports(join(directory, '..', 'index.css')).slice(-1)).toEqual(['./ui2/index.css']);
    for (const file of imports(join(directory, 'index.css'))) expect(rules(sheets[file]).length, file).toBeGreaterThan(0);
  });

  it('scopes every rule to html[data-ui=2]', () => {
    const unscoped = Object.entries(sheets).flatMap(([file, css]) =>
      selectors(css).filter((selector) => !selector.startsWith("html[data-ui='2']")).map((selector) => `${file}: ${selector}`));
    expect(unscoped).toEqual([]);
  });

  it('keeps tokens and the legacy bridge to custom properties on the root', () => {
    for (const file of ['./tokens.css', './legacy-bridge.css']) {
      for (const rule of rules(sheets[file])) {
        expect(rule.selectors.filter((selector) => !ROOT_SELECTORS.includes(selector)), file).toEqual([]);
        expect(rule.declarations.filter(([property]) => !property.startsWith('--')), file).toEqual([]);
      }
    }
    // The bridge only re-points legacy properties; it never redefines a UI 2.0 token.
    expect(rules(sheets['./legacy-bridge.css']).flatMap((rule) => rule.declarations).filter(([property]) => property.startsWith('--dp-'))).toEqual([]);
  });

  it('defines UI 2.0 tokens only in tokens.css', () => {
    const elsewhere = Object.entries(sheets).filter(([file]) => file !== './tokens.css').flatMap(([file, css]) =>
      rules(css).flatMap((rule) => rule.declarations).filter(([property]) => property.startsWith('--dp-')).map(([property]) => `${file}: ${property}`));
    expect(elsewhere).toEqual([]);
  });

  it('keeps the shell and primitives page-independent and token-coloured', () => {
    for (const file of ['./shell.css', './primitives.css']) {
      const anchored = selectors(sheets[file]).filter((selector) => FAMILY_ROOTS.some((root) => new RegExp(`${root.replace('.', '\\.')}(?![\\w-])`).test(selector)));
      expect(anchored, file).toEqual([]);
      const declarations = rules(sheets[file]).flatMap((rule) => rule.declarations);
      expect(declarations.filter(([, value]) => value.includes('!important')), file).toEqual([]);
      expect(declarations.filter(([, value]) => COLOUR_LITERAL.test(withoutFallbacks(value))).map(([property, value]) => `${property}: ${value}`), file).toEqual([]);
    }
  });

  it('keeps each severity and status tone on its own token', () => {
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-critical")).toEqual({ '--ui2-tone': 'var(--dp-critical)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-high")).toEqual({ '--ui2-tone': 'var(--dp-high)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-medium")).toEqual({ '--ui2-tone': 'var(--dp-medium)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-low")).toEqual({ '--ui2-tone': 'var(--dp-low)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.error")['--ui2-tone']).toBe('var(--dp-critical)');
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.success")['--ui2-tone']).toBe('var(--dp-success)');
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.warning")['--ui2-tone']).toBe('var(--dp-warning)');
    const bridge = declared('./legacy-bridge.css', "html[data-ui='2']");
    expect([bridge['--critical'], bridge['--high'], bridge['--medium'], bridge['--low'], bridge['--success'], bridge['--danger'], bridge['--warning']])
      .toEqual(['var(--dp-critical)', 'var(--dp-high)', 'var(--dp-medium)', 'var(--dp-low)', 'var(--dp-success)', 'var(--dp-critical)', 'var(--dp-warning)']);
    // Light-theme semantic tones darkened for WCAG contrast (01353de5).
    const light = declared('./tokens.css', "html[data-ui='2']");
    expect([light['--dp-critical'], light['--dp-high'], light['--dp-medium'], light['--dp-low'], light['--dp-success'], light['--dp-warning']])
      .toEqual(['#bb2329', '#a84300', '#8d5a00', '#1d7449', '#1d7449', '#a05100']);
  });

  it('keeps tab underlines inside their tab strip', () => {
    const underlines = Object.entries(sheets).flatMap(([file, css]) => rules(css).filter((rule) =>
      rule.selectors.some((selector) => /tab[\w-]*(\.active|--active)[^,]*::after|active\)::after/.test(selector))).map((rule) => ({ file, rule })));
    expect(underlines.map(({ file }) => file).sort()).toEqual(['./connect.css', './findings.css', './shell.css']);
    for (const { file, rule } of underlines) {
      const values = Object.fromEntries(rule.declarations);
      expect([values.bottom, values.left, values.right, values.height], file).toEqual(['0', '6px', '6px', '2px']);
    }
  });

  // UI 2.0 box-shadows on .btn, .nav-btn.active and .tenant-context-pill outrank the base.css
  // focus ring, so keyboard focus on buttons and links is drawn with an uncontested outline.
  it('keeps a visible keyboard focus outline on buttons and links', () => {
    const focus = declared('./primitives.css', "html[data-ui='2'] :is(button, a[href], [role='button'], [tabindex]:not([tabindex='-1'])):focus-visible");
    expect([focus.outline, focus['outline-offset']]).toEqual(['2px solid var(--dp-accent)', '-2px']);
    const cleared = FOUNDATION.flatMap((file) => rules(sheets[file])
      .filter((rule) => rule.declarations.some(([property, value]) => /^outline(-style|-width)?$/.test(property) && /none|\b0\b/.test(value)))
      .flatMap((rule) => rule.selectors).filter((selector) => /\b(button|a)\b|\.(btn|nav-[\w-]+|tenant-context-pill|theme-icon-btn|section-tab-btn|settings-menu-item)\b/.test(selector))
      .map((selector) => `${file}: ${selector}`));
    expect(cleared).toEqual([]);
  });

  it('shows Findings identifiers at full width', () => {
    const cell = declared('./findings.css', "html[data-ui='2'] .fpl-root .fpl-td");
    expect(cell['max-width']).toBe('none');
    expect(cell['text-overflow']).toBeUndefined();
  });

  // The public marketing routes never carry data-ui (src/lib/uiVersion.ts). The auth-entry pages
  // share their markup, so UI 2.0 may only style public classes under the auth-entry family root.
  it('styles public-route markup only under the auth-entry family', () => {
    const publicClass = /\.(public-[\w-]+|demo-[\w-]+|blog-[\w-]+|scout-hero)\b/;
    const outsideFamily = Object.entries(sheets).flatMap(([file, css]) => selectors(css)
      .filter((selector) => publicClass.test(selector) && !/^html\[data-ui='2'\] \.ui2-experience-family[.\s]/.test(selector))
      .map((selector) => `${file}: ${selector}`));
    expect(outsideFamily).toEqual([]);
  });

  it('anchors Findings-family rules on the Findings page roots, the shared Inventory or Governance family or the portaled column filter', () => {
    const roots = ['.fpl-root', '.fd3-page', '.ui2-findings-family', '.ui2-inventory-family', '.ui2-governance-family', '.fpl-col-filter-'];
    const unanchored = selectors(sheets['./findings.css']).filter((selector) => !anchoredOn(selector, roots));
    expect(unanchored).toEqual([]);
  });

  it('anchors CVE-workflow rules on the CVE page roots or the shared Governance record detail', () => {
    const roots = ['.cve-assessment-page', '.ui2-cve-family', '.vuln-repo-vulnerabilities-shell', '.vuln-repo-assets-shell', '.ui2-governance-family'];
    const unanchored = selectors(sheets['./cve.css']).filter((selector) => !anchoredOn(selector, roots));
    expect(unanchored).toEqual([]);
    // Only :is() groups that include a CVE root may mention the Governance family.
    const governanceOnly = selectors(sheets['./cve.css']).filter((selector) => anchoredOn(selector, ['.ui2-governance-family']));
    expect(governanceOnly).toEqual([]);
  });

  it('anchors Governance-family rules on the Governance page roots', () => {
    const unanchored = selectors(sheets['./governance.css']).filter((selector) => !anchoredOn(selector, ['.ui2-governance-family']));
    expect(unanchored).toEqual([]);
  });

  it('anchors Connect-family rules on the Connectors and Configurations page roots', () => {
    const unanchored = selectors(sheets['./connect.css']).filter((selector) => !anchoredOn(selector, ['.ui2-connect-family']));
    expect(unanchored).toEqual([]);
  });

  it('anchors remaining-experience rules on the dashboard, campaign, operations and auth-entry roots', () => {
    const unanchored = selectors(sheets['./experience.css']).filter((selector) => !anchoredOn(selector, ['.ui2-experience-family']));
    expect(unanchored).toEqual([]);
  });

  it('anchors Inventory-family rules on the Inventory page roots', () => {
    const unanchored = selectors(sheets['./inventory.css']).filter((selector) => !anchoredOn(selector, ['.ui2-inventory-family']));
    expect(unanchored).toEqual([]);
  });
});
