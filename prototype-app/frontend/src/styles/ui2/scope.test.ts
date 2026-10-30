import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// Every app rule stays behind html[data-ui='2'] so public routes remain isolated. Findings presentation rules stay on their page roots;
// its shared base primitives retain their original specificity behind a zero-weight boundary.
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
  return rules(css).flatMap((rule) => rule.selectors);
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

// Page and family roots. Foundation sheets (tokens, shell, primitives) style shared
// classes on every page, so they must never name one of these.
const FAMILY_ROOTS = ['.fpl-root', '.fd3-page', '.cve-assessment-page', '.vuln-repo-vulnerabilities-shell', '.vuln-repo-assets-shell',
  '.ui2-findings-family', '.ui2-cve-family', '.ui2-inventory-family', '.ui2-governance-family', '.ui2-connect-family', '.ui2-experience-family', '.ui2-fix-family'];
const FOUNDATION = ['./tokens.css', './shell.css', './primitives.css'];
const ROOT_SELECTORS = ["html[data-ui='2']", "html[data-ui='2'][data-theme='light']", "html[data-ui='2'][data-theme='dark']"];
// A colour literal is allowed only as the fallback inside var(--token, <literal>).
const COLOUR_LITERAL = /#[0-9a-f]{3,8}\b|\b(?:rgba?|hsla?)\(/i;
const withoutFallbacks = (value: string) => value.replace(/var\(--[\w-]+,\s*(?:(?:rgba?|hsla?)\([^)]*\)|#[0-9a-f]{3,8})\s*\)/gi, 'var()');

// Retired files must be absent, rather than kept as empty import stubs.
function retiredRules(name: string): Rule[] {
  expect(existsSync(join(directory, '..', name)), name).toBe(false);
  return [];
}
const sharedSelectors = () => selectors(sheets['./app-base.css']).map((selector) => selector.replace(":where(html[data-ui='2']) ", ''));

describe('UI 2.0 stylesheet scope', () => {
  it('parses selector lists and anchors', () => {
    expect(selectors(".a{} html[data-ui='2'] .b, .c{}")).toEqual(['.a', "html[data-ui='2'] .b", '.c']);
    expect(selectors(":is(.a, .b) .c, .d{}")).toEqual([':is(.a, .b) .c', '.d']);
    expect(selectors('@keyframes private { from { opacity: 0; } to { opacity: 1; } } .a{}')).toEqual(['.a']);
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
  it('loads every app sheet once in deterministic precedence order', () => {
    const imports = (file: string) => [...readFileSync(file, 'utf8').matchAll(/@import\s+"([^"]+)"/g)].map((match) => match[1]);
    expect(imports(join(directory, 'index.css'))).toEqual(['./tokens.css', './app-base.css', './shell.css', './primitives.css', './experience-base.css', './inventory-base.css', './findings-base.css', './cve-base.css', './governance-base.css', './connect-base.css', './findings.css', './cve.css', './inventory.css',
      './governance.css', './connect.css', './experience.css', './fix-intelligence.css', './tables.css', '@xyflow/react/dist/style.css']);
    expect(Object.keys(sheets).filter((file) => file !== './index.css').sort()).toEqual(imports(join(directory, 'index.css')).filter((file) => file.startsWith('./')).sort());
    expect(imports(join(directory, '..', 'index.css')).slice(-1)).toEqual(['./ui2/index.css']);
    for (const file of imports(join(directory, 'index.css')).filter((file) => file.startsWith('./'))) expect(rules(sheets[file]).length, file).toBeGreaterThan(0);
  });

  it('scopes every rule to html[data-ui=2]', () => {
    const unscoped = Object.entries(sheets).flatMap(([file, css]) =>
      selectors(css).filter((selector) => {
        if (file === './app-base.css') return !/^(?::where\(html\[data-ui='2'\]\)|html:where\(\[data-ui='2'\]\))/.test(selector);
        return !selector.startsWith(['./tables.css', './experience-base.css', './inventory-base.css', './findings-base.css', './cve-base.css', './governance-base.css', './connect-base.css'].includes(file)
          ? ":where(html[data-ui='2']) " : "html[data-ui='2']");
      }).map((selector) => `${file}: ${selector}`));
    expect(unscoped).toEqual([]);
  });

  it('keeps shared Findings base primitives scoped without increasing their specificity', () => {
    const prefix = ":where(html[data-ui='2']) ";
    const owned = /^\.(?:fpl-[\w-]+|fd3-[\w-]+|finding-id-link\b|ai-security-(?:page|hero|kicker|table-panel|empty|empty-mark)\b)/;
    expect(selectors(sheets['./findings-base.css']).filter((selector) => !owned.test(selector.slice(prefix.length)))).toEqual([]);
    const keyframes = [...sheets['./findings-base.css'].matchAll(/@keyframes\s+([\w-]+)/g)].map((match) => match[1]);
    expect(keyframes.sort()).toEqual(['ui2-findings-reveal', 'ui2-findings-spin']);
    expect(declared('./findings-base.css', prefix + '.ai-security-page').animation).toBe('ui2-findings-reveal 360ms ease-out both');
  });

  it('loads shared Findings controls before any lazy Findings route and retires their legacy definitions', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./findings-base.css', prefix + '.fpl-root').display).toBe('flex');
    expect(declared('./findings-base.css', prefix + '.fd3-body').display).toBe('flex');
    expect(declared('./findings-base.css', prefix + '.fd3-modal-overlay').position).toBe('fixed');
    expect(retiredRules('findings-list.css')).toEqual([]);
    const inventory = retiredRules('finding-detail.css').flatMap((rule) => rule.selectors);
    expect(inventory.filter((selector) => !selector.startsWith('.iov-'))).toEqual([]);
    const retired = retiredRules('base.css').flatMap((rule) => rule.selectors)
      .filter((selector) => /^\.(?:fpl-|fd3-|finding-id-link\b)/.test(selector));
    expect(retired).toEqual([]);
  });

  it('keeps shared CVE controls behind a zero-specificity boundary on direct loads', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./cve-base.css', prefix + '.cve-assessment-page').display).toBe('flex');
    expect(declared('./cve-base.css', prefix + '.cvd2-page').display).toBe('flex');
    expect(declared('./cve-base.css', prefix + '.notify-panel').display).toBe('grid');
    expect(declared('./cve-base.css', prefix + '.inv-step').display).toBe('inline-flex');
    expect(declared('./cve-base.css', prefix + '.agent-draft-popover').position).toBe('absolute');
    expect(declared('./cve-base.css', prefix + '.criteria-select:disabled').cursor).toBe('not-allowed');
    expect(declared('./cve-base.css', prefix + '.md-table').width).toBe('100%');
    const keyframes = [...sheets['./cve-base.css'].matchAll(/@keyframes\s+([\w-]+)/g)].map((match) => match[1]);
    expect(keyframes.sort()).toEqual(['ui2-cve-slide-in', 'ui2-cve-spin']);
    expect(sheets['./cve-base.css']).not.toMatch(/\b(?:cvd-spin|slideInFromRight)\b/);
  });

  it('retires CVE legacy definitions while preserving shared controls and other owners', () => {
    const legacy = (name: string) => retiredRules(name);
    const retired = ['base.css', 'shared.css', 'cve-workbench.css', 'vuln-repo.css'].flatMap((file) => legacy(file)
      .flatMap((rule) => rule.selectors).filter((selector) => /^(?:a)?\.(?:cve-|cvd-|cvd2-|org-cve-|investigation-|notify-)/.test(selector)));
    expect(retired).toEqual([]);
    const shared = sharedSelectors();
    expect(shared).toContain('.confirm-dialog');
    expect(shared).toContain('.segmented-control');
    expect(shared).toContain('.col-toggle');
    expect(selectors(sheets['./inventory-base.css'])).toContain(":where(html[data-ui='2']) .inventory-overview-shell .vuln-repo-dashboard-panel");
    expect(selectors(sheets['./cve-base.css']).filter((selector) => /\.inventory-overview-shell|\.vuln-repo-dashboard-|\.app-shell/.test(selector))).toEqual([]);
  });

  it('preserves Inventory layout and shared lifecycle controls on direct loads', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./inventory-base.css', prefix + '.inventory-shell').display).toBe('flex');
    // Findings base comes later: AI Inventory retains its existing grid page root.
    expect(declared('./findings-base.css', prefix + '.ai-security-page').display).toBe('grid');
    expect(declared('./inventory-base.css', prefix + '.iov-columns')['grid-template-columns']).toBe('1fr 1fr');
    const narrowOverview = rules(sheets['./inventory-base.css']).find((rule) =>
      rule.media === '@media (max-width: 820px)' && rule.selectors.includes(prefix + '.iov-columns'));
    expect(narrowOverview?.declarations).toContainEqual(['grid-template-columns', '1fr']);
    expect(declared('./inventory-base.css', prefix + '.eol-badge-eol').color).toBe('var(--dp-critical)');
    expect(declared('./inventory-base.css', prefix + '.eol-badge-ok').color).toBe('var(--dp-low)');
    expect(declared('./inventory-base.css', prefix + '.ai-dependency-graph-popup').position).toBe('absolute');
    expect(declared('./inventory-base.css', prefix + '.inventory-shell.ai-security-page .fpl-widgets').display).toBe('grid');
  });

  it('retires Inventory legacy rules while leaving navigation, connector and policy owners intact', () => {
    const legacy = (name: string) => retiredRules(name).flatMap((rule) => rule.selectors);
    expect(legacy('finding-detail.css')).toEqual([]);
    expect(legacy('base.css').filter((selector) => /^\.(?:inventory-(?!(?:nav|flyout)(?:-|\b))|host-|software-|sdi-|si-|bom-inventory-|upgrade-|ai-asset-)/.test(selector))).toEqual([]);
    expect(sharedSelectors()).toContain('.inventory-flyout');
    expect(selectors(sheets['./connect-base.css'])).toContain(":where(html[data-ui='2']) .source-focus-hero");
    expect(sharedSelectors()).toContain('.filter-input');
    expect(legacy('eol.css').filter((selector) => /^\.(?:eol-|quality-|slug-suggest-)/.test(selector))).toEqual([]);
    expect(selectors(sheets['./governance-base.css'])).toContain(":where(html[data-ui='2']) .ai-security-hero.policies");
    expect(legacy('ai-security.css').filter((selector) => selector.startsWith('.inventory-shell'))).toEqual([]);
    expect(selectors(sheets['./inventory-base.css']).filter((selector) => /\.inventory-(?:nav|flyout)|\.ai-policy-|\.ai-connector-|\.source-focus-/.test(selector))).toEqual([]);
  });

  it('keeps collapsed sidebar sections hidden despite the submenu grid layout', () => {
    expect(declared('./shell.css', "html[data-ui='2'] .nav-sub-list[hidden]").display).toBe('none');
  });

  it('preserves Governance console, policy and portaled administration controls on direct loads', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./governance-base.css', prefix + '.platform-console-shell').display).toBe('grid');
    expect(declared('./governance-base.css', prefix + '.platform-ai-policy-studio-workspace[hidden]').display).toBe('none');
    expect(declared('./governance-base.css', prefix + '.platform-policy-detail-page button:disabled').cursor).toBe('not-allowed');
    expect(declared('./governance-base.css', prefix + '.um-modal-backdrop').position).toBe('fixed');
    expect(declared('./governance-base.css', prefix + '.um-modal')['overflow']).toBe('auto');
    expect(declared('./governance-base.css', prefix + '.um-form-grid input[disabled]').color).toBe('var(--dp-text-2)');
    const narrowForm = rules(sheets['./governance-base.css']).find((rule) =>
      rule.media === '@media (max-width: 760px)' && rule.selectors.includes(prefix + '.um-form-grid'));
    expect(narrowForm?.declarations).toContainEqual(['grid-template-columns', '1fr']);
  });

  it('retires Governance legacy definitions and preserves connector and operations owners', () => {
    const legacy = (name: string) => retiredRules(name).flatMap((rule) => rule.selectors);
    expect(legacy('user-management.css')).toEqual([]);
    expect(legacy('base.css').filter((selector) => selector.startsWith('.platform-create-tenant-form'))).toEqual([]);
    expect(legacy('shared.css').filter((selector) => selector.startsWith('.platform-console-'))).toEqual([]);
    expect(selectors(sheets['./experience-base.css'])).toContain(":where(html[data-ui='2']) .platform-ops-space");
    expect(legacy('ai-security.css').filter((selector) => /^\.(?:ai-policy-|platform-ai-policy-|platform-policy-|policy-|ai-security-)/.test(selector))).toEqual([]);
    expect(selectors(sheets['./connect-base.css'])).toContain(":where(html[data-ui='2']) .ai-connector-layout");
    expect(selectors(sheets['./connect-base.css'])).toContain(":where(html[data-ui='2']) .ai-run-list");
    expect(selectors(sheets['./connect-base.css'])).toContain(":where(html[data-ui='2']) .ai-scope-list");
    expect(selectors(sheets['./governance-base.css']).filter((selector) => /\.ai-connector-|\.ai-run-|\.ai-scope-|\.platform-ops-/.test(selector))).toEqual([]);
  });

  it('loads Connect provider, configuration and feed controls eagerly inside the app boundary', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./connect-base.css', prefix + '.ai-connector-layout').animation).toBe('ui2-connect-reveal 360ms ease-out both');
    expect(declared('./connect-base.css', prefix + '.sn-health-bar').display).toBe('grid');
    expect(declared('./connect-base.css', prefix + '.platform-feed-search:focus-within').outline).toBe('2px solid var(--dp-accent)');
    expect(declared('./connect-base.css', prefix + '.sn-check-fail').color).toBe('var(--dp-critical)');
  });

  it('retires Connect legacy sheets without consuming the remaining shared controls', () => {
    const legacy = (name: string) => retiredRules(name);
    expect(legacy('connect.css')).toEqual([]);
    expect(legacy('ai-security.css')).toEqual([]);
    expect(existsSync(join(directory, '..', '..', 'pages', 'platform-feed-catalog.css'))).toBe(false);
    expect(sharedSelectors()).toContain('.filter-input');
    expect(sheets['./connect-base.css']).not.toMatch(/animation:\s*ai-security-reveal/);
  });

  it('loads Experience dashboard and Campaign layouts before family presentation', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./experience-base.css', prefix + '.cd-page').display).toBe('flex');
    expect(declared('./experience-base.css', prefix + '.exec-kpi-grid')['grid-template-columns']).toBe('repeat(6, 1fr)');
    const narrow = rules(sheets['./experience-base.css']).find((rule) => rule.media === '@media (max-width: 700px)' && rule.selectors.includes(prefix + '.exec-kpi-grid'));
    expect(narrow?.declarations).toContainEqual(['grid-template-columns', 'repeat(2, 1fr)']);
    expect(sheets['./experience-base.css']).toContain('@keyframes ui2-experience-spin');
    expect(sheets['./experience-base.css']).toContain('@keyframes ui2-experience-toast');
  });

  it('retires Experience legacy sheets and preserves public and shared app defaults', () => {
    const legacy = (name: string) => retiredRules(name);
    expect(legacy('vuln-repo.css')).toEqual([]);
    expect(legacy('exposure-dashboard.css')).toEqual([]);
    const base = legacy('base.css').flatMap((rule) => rule.selectors);
    expect(selectors(readFileSync(join(directory, '..', 'public.css'), 'utf8'))).toContain('.public-demo-shell');
    expect(sharedSelectors()).toContain('.sidebar');
    expect(base.filter((selector) => /^\.(?:campaigns?-|cd-|cw-|cvrs-)/.test(selector))).toEqual([]);
  });

  it('extracts public presentation and its tokens without adopting UI 2 app styles', () => {
    const css = readFileSync(join(directory, '..', 'public.css'), 'utf8');
    const tokens = rules(readFileSync(join(directory, '..', 'public-tokens.css'), 'utf8'));
    expect(selectors(css)).toContain('.public-demo-shell');
    expect(selectors(css)).toContain('.scout-hero');
    expect(css).not.toMatch(/--dp-|data-ui/);
    expect(tokens.flatMap((rule) => rule.selectors)).toEqual([":root:where(:not([data-ui='2']))", ":where(html:not([data-ui='2']))[data-theme='light']", ":where(html:not([data-ui='2'])) body", ":where(html:not([data-ui='2'])) .public-demo-shell", ":where(html:not([data-ui='2']))[data-theme='dark']"]);
    expect(tokens.flatMap((rule) => rule.declarations).filter(([property]) => property.startsWith('--dp-'))).toEqual([]);
  });

  it('keeps shared public/app defaults in explicit cascade order', () => {
    const base = readFileSync(join(directory, '..', 'index.css'), 'utf8');
    expect(base.split(/\r?\n/, 1)[0]).toMatch(/^@import url\(.+\);$/);
    expect([...base.matchAll(/@import\s+"([^"]+)"/g)].map((match) => match[1])).toEqual([
      './public-tokens.css', './public-before.css', './public.css', './public-after.css', './ui2/index.css',
    ]);
    expect(rules(base)).toEqual([]);
    const shared = sharedSelectors();
    expect(shared).toContain('body');
    expect(shared).toContain('.sidebar');
    expect(shared).toContain('button:focus-visible');
  });

  it('preserves semantic Inventory bar colours over the later shared Findings fill', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./findings-base.css', prefix + '.fpl-hbar-fill').background).toBe('var(--dp-accent)');
    for (const [tone, value] of [['success', 'var(--dp-low)'], ['warning', 'var(--dp-warning)'], ['muted', 'color-mix(in srgb, var(--dp-text-2) 36%, transparent)']]) {
      expect(declared('./inventory-base.css', prefix + `.inventory-hbar-${tone}.fpl-hbar-fill`).background).toBe(value);
    }
  });

  it('keeps design tokens on the root and removes the token bridge', () => {
    for (const rule of rules(sheets['./tokens.css'])) {
      expect(rule.selectors.filter((selector) => !ROOT_SELECTORS.includes(selector))).toEqual([]);
      expect(rule.declarations.filter(([property]) => !property.startsWith('--') && property !== 'color-scheme')).toEqual([]);
    }
    expect(existsSync(join(directory, 'legacy-bridge.css'))).toBe(false);
    // Family component-local state tokens remain; shared compatibility aliases do not.
    const retiredAliases = /^(?:--(?:font-(?:body|display|mono)|space-[1-8]|control-(?:sm|md|lg)|radius-(?:sm|md|lg|xl)|bg(?:-gradient)?|shell-glow|sidebar-(?:bg|border|muted)|panel(?:-solid|-muted)?|surface(?:-raised|-hover|-bg)?|track|table-row|text(?:-primary|-secondary|-muted|-1)?|title|muted|border(?:-strong|-color)?|accent(?:-strong)?|critical|high|medium|low|success|danger|warn(?:ing)?(?:-strong)?|shadow-(?:sm|md|lg)|focus-ring|color-[\w-]+|input-bg|primary-subtle|badge-info-(?:bg|border|text)))$/;
    for (const [file, css] of Object.entries(sheets)) {
      expect(rules(css).flatMap((rule) => rule.declarations).filter(([property]) => retiredAliases.test(property)), file).toEqual([]);
      expect([...css.matchAll(/var\((--[\w-]+)/g)].map((match) => match[1]).filter((property) => retiredAliases.test(property)), file).toEqual([]);
    }
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

  it('owns the only source stylesheet import at startup', () => {
    const source = join(directory, '..', '..');
    const files = (folder: string): string[] => readdirSync(folder, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory() ? files(join(folder, entry.name)) : [join(folder, entry.name)]);
    const imports = files(source).filter((file) => /\.(ts|tsx)$/.test(file)).flatMap((file) =>
      [...readFileSync(file, 'utf8').matchAll(/^import\s+['"]([^'"]+\.css)['"];?$/gm)].map((match) => [relative(source, file), match[1]]));
    expect(imports).toEqual([['main.tsx', './styles/index.css']]);
    expect(readFileSync(join(source, 'main.tsx'), 'utf8').split('\n')[0]).toBe("import './styles/index.css';");
  });

  it('isolates public tokens and shared defaults from every app route', () => {
    const root = document.documentElement;
    const css = ['public-tokens.css', 'public-before.css', 'public-after.css'].map((file) => readFileSync(join(directory, '..', file), 'utf8'));
    for (const selector of css.flatMap(selectors)) expect(selector).toContain(":not([data-ui='2'])");
    // Token selectors must switch with the same root attribute used before paint.
    const tokenSelectors = selectors(css[0]);
    const originalUi = root.getAttribute('data-ui'), originalTheme = root.getAttribute('data-theme');
    try {
      for (const theme of ['dark', 'light']) {
        root.setAttribute('data-theme', theme);
        root.removeAttribute('data-ui');
        expect(tokenSelectors.some((selector) => root.matches(selector))).toBe(true);
        root.setAttribute('data-ui', '2');
        expect(tokenSelectors.some((selector) => root.matches(selector))).toBe(false);
      }
    } finally {
      if (originalUi === null) root.removeAttribute('data-ui'); else root.setAttribute('data-ui', originalUi);
      if (originalTheme === null) root.removeAttribute('data-theme'); else root.setAttribute('data-theme', originalTheme);
    }
    for (const file of ['base.css', 'shared.css', 'cve-workbench.css', 'eol.css', 'shared-before-public.css', 'shared-after-public.css']) retiredRules(file);
  });

  it('retains shared auth defaults, responsive shell, dialogs and eager table controls', () => {
    const prefix = ":where(html[data-ui='2']) ";
    expect(declared('./app-base.css', prefix + '.auth-gate').display).toBe('grid');
    expect(declared('./app-base.css', prefix + 'body')['font-family']).toBe('var(--dp-font)');
    expect(declared('./app-base.css', prefix + '.sidebar').position).toBe('sticky');
    expect(declared('./app-base.css', prefix + '.modal-overlay').position).toBe('fixed');
    expect(declared('./app-base.css', prefix + '.confirm-dialog').background).toBeDefined();
    expect(declared('./primitives.css', "html[data-ui='2'] .ui2-dialog[open]").position).toBe('fixed');
    expect(declared('./tables.css', prefix + '.table-settings-btn:disabled').cursor).toBe('not-allowed');
    expect(declared('./tables.css', prefix + 'table.resizable-table')['table-layout']).toBe('fixed');
    expect(rules(sheets['./app-base.css']).some((rule) => rule.media && rule.selectors.includes(prefix + '.app-shell'))).toBe(true);
    const auth = prefix + '.public-demo-shell:where(.ui2-experience-family, .ui2-experience-family *)';
    expect(declared('./app-base.css', auth)['min-height']).toBe('100vh');
  });

  it('keeps each severity and status tone on its own token', () => {
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-critical")).toEqual({ '--ui2-tone': 'var(--dp-critical)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-high")).toEqual({ '--ui2-tone': 'var(--dp-high)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-medium")).toEqual({ '--ui2-tone': 'var(--dp-medium)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .severity-low")).toEqual({ '--ui2-tone': 'var(--dp-low)' });
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.error")['--ui2-tone']).toBe('var(--dp-critical)');
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.success")['--ui2-tone']).toBe('var(--dp-success)');
    expect(declared('./primitives.css', "html[data-ui='2'] .notice.warning")['--ui2-tone']).toBe('var(--dp-warning)');
    const lifecycle = declared('./inventory-base.css', ":where(html[data-ui='2']) .eol-badge-eol");
    expect(lifecycle.color).toBe('var(--dp-critical)');
    expect(declared('./inventory-base.css', ":where(html[data-ui='2']) .eol-badge-ok").color).toBe('var(--dp-low)');
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

  // The public marketing routes never carry data-ui (src/lib/presentationBoundary.ts). The auth-entry pages
  // share their markup, so UI 2.0 may only style public classes under the auth-entry family root.
  it('keeps shared public markup inside the app boundary and auth presentation under its family', () => {
    const publicClass = /\.(public-[\w-]+|demo-[\w-]+|blog-[\w-]+|scout-hero)\b/;
    const outsideFamily = Object.entries(sheets).flatMap(([file, css]) => selectors(css)
      .filter((selector) => publicClass.test(selector) && !/^html\[data-ui='2'\] \.ui2-experience-family[.\s]/.test(selector) && !(file === './app-base.css' && (selector.startsWith(":where(html[data-ui='2']) .demo-status-pill") || (selector.startsWith(":where(html[data-ui='2']) ") && selector.includes(':where(.ui2-experience-family, .ui2-experience-family *)')))))
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

  it('anchors Fix Intelligence rules on its page roots and the embedded Remediation options panel', () => {
    const unanchored = selectors(sheets['./fix-intelligence.css']).filter((selector) => !anchoredOn(selector, ['.ui2-fix-family']));
    expect(unanchored).toEqual([]);
  });

  it('anchors Inventory-family rules on the Inventory page roots', () => {
    const unanchored = selectors(sheets['./inventory.css']).filter((selector) => !anchoredOn(selector, ['.ui2-inventory-family']));
    expect(unanchored).toEqual([]);
  });
});
