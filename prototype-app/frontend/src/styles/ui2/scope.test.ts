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

describe('UI 2.0 stylesheet scope', () => {
  it('loads the UI 2.0 sheets', () => {
    expect(Object.keys(sheets)).toEqual(expect.arrayContaining(['./tokens.css', './primitives.css', './findings.css']));
    expect(selectors(sheets['./findings.css']).length).toBeGreaterThan(100);
    expect(selectors(".a{} html[data-ui='2'] .b, .c{}")).toEqual(['.a', "html[data-ui='2'] .b", '.c']);
    expect(selectors(":is(.a, .b) .c, .d{}")).toEqual([':is(.a, .b) .c', '.d']);
    expect(anchoredOn("html[data-ui='2'] :is(.a, .b) .c", ['.a', '.b'])).toBe(true);
    expect(anchoredOn("html[data-ui='2'] :is(.a, .z) .c", ['.a', '.b'])).toBe(false);
  });

  it('scopes every rule to html[data-ui=2]', () => {
    const unscoped = Object.entries(sheets).flatMap(([file, css]) =>
      selectors(css).filter((selector) => !selector.startsWith("html[data-ui='2']")).map((selector) => `${file}: ${selector}`));
    expect(unscoped).toEqual([]);
  });

  it('anchors Findings-family rules on the Findings page roots, the shared Inventory or Governance family or the portaled column filter', () => {
    const roots = ['.fpl-root', '.fd3-page', '.ui2-findings-family', '.ui2-inventory-family', '.ui2-governance-family', '.fpl-col-filter-'];
    const unanchored = selectors(sheets['./findings.css']).filter((selector) => !anchoredOn(selector, roots));
    expect(unanchored).toEqual([]);
  });

  it('anchors CVE-workflow rules on the CVE page roots or the shared Governance record detail', () => {
    expect(selectors(sheets['./cve.css']).length).toBeGreaterThan(100);
    const roots = ['.cve-assessment-page', '.ui2-cve-family', '.vuln-repo-vulnerabilities-shell', '.vuln-repo-assets-shell', '.ui2-governance-family'];
    const unanchored = selectors(sheets['./cve.css']).filter((selector) => !anchoredOn(selector, roots));
    expect(unanchored).toEqual([]);
    // Only :is() groups that include a CVE root may mention the Governance family.
    const governanceOnly = selectors(sheets['./cve.css']).filter((selector) => anchoredOn(selector, ['.ui2-governance-family']));
    expect(governanceOnly).toEqual([]);
  });

  it('anchors Governance-family rules on the Governance page roots', () => {
    expect(selectors(sheets['./governance.css']).length).toBeGreaterThan(50);
    const unanchored = selectors(sheets['./governance.css']).filter((selector) => !anchoredOn(selector, ['.ui2-governance-family']));
    expect(unanchored).toEqual([]);
  });

  it('anchors Inventory-family rules on the Inventory page roots', () => {
    expect(selectors(sheets['./inventory.css']).length).toBeGreaterThan(20);
    const unanchored = selectors(sheets['./inventory.css']).filter((selector) => !anchoredOn(selector, ['.ui2-inventory-family']));
    expect(unanchored).toEqual([]);
  });
});
