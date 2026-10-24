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

function selectors(css: string): string[] {
  const withoutComments = css.replace(/\/\*[\s\S]*?\*\//g, '');
  return [...withoutComments.matchAll(/([^{}]+)\{/g)]
    .map((match) => match[1].trim())
    .filter((selector) => !selector.startsWith('@'))
    .flatMap((selector) => selector.split(',').map((part) => part.trim()));
}

describe('UI 2.0 stylesheet scope', () => {
  it('loads the UI 2.0 sheets', () => {
    expect(Object.keys(sheets)).toEqual(expect.arrayContaining(['./tokens.css', './primitives.css', './findings.css']));
    expect(selectors(sheets['./findings.css']).length).toBeGreaterThan(100);
    expect(selectors(".a{} html[data-ui='2'] .b, .c{}")).toEqual(['.a', "html[data-ui='2'] .b", '.c']);
  });

  it('scopes every rule to html[data-ui=2]', () => {
    const unscoped = Object.entries(sheets).flatMap(([file, css]) =>
      selectors(css).filter((selector) => !selector.startsWith("html[data-ui='2']")).map((selector) => `${file}: ${selector}`));
    expect(unscoped).toEqual([]);
  });

  it('anchors Findings-family rules on the Findings page roots or the portaled column filter', () => {
    const anchor = /^html\[data-ui='2'\] (\.fpl-root|\.fd3-page|\.ui2-findings-family|\.fpl-col-filter-)/;
    const unanchored = selectors(sheets['./findings.css']).filter((selector) => !anchor.test(selector));
    expect(unanchored).toEqual([]);
  });
});
