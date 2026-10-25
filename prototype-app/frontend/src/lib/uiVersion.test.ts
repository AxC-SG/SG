import { afterEach, describe, expect, it } from 'vitest';
import { applyUiVersion, resolveUiVersion } from './uiVersion';

describe('uiVersion', () => {
  afterEach(() => {
    document.documentElement.removeAttribute('data-ui');
  });

  it('keeps the legacy presentation unless the flag is exactly 2', () => {
    expect(resolveUiVersion(undefined)).toBeNull();
    expect(resolveUiVersion('')).toBeNull();
    expect(resolveUiVersion('true')).toBeNull();
    expect(resolveUiVersion('1')).toBeNull();
    expect(resolveUiVersion(' 2 ')).toBe('2');
  });

  it('sets data-ui on the root element only when enabled', () => {
    const root = document.documentElement;
    applyUiVersion(root, undefined, '/findings');
    expect(root.hasAttribute('data-ui')).toBe(false);

    applyUiVersion(root, '2', '/findings');
    expect(root.getAttribute('data-ui')).toBe('2');

    applyUiVersion(root, undefined, '/findings');
    expect(root.hasAttribute('data-ui')).toBe(false);
  });

  it.each(['/demo', '/demo/', '/demo/blog', '/demo/blog/mythos-readiness', '/demo/request', '/demo/request/success', '/demo/expired', '/DEMO/blog'])('keeps %s outside UI 2.0 even when enabled', (pathname) => {
    document.documentElement.setAttribute('data-ui', '2');
    applyUiVersion(document.documentElement, '2', pathname);
    expect(document.documentElement).not.toHaveAttribute('data-ui');
  });

  it.each(['/login', '/setup/token', '/invite/token', '/tenant-invite/token', '/findings', '/platform/tenants', '/demonstration'])('retains UI 2.0 on %s', (pathname) => {
    applyUiVersion(document.documentElement, '2', pathname);
    expect(document.documentElement).toHaveAttribute('data-ui', '2');
  });

  it('leaves the theme attribute and storage untouched', () => {
    const root = document.documentElement;
    root.setAttribute('data-theme', 'dark');
    localStorage.setItem('scoutai-theme', 'dark');
    applyUiVersion(root, '2', '/findings');
    expect(root.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('scoutai-theme')).toBe('dark');
    localStorage.clear();
    root.removeAttribute('data-theme');
  });
});
