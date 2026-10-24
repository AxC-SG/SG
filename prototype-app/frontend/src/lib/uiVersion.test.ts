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
    applyUiVersion(root, undefined);
    expect(root.hasAttribute('data-ui')).toBe(false);

    applyUiVersion(root, '2');
    expect(root.getAttribute('data-ui')).toBe('2');

    applyUiVersion(root, undefined);
    expect(root.hasAttribute('data-ui')).toBe(false);
  });

  it('leaves the theme attribute and storage untouched', () => {
    const root = document.documentElement;
    root.setAttribute('data-theme', 'dark');
    localStorage.setItem('scoutai-theme', 'dark');
    applyUiVersion(root, '2');
    expect(root.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('scoutai-theme')).toBe('dark');
    localStorage.clear();
    root.removeAttribute('data-theme');
  });
});
