import { afterEach, describe, expect, it } from 'vitest';
import { applyPresentationBoundary } from './presentationBoundary';

afterEach(() => {
  document.documentElement.removeAttribute('data-ui');
  document.documentElement.removeAttribute('data-theme');
  localStorage.clear();
});

describe('presentation route boundary', () => {
  it.each(['/demo', '/demo/', '/demo/blog', '/demo/blog/mythos-readiness', '/demo/request', '/demo/request/success', '/demo/expired', '/DEMO/blog'])('keeps %s outside UI 2 on direct load', (pathname) => {
    document.documentElement.setAttribute('data-ui', '2');
    applyPresentationBoundary(document.documentElement, pathname);
    expect(document.documentElement).not.toHaveAttribute('data-ui');
  });

  it.each(['/login', '/setup/token', '/invite/token', '/tenant-invite/token', '/findings', '/platform/tenants', '/demonstration'])('always applies UI 2 on direct load of %s', (pathname) => {
    applyPresentationBoundary(document.documentElement, pathname);
    expect(document.documentElement).toHaveAttribute('data-ui', '2');
  });

  it('idempotently replaces a stale presentation attribute using only the route', () => {
    const root = document.documentElement;
    root.setAttribute('data-ui', '1');
    for (const path of ['/findings', '/findings']) {
      applyPresentationBoundary(root, path);
      expect(root).toHaveAttribute('data-ui', '2');
    }
    for (const path of ['/demo', '/demo']) {
      applyPresentationBoundary(root, path);
      expect(root).not.toHaveAttribute('data-ui');
    }
    applyPresentationBoundary(root, '/login');
    expect(root).toHaveAttribute('data-ui', '2');
  });

  it.each(['dark', 'light'])('preserves the %s theme attribute and scoutai-theme storage across boundaries', (theme) => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    localStorage.setItem('scoutai-theme', theme);
    for (const pathname of ['/findings', '/demo/blog', '/login', '/demo/request']) {
      applyPresentationBoundary(root, pathname);
      expect(root).toHaveAttribute('data-theme', theme);
      expect(localStorage.getItem('scoutai-theme')).toBe(theme);
    }
  });
});
