// Presentation only: public marketing routes keep their own styles. Auth and app
// routes always use UI 2. This never changes routing, queries or authorization.
const THEME_STORAGE_KEY = 'scoutai-theme';

// AppShell owns the theme once mounted; public and login routes render outside it, so a
// direct load must pick up the stored choice. A theme already on the root is never replaced.
function applyStoredTheme(root: HTMLElement): void {
  if (root.hasAttribute('data-theme')) return;
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
  } catch {
    // Storage can be blocked; the default presentation applies.
  }
}

export function applyPresentationBoundary(root: HTMLElement, pathname: string): void {
  // Login, password setup and invitations retain the app presentation.
  if (/^\/demo(?:\/|$)/i.test(pathname)) {
    root.removeAttribute('data-ui');
  } else {
    root.setAttribute('data-ui', '2');
  }
  applyStoredTheme(root);
}
