// Presentation-only rollout switch for UI 2.0. It sets data-ui="2" on <html>, which
// activates the scoped styles in src/styles/ui2/ outside the public marketing routes.
// It follows client-side navigation and never affects routing, queries,
// authorization or entitlements. Unset (the default) keeps the legacy presentation;
// rollback is a rebuild without VITE_UI_VERSION.
export const UI_VERSION_ATTRIBUTE = 'data-ui';

export function resolveUiVersion(value: string | undefined): '2' | null {
  return value?.trim() === '2' ? '2' : null;
}

export function applyUiVersion(root: HTMLElement, value: string | undefined, pathname: string): void {
  // The /demo tree contains the excluded landing, blog and demo-request pages.
  // Login, password setup and invitation routes retain the app presentation.
  const version = /^\/demo(?:\/|$)/i.test(pathname) ? null : resolveUiVersion(value);
  if (version) {
    root.setAttribute(UI_VERSION_ATTRIBUTE, version);
  } else {
    root.removeAttribute(UI_VERSION_ATTRIBUTE);
  }
}
