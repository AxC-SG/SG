// Presentation-only rollout switch for UI 2.0. It sets data-ui="2" on <html>, which
// activates the scoped styles in src/styles/ui2/. It never affects routing, queries,
// authorization or entitlements. Unset (the default) keeps the legacy presentation;
// rollback is a rebuild without VITE_UI_VERSION.
export const UI_VERSION_ATTRIBUTE = 'data-ui';

export function resolveUiVersion(value: string | undefined): '2' | null {
  return value?.trim() === '2' ? '2' : null;
}

export function applyUiVersion(root: HTMLElement, value: string | undefined): void {
  const version = resolveUiVersion(value);
  if (version) {
    root.setAttribute(UI_VERSION_ATTRIBUTE, version);
  } else {
    root.removeAttribute(UI_VERSION_ATTRIBUTE);
  }
}
