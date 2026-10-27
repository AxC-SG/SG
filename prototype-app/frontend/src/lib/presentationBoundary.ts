// Presentation only: public marketing routes keep their own styles. Auth and app
// routes always use UI 2. This never changes routing, queries or authorization.
export function applyPresentationBoundary(root: HTMLElement, pathname: string): void {
  // Login, password setup and invitations retain the app presentation.
  if (/^\/demo(?:\/|$)/i.test(pathname)) {
    root.removeAttribute('data-ui');
  } else {
    root.setAttribute('data-ui', '2');
  }
}
