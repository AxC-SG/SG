export function isDocumentVisible(): boolean {
  if (typeof document === 'undefined') {
    return true;
  }
  return document.visibilityState !== 'hidden';
}

export function visibleInterval(intervalMs: number): number | false {
  return isDocumentVisible() ? intervalMs : false;
}
