import { useLayoutEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { applyUiVersion } from '../lib/uiVersion';

// Update before paint on both links and browser back/forward navigation.
export function UiVersionPresentation() {
  const { pathname } = useLocation();
  useLayoutEffect(() => {
    applyUiVersion(document.documentElement, import.meta.env.VITE_UI_VERSION, pathname);
  }, [pathname]);
  return null;
}
