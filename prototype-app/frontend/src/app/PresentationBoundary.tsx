import { useLayoutEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { applyPresentationBoundary } from '../lib/presentationBoundary';

// Update before paint on links and browser Back/Forward navigation.
export function PresentationBoundary() {
  const { pathname } = useLocation();
  useLayoutEffect(() => {
    applyPresentationBoundary(document.documentElement, pathname);
  }, [pathname]);
  return null;
}
