import React from 'react';
import { useLocation } from 'react-router-dom';

// The shell renders the only authenticated route H1. Pages register a title (and optional
// actions) for their own pathname; the shell ignores a registration made for any other path,
// so a navigation never shows the previous record's title while the next page loads.
export type PageHeaderContent = {
  title: string;
  actions?: React.ReactNode;
};

export type PageHeaderRegistration = PageHeaderContent & { pathname: string; id: number };

export type PageHeaderRegistry = {
  register: (registration: PageHeaderRegistration) => void;
  clear: (id: number) => void;
};

// Registering pages read only the stable registry, so their own registration never re-renders them.
export const PageHeaderRegistryContext = React.createContext<PageHeaderRegistry | null>(null);
export const PageHeaderStateContext = React.createContext<PageHeaderRegistration | null>(null);

let nextRegistrationId = 0;

/** Registers the route header before paint. Pass `null` while the record is still unknown. */
export function usePageHeader(content: PageHeaderContent | null): void {
  const registry = React.useContext(PageHeaderRegistryContext);
  const { pathname } = useLocation();
  const title = content?.title;
  const actions = content?.actions;
  React.useLayoutEffect(() => {
    if (!registry || title == null) return undefined;
    const id = ++nextRegistrationId;
    registry.register({ id, pathname, title, actions });
    return () => registry.clear(id);
  }, [registry, pathname, title, actions]);
}

/** The header the shell renders for `pathname`: the current registration, else the route fallback. */
export function useRouteHeader(pathname: string, fallbackTitle: string): PageHeaderContent {
  const registration = React.useContext(PageHeaderStateContext);
  if (registration && registration.pathname === pathname) {
    return { title: registration.title, actions: registration.actions };
  }
  return { title: fallbackTitle };
}
