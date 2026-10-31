import React from 'react';
import { PageHeaderRegistryContext, PageHeaderStateContext, type PageHeaderRegistration, type PageHeaderRegistry } from './pageHeaderState';

export function PageHeaderProvider({ children }: { children: React.ReactNode }) {
  const [registration, setRegistration] = React.useState<PageHeaderRegistration | null>(null);
  const registry = React.useMemo<PageHeaderRegistry>(() => ({
    register: setRegistration,
    clear: (id) => setRegistration((current) => (current?.id === id ? null : current)),
  }), []);
  return (
    <PageHeaderRegistryContext.Provider value={registry}>
      <PageHeaderStateContext.Provider value={registration}>{children}</PageHeaderStateContext.Provider>
    </PageHeaderRegistryContext.Provider>
  );
}
