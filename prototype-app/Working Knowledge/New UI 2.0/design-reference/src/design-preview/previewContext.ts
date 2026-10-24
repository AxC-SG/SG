import React from 'react';

/** Mock-only switches surfaced through the "Reference controls" panel. */
export type PreviewState = {
  scope: 'tenant' | 'platform';
  loading: boolean;
  persona: string | null;
  role: 'TENANT_ADMIN' | 'SECURITY_ANALYST' | 'INVENTORY_ADMIN' | 'READ_ONLY_AUDITOR';
  scenario: 'ready' | 'refreshing' | 'partial-error' | 'save-error' | 'empty' | 'provisioning' | 'blocked' | 'expired' | 'session-error';
  aiEntitled: boolean;
  enhancements: boolean;
};

export const DEFAULT_PREVIEW: PreviewState = { scope: 'tenant', loading: false, persona: null, role: 'TENANT_ADMIN', scenario: 'ready', aiEntitled: true, enhancements: false };
export const PreviewContext = React.createContext<PreviewState>(DEFAULT_PREVIEW);

export function usePreview(): PreviewState {
  return React.useContext(PreviewContext);
}

export function useCapabilities() {
  const preview = usePreview();
  return {
    canTriage: preview.scope === 'tenant' && ['TENANT_ADMIN', 'SECURITY_ANALYST'].includes(preview.role),
    canConfigure: preview.scope === 'tenant' && preview.role === 'TENANT_ADMIN',
    canInventory: preview.scope === 'tenant' && ['TENANT_ADMIN', 'INVENTORY_ADMIN'].includes(preview.role),
    canPublish: preview.scope === 'platform',
  };
}
