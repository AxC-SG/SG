import { apiRequest } from '../../api/client';
import type { SyncTriggerResponse } from '../connect/types';
import type {
  FixContext,
  FixControlRequest,
  FixDetail,
  FixListFilters,
  FixListPage,
  FixSummary,
  FixView,
  PatchConnectionTest,
  PatchConnectorConfig,
  PatchConnectorConfigRequest,
  PatchProvider,
  PatchSyncStatus
} from './types';

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body)
});

function listQuery(filters: FixListFilters): string {
  const params = new URLSearchParams({ view: filters.view });
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.ecosystem) params.set('ecosystem', filters.ecosystem);
  if (filters.status) params.set('status', filters.status);
  if (filters.search?.trim()) params.set('search', filters.search.trim());
  params.set('page', String(filters.page ?? 0));
  params.set('size', String(filters.size ?? 50));
  return params.toString();
}

export const fixIntelligenceApi = {
  summary: (view: FixView) =>
    apiRequest<FixSummary>(`/fix-intelligence/summary?view=${encodeURIComponent(view)}`),
  list: (filters: FixListFilters) => apiRequest<FixListPage>(`/fix-intelligence/fixes?${listQuery(filters)}`),
  detail: (fixId: string) => apiRequest<FixDetail>(`/fix-intelligence/fixes/${encodeURIComponent(fixId)}`),
  create: (payload: FixControlRequest) => apiRequest<FixDetail>('/fix-intelligence/fixes', json('POST', payload)),
  update: (fixId: string, payload: FixControlRequest) =>
    apiRequest<FixDetail>(`/fix-intelligence/fixes/${encodeURIComponent(fixId)}`, json('PUT', payload)),
  approve: (fixId: string) =>
    apiRequest<FixDetail>(`/fix-intelligence/fixes/${encodeURIComponent(fixId)}/approve`, { method: 'POST' }),
  retire: (fixId: string) =>
    apiRequest<FixDetail>(`/fix-intelligence/fixes/${encodeURIComponent(fixId)}/retire`, { method: 'POST' }),
  context: (params: { cveId?: string | null; assetId?: string | null }) => {
    const query = new URLSearchParams();
    if (params.cveId) query.set('cveId', params.cveId);
    if (params.assetId) query.set('assetId', params.assetId);
    return apiRequest<FixContext>(`/fix-intelligence/context?${query.toString()}`);
  },

  getPatchConnector: (provider: PatchProvider) =>
    apiRequest<PatchConnectorConfig>(`/connectors/patch/${provider}`),
  savePatchConnector: (provider: PatchProvider, payload: PatchConnectorConfigRequest) =>
    apiRequest<PatchConnectorConfig>(`/connectors/patch/${provider}`, json('PUT', payload)),
  testPatchConnector: (provider: PatchProvider) =>
    apiRequest<PatchConnectionTest>(`/connectors/patch/${provider}/test`, { method: 'POST' }),
  syncPatchConnector: (provider: PatchProvider) =>
    apiRequest<SyncTriggerResponse>(`/connectors/patch/${provider}/sync`, { method: 'POST' }),
  patchSyncStatus: (provider: PatchProvider) =>
    apiRequest<PatchSyncStatus>(`/connectors/patch/${provider}/sync/status`)
};
