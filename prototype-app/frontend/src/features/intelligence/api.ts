import { apiRequest } from '../../api/client';
import type { SyncTriggerResponse } from '../connect/types';

export type Candidate = {
  id: string; status: string; base_release_id: string | null; digest: string | null;
  selected_run_ids: string[]; expanded_run_ids: string[]; normalization_policy: string;
  quality_report: Record<string, number | string>; error_code: string | null; published_release_id: string | null;
};
export type CandidateRecord = { id: number; kind: string; external_id: string; source_system: string; validation: string; payload: unknown };
export type Release = { id: string; generation: number; predecessor_id: string | null; kind: string; actor: string; published_at: string; digest: string };
export type Processing = { tenant_id: string; status: string; required_revision: number; completed_revision: number; completed_generation: number; last_completed_at: string | null; last_error: string | null; current_release_id?: string | null; current_generation?: number };
export type FeedSchedule = { sync_type: string; enabled: boolean; interval_hours: number; next_due_at: string | null };
const root = '/platform/intelligence';
const post = <T>(path: string, body: unknown) => apiRequest<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const intelligenceApi = {
  trigger: (type: 'OSV' | 'EPSS') => post<SyncTriggerResponse>(`${root}/feeds/${type}/run`, {}),
  create: (syncRunIds: string[]) => post<Candidate>(`${root}/candidates`, { syncRunIds }),
  candidate: (id: string) => apiRequest<Candidate>(`${root}/candidates/${id}`),
  records: (id: string, page: number) => apiRequest<CandidateRecord[]>(`${root}/candidates/${id}/records?page=${page}&size=50`),
  publish: (candidate: Candidate, idempotencyKey: string) => post(`${root}/candidates/${candidate.id}/publish`, { digest: candidate.digest, baseReleaseId: candidate.base_release_id, idempotencyKey }),
  reject: (id: string, reason: string) => post(`${root}/candidates/${id}/reject`, { reason }),
  releases: () => apiRequest<Release[]>(`${root}/releases`),
  withdraw: (id: string, idempotencyKey: string) => post(`${root}/releases/${id}/withdraw`, { idempotencyKey }),
  processing: (id: string, page = 0) => apiRequest<Processing[]>(`${root}/releases/${id}/processing?page=${page}&size=50`),
  tenantStatus: () => apiRequest<Processing>('/connectors/vulnerability-sources/processing'),
  schedules: () => apiRequest<FeedSchedule[]>(`${root}/schedules`),
  saveSchedule: (type: string, enabled: boolean, intervalHours: number) => apiRequest<FeedSchedule>(`${root}/schedules/${type}`, { method: 'PUT', body: JSON.stringify({ enabled, intervalHours }) }),
};
