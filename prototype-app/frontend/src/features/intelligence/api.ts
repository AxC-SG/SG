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
export type PublicationProgress = { status: string; requested_action?: 'PAUSE' | 'CANCEL' | null; phase: string; processed: number; total: number | null; heartbeat_at: string | null; started_at: string | null; checkpoint: unknown; attempt_count: number; events: { id: string; level: string; message: string; created_at: string }[] };
export type ImportProfile = { id: string; name: string; sources: string[]; publicationYearFrom: number | null; publicationYearTo: number | null; minCvss: number | null; maxCvss: number | null; severities: string[]; includeUnknownScores: boolean };
export type PublicationAction = 'PAUSE' | 'RESUME' | 'RETRY' | 'CANCEL';
const post = <T>(path: string, body: unknown) => apiRequest<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const intelligenceApi = {
  progress: (id: string) => apiRequest<PublicationProgress>(`${root}/candidates/${id}/progress`),
  control: (id: string, action: PublicationAction) => post(`${root}/candidates/${id}/control`, { action }),
  profiles: () => apiRequest<ImportProfile[]>(`${root}/import-profiles`),
  saveProfile: (profile: Omit<ImportProfile, 'id'>) => post<ImportProfile>(`${root}/import-profiles`, profile),
  runProfile: (id: string) => post(`${root}/import-profiles/${id}/run`, {}),
  scheduleProfile: (id: string, enabled: boolean, intervalHours: number) => post(`${root}/import-profiles/${id}/schedule`, { enabled, intervalHours }),
  profileSchedule: (id: string) => apiRequest<{ enabled: boolean; intervalHours: number }>(`${root}/import-profiles/${id}/schedule`),
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
