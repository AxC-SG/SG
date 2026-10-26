import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api, apiRequest } from '../../api/client';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../../lib/polling';
import type { SyncRun, VulnerabilitySourceSystem } from './types';

export type SyncRunsQueryParams = Parameters<typeof api.listSyncRuns>[0];
type QueryPollingOption = number | false | undefined;

function shouldPollRuns(runs: SyncRun[] | undefined): boolean {
  return (runs ?? []).some((run) => {
    const status = run.status.trim().toUpperCase();
    return status === 'RUNNING' || status === 'STARTED' || status === 'QUEUED';
  });
}

export function useSyncRunsQuery(params: SyncRunsQueryParams, enabled = true, refetchInterval?: QueryPollingOption) {
  return useQuery({
    queryKey: ['sync-runs', params],
    queryFn: () => api.listSyncRuns(params),
    enabled,
    placeholderData: keepPreviousData,
    refetchInterval: refetchInterval ?? ((query) => (
      shouldPollRuns(query.state.data as SyncRun[] | undefined) ? RUN_QUEUE_REFRESH_INTERVAL_MS : false
    )),
    refetchIntervalInBackground: false
  });
}

export function useIngestionJobsQuery(enabled = true) {
  return useQuery({
    queryKey: ['ingestion-jobs', { page: 0, size: 100 }],
    queryFn: () => api.listIngestionJobs(0, 100),
    enabled,
    // Connector execution can enqueue a job while this query is still inside the
    // application-wide stale window. The run queue must always reconcile with the
    // server when it is opened, otherwise a newly queued job can remain invisible.
    refetchOnMount: 'always',
    refetchInterval: (query) => (
      (query.state.data?.items ?? []).some((job) => {
        const status = job.status.trim().toUpperCase();
        return status === 'QUEUED' || status === 'RUNNING';
      })
        ? RUN_QUEUE_REFRESH_INTERVAL_MS
        : false
    ),
    refetchIntervalInBackground: false
  });
}

export function useVexAssertionRepairSummaryQuery(enabled = true, refetchInterval?: QueryPollingOption) {
  return useQuery({
    queryKey: ['vex-assertion-repair-summary'],
    queryFn: api.getVexAssertionRepairSummary,
    enabled,
    refetchInterval
  });
}

export function useSourceFilterConfigQuery(sourceSystem: VulnerabilitySourceSystem | null, enabled = true) {
  return useQuery({
    queryKey: ['source-filter-config', sourceSystem],
    queryFn: () => api.getVulnerabilitySourceFilterConfig(sourceSystem ?? 'nvd'),
    enabled: enabled && sourceSystem != null
  });
}

export function useGithubSbomSourcesQuery() {
  return useQuery({
    queryKey: ['github-sbom-sources'],
    queryFn: api.listGithubSbomSources
  });
}

export function useServiceNowCmdbConfigQuery() {
  return useQuery({
    queryKey: ['service-now-cmdb-config'],
    queryFn: api.getServiceNowCmdbConfig
  });
}

export function useSccmCmdbConfigQuery() {
  return useQuery({
    queryKey: ['sccm-cmdb-config'],
    queryFn: api.getSccmCmdbConfig
  });
}

export function useAwsDiscoveryConfigQuery() {
  return useQuery({
    queryKey: ['aws-discovery-config'],
    queryFn: api.getAwsDiscoveryConfig
  });
}

export function useAwsDiscoveryTargetsQuery(enabled = true) {
  return useQuery({
    queryKey: ['aws-discovery-targets'],
    queryFn: api.listAwsDiscoveryTargets,
    enabled
  });
}

export function useAzureDiscoveryConfigQuery() {
  return useQuery({
    queryKey: ['azure-discovery-config'],
    queryFn: api.getAzureDiscoveryConfig
  });
}

export function useAzureDiscoveryTargetsQuery(enabled = true) {
  return useQuery({
    queryKey: ['azure-discovery-targets'],
    queryFn: api.listAzureDiscoveryTargets,
    enabled
  });
}

export interface OsvCoverageResponse {
  ecosystemCounts: Record<string, number>;
  totalAdvisories: number;
  lastSyncedAt?: string;
}

export interface AdvisoryEquivalenceGroup {
  primaryCveId: string;
  ghsaIds: string[];
  osvIds: string[];
}

export const useOsvCoverageQuery = (tenantId?: string) => {
  const id = tenantId;

  return useQuery({
    queryKey: ['osv-coverage', id],
    queryFn: async () => {
      return apiRequest<OsvCoverageResponse>(`/tenants/${encodeURIComponent(id!)}/osv/coverage`);
    },
    enabled: !!id,
    staleTime: 5 * 60 * 1000, // 5 minutes
    retry: 1,
  });
};

export const useAdvisoryEquivalencesQuery = (cveId?: string) => {
  return useQuery({
    queryKey: ['advisory-equivalences', cveId],
    queryFn: async () => {
      if (!cveId) throw new Error('CVE ID required');

      return apiRequest<AdvisoryEquivalenceGroup>(`/cve-detail/${encodeURIComponent(cveId)}/advisory-equivalences`);
    },
    enabled: !!cveId,
    staleTime: 1 * 60 * 1000, // 1 minute
    retry: 1,
  });
};
