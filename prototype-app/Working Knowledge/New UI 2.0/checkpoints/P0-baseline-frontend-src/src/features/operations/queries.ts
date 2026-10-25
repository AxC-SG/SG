import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DASHBOARD_REFRESH_INTERVAL_MS, OPERATIONS_REFRESH_INTERVAL_MS } from '../../lib/polling';
import type {
  ClusterImpactResult,
  CorrelationOverridePayload,
  NormalizationOverridePayload,
  OperationalApiReadPath,
  OperationalFreshnessDrift,
  OperationalIngestionEfficiency,
  OperationalMetricDefinition,
  PerformanceScorecard,
  OperationalSectionResponse,
  SloStatus
} from './types';

export type OperationsDashboardViewKey = 'quality' | 'pipeline' | 'platform-health';

export type PipelinePayload = {
  ingestion: OperationalSectionResponse<OperationalIngestionEfficiency>;
  freshness: OperationalSectionResponse<OperationalFreshnessDrift>;
};

export type PlatformHealthPayload = {
  readPath: OperationalSectionResponse<OperationalApiReadPath>;
  slo: SloStatus;
  catalog: OperationalSectionResponse<OperationalMetricDefinition[]>;
  performanceScorecard: PerformanceScorecard;
};

async function loadOperationsView(selectedView: OperationsDashboardViewKey): Promise<PipelinePayload | PlatformHealthPayload | null> {
  switch (selectedView) {
    case 'quality':
      return null;
    case 'pipeline': {
      const [ingestion, freshness] = await Promise.all([
        api.getOperationalIngestionEfficiency(),
        api.getOperationalFreshnessDrift(),
      ]);
      return {
        ingestion,
        freshness,
      };
    }
    case 'platform-health': {
      const [readPath, slo, catalog, performanceScorecard] = await Promise.all([
        api.getOperationalApiReadPath(),
        api.getSloStatus(),
        api.getOperationalMetricCatalog(),
        api.getOperationalPerformanceScorecard()
      ]);
      return {
        readPath,
        slo,
        catalog,
        performanceScorecard
      };
    }
    default:
      return loadOperationsView('pipeline');
  }
}

export function useOperationsViewQuery(selectedView: OperationsDashboardViewKey) {
  return useQuery({
    queryKey: ['operations-view', selectedView],
    queryFn: () => loadOperationsView(selectedView),
    enabled: selectedView !== 'quality',
    refetchInterval: OPERATIONS_REFRESH_INTERVAL_MS
  });
}

export type OperationalQualityIssuesQueryParams = NonNullable<Parameters<typeof api.listOperationalQualityIssues>[0]>;

export function useOperationalQualitySummaryQuery() {
  return useQuery({
    queryKey: ['operational-quality-summary'],
    queryFn: api.getOperationalQualitySummary,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useOperationalQualityFiltersQuery() {
  return useQuery({
    queryKey: ['operational-quality-filters'],
    queryFn: api.getOperationalQualityFilters
  });
}

export function useOperationalQualityIssuesQuery(params: OperationalQualityIssuesQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['operational-quality-issues', params],
    queryFn: () => api.listOperationalQualityIssues(params),
    enabled,
    placeholderData: keepPreviousData,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useOperationalQualityIssueDetailQuery(issueId: string | null) {
  return useQuery({
    queryKey: ['operational-quality-issue-detail', issueId],
    queryFn: () => api.getOperationalQualityIssue(issueId ?? ''),
    enabled: Boolean(issueId)
  });
}

function qualityInvalidationKeys(issueId: string) {
  return [
    ['operational-quality-issue-detail', issueId],
    ['operational-quality-issues'],
    ['operational-quality-summary']
  ] as const;
}

export function useApplyNormalizationOverrideMutation(issueId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: NormalizationOverridePayload) => api.applyNormalizationOverride(issueId, payload),
    onSuccess: () => {
      qualityInvalidationKeys(issueId).forEach((key) => queryClient.invalidateQueries({ queryKey: key }));
    }
  });
}

export function useRevokeNormalizationOverrideMutation(issueId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.revokeNormalizationOverride(issueId),
    onSuccess: () => {
      qualityInvalidationKeys(issueId).forEach((key) => queryClient.invalidateQueries({ queryKey: key }));
    }
  });
}

export function useApplyCorrelationOverrideMutation(issueId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CorrelationOverridePayload) => api.applyCorrelationOverride(issueId, payload),
    onSuccess: () => {
      qualityInvalidationKeys(issueId).forEach((key) => queryClient.invalidateQueries({ queryKey: key }));
    }
  });
}

export function useRevokeCorrelationOverrideMutation(issueId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.revokeCorrelationOverride(issueId),
    onSuccess: () => {
      qualityInvalidationKeys(issueId).forEach((key) => queryClient.invalidateQueries({ queryKey: key }));
    }
  });
}

export function useSoftwareIdentitySearchQuery(query: string, enabled = true) {
  return useQuery({
    queryKey: ['software-identity-search', query],
    queryFn: () => api.searchSoftwareIdentities(query),
    enabled: enabled && query.trim().length >= 2,
    staleTime: 30_000
  });
}

export function useClusterImpactQuery(issueId: string, enabled = true) {
  return useQuery<ClusterImpactResult>({
    queryKey: ['normalization-cluster-impact', issueId],
    queryFn: () => api.getNormalizationImpact(issueId),
    enabled: enabled && issueId.length > 0,
    staleTime: 60_000
  });
}
