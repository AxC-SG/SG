import { keepPreviousData, useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { FindingQueueDefinition, FindingsFilterModel } from './types';

export type FindingsQueryParams = Parameters<typeof api.listFindings>[0];

export function useFindingFiltersQuery() {
  return useQuery({
    queryKey: ['finding-filters'],
    queryFn: api.listFindingFilters
  });
}

export function useFindingsQuery(params: FindingsQueryParams) {
  return useQuery({
    queryKey: ['findings', params],
    queryFn: () => api.listFindings(params),
    placeholderData: keepPreviousData
  });
}

export function useFindingSummaryQuery(params: FindingsFilterModel) {
  return useQuery({
    queryKey: ['findings-summary', params],
    queryFn: () => api.getFindingSummary(params)
  });
}

export function useFindingDistributionsQuery(params: FindingsFilterModel) {
  return useQuery({
    queryKey: ['findings-distributions', params],
    queryFn: () => api.getFindingDistributions(params)
  });
}

export function useFindingBacklogHealthQuery(params: FindingsFilterModel) {
  return useQuery({
    queryKey: ['findings-backlog-health', params],
    queryFn: () => api.getFindingBacklogHealth(params)
  });
}

export function useFindingProjectionStatusQuery() {
  return useQuery({
    queryKey: ['findings-projection-status'],
    queryFn: api.getFindingProjectionStatus
  });
}

export function useFindingQueuesQuery() {
  return useQuery<FindingQueueDefinition[]>({
    queryKey: ['finding-queues'],
    queryFn: api.listFindingQueues
  });
}

export function useRebuildFindingProjectionMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: api.rebuildFindingProjection,
    onSuccess: () => {
      [
        ['findings-projection-status'],
        ['findings'],
        ['findings-summary'],
        ['findings-distributions'],
        ['findings-backlog-health'],
      ].forEach((queryKey) => queryClient.invalidateQueries({ queryKey }));
    }
  });
}

export function useFindingGroupsQueries(fields: string[], params: FindingsFilterModel) {
  return useQueries({ queries: fields.map(field => ({
    queryKey: ['finding-groups', field, params],
    queryFn: () => api.getFindingGroups(field, params),
  })) });
}
