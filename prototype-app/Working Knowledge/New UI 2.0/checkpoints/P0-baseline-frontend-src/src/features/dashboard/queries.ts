import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DASHBOARD_REFRESH_INTERVAL_MS } from '../../lib/polling';

export function useDashboardSummaryQuery() {
  return useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: api.getDashboard,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useDashboardCveInventoryMapQuery(limit = 5) {
  return useQuery({
    queryKey: ['dashboard-cve-inventory-map', limit],
    queryFn: () => api.getCveInventoryMap(limit),
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useGridExposureQuery() {
  return useQuery({
    queryKey: ['dashboard-grid-exposure'],
    queryFn: api.getGridExposure,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useExposureSummaryQuery() {
  return useQuery({
    queryKey: ['exposure-summary'],
    queryFn: api.getExposureSummary,
    staleTime: DASHBOARD_REFRESH_INTERVAL_MS,
    gcTime: DASHBOARD_REFRESH_INTERVAL_MS,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
  });
}
