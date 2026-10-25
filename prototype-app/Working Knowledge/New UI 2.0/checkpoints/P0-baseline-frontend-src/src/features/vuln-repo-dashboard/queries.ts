import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DASHBOARD_REFRESH_INTERVAL_MS } from '../../lib/polling';

export function useVulnRepoDashboardQuery(platformScope = false) {
  return useQuery({
    queryKey: ['vuln-repo-dashboard', platformScope ? 'platform' : 'tenant'],
    queryFn: () => platformScope ? api.getPlatformVulnRepoDashboard() : api.getVulnRepoDashboard(),
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
  });
}

export function usePlatformVulnSourceStatsQuery() {
  return useQuery({
    queryKey: ['platform-vuln-source-stats'],
    queryFn: () => api.getPlatformVulnSourceStats(),
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS,
  });
}

export function useVulnIntelSourcesSummaryQuery() {
  return useQuery({
    queryKey: ['vuln-intel-sources-summary'],
    queryFn: () => api.getVulnIntelSourcesSummary(),
  });
}

export function usePlatformVulnIntelDetailQuery(externalId: string) {
  return useQuery({
    queryKey: ['platform-vuln-intel-detail', externalId],
    queryFn: () => api.getPlatformVulnIntelDetail(externalId),
    enabled: !!externalId,
  });
}
