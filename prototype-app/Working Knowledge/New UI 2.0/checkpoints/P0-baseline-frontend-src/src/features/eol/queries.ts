import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { DASHBOARD_REFRESH_INTERVAL_MS } from '../../lib/polling';

export type EolComponentStatusesQueryParams = Parameters<typeof api.getEolComponentStatuses>[0];

export function useEolSummaryQuery(enabled = true) {
  return useQuery({
    queryKey: ['eol-summary'],
    queryFn: api.getEolSummary,
    enabled,
    refetchInterval: DASHBOARD_REFRESH_INTERVAL_MS
  });
}

export function useEolComponentStatusesQuery(params: EolComponentStatusesQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['eol-component-statuses', params],
    queryFn: () => api.getEolComponentStatuses(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useEolProductsQuery(enabled = true) {
  return useQuery({
    queryKey: ['eol-products'],
    queryFn: api.listEolProducts,
    enabled
  });
}

export function useEolReleasesQuery(slug: string | null, enabled = true) {
  return useQuery({
    queryKey: ['eol-releases', slug],
    queryFn: () => api.listEolProductReleases(slug ?? ''),
    enabled: enabled && Boolean(slug)
  });
}

export type EolUnresolvedMappingsQueryParams = { page?: number; size?: number };

export function useEolUnresolvedMappingsQuery(params: EolUnresolvedMappingsQueryParams = {}, enabled = true) {
  return useQuery({
    queryKey: ['eol-unresolved-mappings', params],
    queryFn: () => api.listEolUnresolvedMappings(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useEolSlugSuggestionsQuery(normalizedKey: string | null, enabled = true) {
  return useQuery({
    queryKey: ['eol-slug-suggestions', normalizedKey],
    queryFn: () => api.listEolMappingSuggestions(normalizedKey ?? ''),
    enabled: enabled && Boolean(normalizedKey),
    staleTime: 5 * 60 * 1000
  });
}

export type EolPackageStatusesQueryParams = { filter?: string; page?: number; size?: number };

export function useEolPackageStatusesQuery(params: EolPackageStatusesQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['eol-package-statuses', params],
    queryFn: () => api.getEolPackageStatuses(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export type EolPackageAssetsQueryParams = {
  packageName: string;
  ecosystem?: string;
  page?: number;
  size?: number;
};

export function useEolPackageAssetsQuery(params: EolPackageAssetsQueryParams | null, enabled = true) {
  return useQuery({
    queryKey: ['eol-package-assets', params],
    queryFn: () => api.getEolPackageAssets(params!),
    enabled: enabled && params !== null,
    placeholderData: keepPreviousData
  });
}
