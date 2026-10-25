import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';

export type SoftwareIdentitiesQueryParams = Parameters<typeof api.listSoftwareIdentities>[0];

export function useSoftwareIdentitiesQuery(params: SoftwareIdentitiesQueryParams, enabled = true) {
  return useQuery({
    queryKey: ['software-identities', params],
    queryFn: () => api.listSoftwareIdentities(params),
    enabled,
    placeholderData: keepPreviousData
  });
}

export function useSoftwareIdentityFunnelQuery(enabled = true) {
  return useQuery({
    queryKey: ['software-identity-funnel'],
    queryFn: () => api.getSoftwareIdentityFunnel(),
    enabled
  });
}

export function useSoftwareIdentityDetailQuery(softwareIdentityId: string | null, enabled = true) {
  return useQuery({
    queryKey: ['software-identity-detail', softwareIdentityId],
    queryFn: () => api.getSoftwareIdentityDetail(softwareIdentityId ?? ''),
    enabled: enabled && Boolean(softwareIdentityId)
  });
}

export function useSoftwareIdentityMetadataQuery(softwareIdentityId: string | null, enabled = true) {
  return useQuery({
    queryKey: ['software-identity-metadata', softwareIdentityId],
    queryFn: () => api.getSoftwareIdentityMetadata(softwareIdentityId ?? ''),
    enabled: enabled && Boolean(softwareIdentityId)
  });
}

export function useVulnRepoSoftwareAssetsQuery(softwareIdentityId: string | null, enabled = true) {
  return useQuery({
    queryKey: ['vuln-repo-software-assets', softwareIdentityId],
    queryFn: () => api.getVulnRepoSoftwareAssets(softwareIdentityId ?? ''),
    enabled: enabled && Boolean(softwareIdentityId)
  });
}
