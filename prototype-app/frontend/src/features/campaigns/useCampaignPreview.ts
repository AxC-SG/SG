import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { CampaignCreateRequest } from './types';

/** Loads the launch preview while the wizard is on its last step; the request is the one create would send. */
export function useCampaignPreview(request: CampaignCreateRequest, enabled: boolean) {
  return useQuery({
    queryKey: ['campaign-preview', request],
    queryFn: () => api.previewCampaign(request),
    enabled,
    staleTime: 0,
    gcTime: 0,
  });
}
