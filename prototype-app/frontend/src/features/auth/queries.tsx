import { useQuery } from '@tanstack/react-query';
import { getStoredAuthToken } from '../../api/client';
import { authApi } from './api';
import { managedBrowserAuthEnabled } from './managedSession';

export const AUTH_CONTEXT_QUERY_ROOT = ['auth-context'] as const;

export function getAuthContextQueryKey(token: string) {
  return [...AUTH_CONTEXT_QUERY_ROOT, token] as const;
}

export function useActorQuery() {
  const authToken = managedBrowserAuthEnabled ? 'managed-session' : getStoredAuthToken().trim() || 'anonymous';
  return useQuery({
    queryKey: getAuthContextQueryKey(authToken),
    queryFn: authApi.getActorContext,
    staleTime: 60 * 1000
  });
}
