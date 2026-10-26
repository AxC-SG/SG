import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, getStoredAuthToken } from '../../api/client';
import { getAuthContextQueryKey } from '../auth/queries';
import type {
  ServiceAccountRequest,
  TenantBulkInviteRequest,
  TenantInviteRequest,
  TenantMemberRequest,
  TenantMemberUpdateRequest
} from './types';

const SERVICE_ACCOUNTS_KEY = ['service-accounts'] as const;
const AUDIT_EVENTS_KEY = ['audit-events'] as const;

function membersKey(tenantId: string | null | undefined) {
  return ['tenant-members', tenantId ?? 'unknown'] as const;
}

function invitesKey(tenantId: string | null | undefined) {
  return ['tenant-invites', tenantId ?? 'unknown'] as const;
}

export function useAuthContextQuery() {
  const authToken = getStoredAuthToken().trim() || 'anonymous';
  return useQuery({
    queryKey: getAuthContextQueryKey(authToken),
    queryFn: api.getAuthContext,
    staleTime: 5 * 60 * 1000
  });
}

export function useTenantMembersQuery(tenantId: string | null | undefined) {
  return useQuery({
    queryKey: membersKey(tenantId),
    queryFn: () => api.listTenantMembers(tenantId as string),
    enabled: !!tenantId
  });
}

export function useTenantInvitesQuery(tenantId: string | null | undefined) {
  return useQuery({
    queryKey: invitesKey(tenantId),
    queryFn: () => api.listTenantInvites(tenantId as string),
    enabled: !!tenantId
  });
}

export function useAddTenantMemberMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: TenantMemberRequest) => api.addTenantMember(tenantId as string, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: membersKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useCreateTenantInviteMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: TenantInviteRequest) => api.createTenantInvite(tenantId as string, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: invitesKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useCreateTenantBulkInvitesMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: TenantBulkInviteRequest) => api.createTenantBulkInvites(tenantId as string, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: invitesKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useResendTenantInviteMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (inviteId: string) => api.resendTenantInvite(tenantId as string, inviteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: invitesKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useCancelTenantInviteMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (inviteId: string) => api.cancelTenantInvite(tenantId as string, inviteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: invitesKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useUpdateTenantMemberMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ memberId, payload }: { memberId: string; payload: TenantMemberUpdateRequest }) =>
      api.updateTenantMember(tenantId as string, memberId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: membersKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useDeleteTenantMemberMutation(tenantId: string | null | undefined) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (memberId: string) => api.deleteTenantMember(tenantId as string, memberId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: membersKey(tenantId) });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useServiceAccountsQuery() {
  return useQuery({
    queryKey: SERVICE_ACCOUNTS_KEY,
    queryFn: api.listServiceAccounts
  });
}

export function useCreateServiceAccountMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ServiceAccountRequest) => api.createServiceAccount(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SERVICE_ACCOUNTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useDeleteServiceAccountMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (accountId: string) => api.deleteServiceAccount(accountId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SERVICE_ACCOUNTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useDeactivateServiceAccountMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (accountId: string) => api.deactivateServiceAccount(accountId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SERVICE_ACCOUNTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useReactivateServiceAccountMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (accountId: string) => api.reactivateServiceAccount(accountId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: SERVICE_ACCOUNTS_KEY });
      queryClient.invalidateQueries({ queryKey: AUDIT_EVENTS_KEY });
    }
  });
}

export function useAuditEventsQuery() {
  return useQuery({
    queryKey: AUDIT_EVENTS_KEY,
    queryFn: api.listAuditEvents
  });
}
