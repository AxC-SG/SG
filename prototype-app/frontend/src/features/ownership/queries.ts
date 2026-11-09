import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { DirectoryPersonCreate, OwnershipAuthorityState, OwnershipTeamRequest } from './types';

// One key root so a write can refresh everything it may affect (teams feed review items and coverage).
export const ownershipKeys = {
  all: ['ownership'] as const,
  coverage: (consumer: 'INVENTORY' | 'FINDINGS') => ['ownership', 'coverage', consumer] as const,
  teams: (q: string, status: string) => ['ownership', 'teams', q, status] as const,
  aliases: (teamId: string) => ['ownership', 'aliases', teamId] as const,
  people: (q: string) => ['ownership', 'people', q] as const,
  groups: (q: string) => ['ownership', 'groups', q] as const,
  members: (groupId: string) => ['ownership', 'members', groupId] as const,
  review: (state: string, type: string) => ['ownership', 'review', state, type] as const,
  encryption: ['ownership', 'encryption'] as const,
  qualification: ['ownership', 'qualification', 'CORE'] as const
};

/** Shortest people/group search the server accepts (DirectoryService MIN_PREFIX). */
export const DIRECTORY_MIN_QUERY = 2;

export function useOwnershipCoverageQuery(consumer: 'INVENTORY' | 'FINDINGS') {
  return useQuery({ queryKey: ownershipKeys.coverage(consumer), queryFn: () => api.getOwnershipCoverage(consumer) });
}

export function useOwnershipTeamsQuery(q: string, status: 'ACTIVE' | 'ARCHIVED' | '') {
  return useQuery({
    queryKey: ownershipKeys.teams(q, status),
    queryFn: () => api.listOwnershipTeams({ q: q || undefined, status: status || undefined, limit: 200 }),
    placeholderData: keepPreviousData
  });
}

export function useOwnershipTeamAliasesQuery(teamId: string | null) {
  return useQuery({
    queryKey: ownershipKeys.aliases(teamId ?? ''),
    queryFn: () => api.listOwnershipTeamAliases(teamId ?? ''),
    enabled: Boolean(teamId)
  });
}

export function useDirectoryPeopleQuery(q: string) {
  const trimmed = q.trim();
  return useQuery({
    queryKey: ownershipKeys.people(trimmed),
    queryFn: () => api.searchDirectoryPeople(trimmed, 50),
    enabled: trimmed.length >= DIRECTORY_MIN_QUERY,
    placeholderData: keepPreviousData
  });
}

export function useDirectoryGroupsQuery(q: string) {
  const trimmed = q.trim();
  return useQuery({
    queryKey: ownershipKeys.groups(trimmed),
    queryFn: () => api.searchDirectoryGroups(trimmed, 50),
    placeholderData: keepPreviousData
  });
}

export function useDirectoryGroupMembersQuery(groupId: string | null) {
  return useQuery({
    queryKey: ownershipKeys.members(groupId ?? ''),
    queryFn: () => api.listDirectoryGroupMembers(groupId ?? ''),
    enabled: Boolean(groupId)
  });
}

export function useOwnershipReviewQuery(state: 'OPEN' | 'RESOLVED' | 'DISMISSED', type: string) {
  return useQuery({
    queryKey: ownershipKeys.review(state, type),
    queryFn: () => api.listOwnershipReviewItems({ state, type: type || undefined, limit: 100 }),
    placeholderData: keepPreviousData
  });
}

export function useOwnershipEncryptionQuery(enabled: boolean) {
  return useQuery({ queryKey: ownershipKeys.encryption, queryFn: api.getOwnershipEncryption, enabled });
}

export function useOwnershipQualificationQuery(enabled: boolean) {
  return useQuery({ queryKey: ownershipKeys.qualification, queryFn: () => api.getOwnershipQualification('CORE'), enabled });
}

function useOwnershipMutation<TArgs, TResult>(fn: (args: TArgs) => Promise<TResult>) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => client.invalidateQueries({ queryKey: ownershipKeys.all })
  });
}

export function useCreateTeamMutation() {
  return useOwnershipMutation((payload: OwnershipTeamRequest) => api.createOwnershipTeam(payload));
}

export function useUpdateTeamMutation() {
  return useOwnershipMutation(({ teamId, payload }: { teamId: string; payload: OwnershipTeamRequest }) =>
    api.updateOwnershipTeam(teamId, payload));
}

export function useAddAliasMutation() {
  return useOwnershipMutation(({ teamId, alias, sourceKind }: { teamId: string; alias: string; sourceKind: string }) =>
    api.addOwnershipTeamAlias(teamId, alias, sourceKind));
}

export function useRemoveAliasMutation() {
  return useOwnershipMutation(({ teamId, aliasId }: { teamId: string; aliasId: string }) => api.removeOwnershipTeamAlias(teamId, aliasId));
}

export function useCreatePersonMutation() {
  return useOwnershipMutation((payload: DirectoryPersonCreate) => api.createDirectoryPerson(payload));
}

export function useSetPersonStatusMutation() {
  return useOwnershipMutation(({ personId, status, version }: { personId: string; status: 'ACTIVE' | 'INACTIVE'; version: number }) =>
    api.updateDirectoryPerson(personId, { status, version }));
}

export function useCreateGroupMutation() {
  return useOwnershipMutation((displayName: string) => api.createDirectoryGroup(displayName));
}

export function useSetGroupStatusMutation() {
  return useOwnershipMutation(({ groupId, status, version }: { groupId: string; status: 'ACTIVE' | 'INACTIVE'; version: number }) =>
    api.updateDirectoryGroup(groupId, { status, version }));
}

export function useAddMemberMutation() {
  return useOwnershipMutation(({ groupId, userId }: { groupId: string; userId: string }) => api.addDirectoryGroupMember(groupId, userId));
}

export function useRemoveMemberMutation() {
  return useOwnershipMutation(({ groupId, userId }: { groupId: string; userId: string }) => api.removeDirectoryGroupMember(groupId, userId));
}

export function useCloseReviewItemMutation() {
  return useOwnershipMutation(({ itemId, state, note }: { itemId: string; state: 'RESOLVED' | 'DISMISSED'; note?: string }) =>
    api.closeOwnershipReviewItem(itemId, state, note));
}

export function useProvisionEncryptionMutation() {
  return useOwnershipMutation<void, Awaited<ReturnType<typeof api.provisionOwnershipEncryption>>>(() => api.provisionOwnershipEncryption());
}

export function useAuthorityTransitionMutation() {
  return useOwnershipMutation(({ state, reportHash }: { state: OwnershipAuthorityState; reportHash?: string }) =>
    api.transitionOwnershipAuthority('CORE', state, reportHash));
}
