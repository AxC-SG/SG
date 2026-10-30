import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api, setStoredAuthToken } from '../api/client';
import { useActor } from '../features/auth/context';
import { AsyncSection, type AsyncSectionState } from '../components/AsyncSection';

function listState(query: { isPending: boolean; isError: boolean; data?: unknown[] }, count: number): AsyncSectionState {
  if (query.isPending) return 'pending';
  if (query.isError && !query.data) return 'error';
  return count === 0 ? 'empty' : 'ready';
}

function errorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function accessLabel(mode: string | null | undefined, role: string): string {
  if (mode === 'DIRECT_PLAYGROUND_MEMBERSHIP') return 'Playground administrator';
  if (mode === 'SUPPORT_READ_ONLY') return 'Support · read only';
  if (mode === 'SUPPORT_WRITE_ENABLED') return 'Support · write enabled';
  return role.replace(/_/g, ' ');
}

export function AuthorizedWorkspacesPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const workspacesQuery = useQuery({
    queryKey: ['authorized-workspaces'],
    queryFn: api.listAuthorizedWorkspaces
  });
  const invitationsQuery = useQuery({
    queryKey: ['invited-support-grants'],
    queryFn: api.listInvitedSupportGrants
  });
  const enterWorkspace = useMutation({
    mutationFn: api.selectTenantContext,
    onSuccess: (response) => {
      setStoredAuthToken(response.token);
      queryClient.clear();
      navigate('/exposure', { replace: true });
    }
  });
  const returnToPlatform = useMutation({
    mutationFn: api.clearTenantContext,
    onSuccess: (response) => {
      setStoredAuthToken(response.token);
      queryClient.clear();
      navigate('/authorized-workspaces', { replace: true });
    }
  });
  const acceptInvitation = useMutation({
    mutationFn: api.acceptSupportGrant,
    onSuccess: async () => {
      await Promise.all([
        workspacesQuery.refetch(),
        invitationsQuery.refetch()
      ]);
    }
  });

  const workspaces = workspacesQuery.data ?? [];
  const pendingInvitations = (invitationsQuery.data ?? []).filter((grant) => grant.status === 'PENDING');

  return (
    <div className="page-grid ui2-governance-family">
      <section className="panel">
        <div className="section-title-row">
          <div>
            <div className="eyebrow">Tenant-authorized access</div>
            <h2>Authorized Workspaces</h2>
          </div>
          {actor?.actingAsPlatformOwner ? (
            <button
              type="button"
              className="btn btn-secondary"
              disabled={returnToPlatform.isPending}
              onClick={() => returnToPlatform.mutate()}
            >
              {returnToPlatform.isPending ? 'Returning…' : 'Return to platform scope'}
            </button>
          ) : null}
        </div>
        <p className="text-muted">
          Only workspaces where you hold a tenant membership or an accepted support grant are shown here.
        </p>

        {/* A failed list is not "no access granted". */}
        <AsyncSection
          state={listState(workspacesQuery, workspaces.length)}
          loadingLabel="Loading authorized workspaces…"
          emptyMessage="No workspace access has been granted to this identity."
          errorMessage={errorText(workspacesQuery.error, 'Unable to load authorized workspaces')}
          onRetry={() => void workspacesQuery.refetch()}
          retrying={workspacesQuery.isFetching}
        >
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Workspace</th><th>Access</th><th>Expires</th><th>Action</th></tr></thead>
              <tbody>
                {workspaces.map((workspace) => {
                  const playground = workspace.accessMode === 'DIRECT_PLAYGROUND_MEMBERSHIP';
                  const active = actor?.actingAsPlatformOwner && actor.tenantId === workspace.id;
                  return (
                    <tr key={`${workspace.id}:${workspace.accessReferenceId ?? workspace.accessMode}`}>
                      <td>
                        <strong>{playground ? 'Open Playground' : workspace.name}</strong>
                        <div><small>{workspace.slug ?? ''}</small></div>
                      </td>
                      <td>{accessLabel(workspace.accessMode, workspace.role)}</td>
                      <td>{workspace.expiresAt ? new Date(workspace.expiresAt).toLocaleString() : 'No expiry'}</td>
                      <td>
                        {active ? (
                          <span className="status-badge">Current workspace</span>
                        ) : (
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            disabled={enterWorkspace.isPending}
                            onClick={() => enterWorkspace.mutate(workspace.id)}
                          >
                            {enterWorkspace.isPending && enterWorkspace.variables === workspace.id
                              ? 'Opening…'
                              : playground ? 'Open Playground' : 'Open workspace'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </AsyncSection>
        {(enterWorkspace.isError || returnToPlatform.isError) ? (
          <div className="notice error" role="alert">
            {enterWorkspace.error instanceof Error
              ? enterWorkspace.error.message
              : returnToPlatform.error instanceof Error
                ? returnToPlatform.error.message
                : 'Workspace context could not be changed'}
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="section-title-row"><h3>Pending support invitations</h3></div>
        <AsyncSection
          state={listState(invitationsQuery, pendingInvitations.length)}
          loadingLabel="Loading support invitations…"
          emptyMessage="No pending support invitations."
          errorMessage={errorText(invitationsQuery.error, 'Support invitations could not be loaded')}
          onRetry={() => void invitationsQuery.refetch()}
          retrying={invitationsQuery.isFetching}
        >
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Workspace</th><th>Mode</th><th>Reason</th><th>Expires</th><th>Action</th></tr></thead>
              <tbody>
                {pendingInvitations.map((grant) => (
                  <tr key={grant.id}>
                    <td>{grant.tenantName}</td>
                    <td>{accessLabel(grant.accessMode === 'WRITE_ENABLED' ? 'SUPPORT_WRITE_ENABLED' : 'SUPPORT_READ_ONLY', '')}</td>
                    <td>{grant.reason}</td>
                    <td>{grant.expiresAt ? new Date(grant.expiresAt).toLocaleString() : 'No expiry'}</td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-primary btn-sm"
                        disabled={acceptInvitation.isPending}
                        onClick={() => acceptInvitation.mutate(grant.id)}
                      >
                        {acceptInvitation.isPending && acceptInvitation.variables === grant.id ? 'Accepting…' : 'Accept'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncSection>
        {acceptInvitation.isError ? (
          <div className="notice error" role="alert">
            {acceptInvitation.error instanceof Error ? acceptInvitation.error.message : 'Invitation could not be accepted'}
          </div>
        ) : null}
      </section>
    </div>
  );
}
