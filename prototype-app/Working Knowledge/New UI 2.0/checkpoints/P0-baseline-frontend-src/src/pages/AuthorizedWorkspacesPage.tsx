import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api, setStoredAuthToken } from '../api/client';
import { useActor } from '../features/auth/context';

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
    <div className="page-grid">
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

        {workspacesQuery.isLoading ? <div className="empty-state"><p>Loading authorized workspaces…</p></div> : null}
        {workspacesQuery.isError ? (
          <div className="notice error" role="alert">
            {workspacesQuery.error instanceof Error ? workspacesQuery.error.message : 'Unable to load authorized workspaces'}
          </div>
        ) : null}
        {!workspacesQuery.isLoading && workspaces.length === 0 ? (
          <div className="empty-state"><p>No workspace access has been granted to this identity.</p></div>
        ) : null}
        {workspaces.length > 0 ? (
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
        ) : null}
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
        {pendingInvitations.length === 0 ? (
          <div className="empty-state"><p>No pending support invitations.</p></div>
        ) : (
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
        )}
        {acceptInvitation.isError ? (
          <div className="notice error" role="alert">
            {acceptInvitation.error instanceof Error ? acceptInvitation.error.message : 'Invitation could not be accepted'}
          </div>
        ) : null}
      </section>
    </div>
  );
}
