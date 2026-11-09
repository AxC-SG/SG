import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { GroupMembersDialog } from './GroupMembersDialog';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { useCreateGroupMutation, useDirectoryGroupsQuery, useSetGroupStatusMutation } from './queries';
import type { DirectoryGroup } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'name', label: 'Group', header: 'Group', priority: 'essential', initialSize: 260, minWidth: 160 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 110 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 220, minWidth: 200 }
];

/**
 * Directory groups (plan §6.2). A group is a collection of people, not an ownership team: it reaches ownership only
 * through an explicit group-to-team mapping, which arrives with the provider groups in Releases 2–3.
 */
export function GroupsPanel({ canWrite }: { canWrite: boolean }) {
  const [query, setQuery] = React.useState('');
  const groups = useDirectoryGroupsQuery(query);
  const create = useCreateGroupMutation();
  const setStatus = useSetGroupStatusMutation();
  const [creating, setCreating] = React.useState(false);
  const [name, setName] = React.useState('');
  const [membersGroup, setMembersGroup] = React.useState<DirectoryGroup | null>(null);
  const [statusTarget, setStatusTarget] = React.useState<DirectoryGroup | null>(null);
  const [message, setMessage] = React.useState('');
  const nameRef = React.useRef<HTMLInputElement>(null);

  const rows = (groups.data ?? []).map((group) => ({
    id: group.id,
    cells: {
      name: { content: <strong>{group.displayName}</strong> },
      status: { content: <span className={`status-pill ${group.status === 'ACTIVE' ? 'status-success' : 'status-unknown'}`}>{group.status === 'ACTIVE' ? 'Active' : 'Inactive'}</span> },
      actions: {
        content: (
          <div className="button-row">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setMembersGroup(group)}>Members</button>
            {canWrite && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setStatus.reset(); setStatusTarget(group); }}>
                {group.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
              </button>
            )}
          </div>
        )
      }
    }
  }));

  const state = groups.isPending ? 'pending' : groups.isError && !groups.data ? 'error'
    : rows.length > 0 ? 'ready' : query.trim() ? 'filtered-empty' : 'empty';

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <label className="ownership-search">
          <span>Search groups</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name starts with…" />
        </label>
        {canWrite && (
          <button type="button" className="btn btn-primary" onClick={() => { create.reset(); setName(''); setCreating(true); }}>
            Create group
          </button>
        )}
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Loading groups…"
        errorMessage={ownershipErrorText(groups.error, 'Groups could not be loaded.')}
        onRetry={() => void groups.refetch()}
        retrying={groups.isFetching}
        emptyTitle="No groups yet"
        emptyMessage="Create a group manually or import groups and memberships from CSV."
        filteredEmptyMessage="No groups match this search."
        onClearFilters={() => setQuery('')}
        refreshError={groups.isError && groups.data ? 'The latest group list could not be loaded; showing the previous result.' : undefined}
        isRefreshing={groups.isFetching && !groups.isPending}
      >
        <DataTable storageKey="ownership-groups" columns={COLUMNS} rows={rows} label="Groups" />
      </AsyncSection>

      <OwnershipFormDialog
        isOpen={creating}
        title="Create group"
        submitLabel="Create group"
        busy={create.isPending}
        busyMessage="Creating the group…"
        error={create.isError ? ownershipErrorText(create.error, 'The group could not be created.') : null}
        submitDisabled={name.trim() === ''}
        onSubmit={() => create.mutate(name.trim(), {
          onSuccess: (group) => { setCreating(false); setMessage(`Group ${group.displayName} created.`); }
        })}
        onClose={() => setCreating(false)}
        initialFocusRef={nameRef}
      >
        <label>
          <span>Group name</span>
          <input ref={nameRef} required value={name} onChange={(event) => setName(event.target.value)} />
        </label>
      </OwnershipFormDialog>

      <ConfirmDialog
        isOpen={statusTarget !== null}
        title={statusTarget?.status === 'ACTIVE' ? `Deactivate ${statusTarget?.displayName}?` : `Reactivate ${statusTarget?.displayName}?`}
        message={
          <>
            Memberships are kept either way.
            {setStatus.isError && <div className="notice error" role="alert">{ownershipErrorText(setStatus.error, 'The group could not be updated.')}</div>}
          </>
        }
        confirmLabel={statusTarget?.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
        busy={setStatus.isPending}
        busyMessage="Updating the group…"
        onConfirm={() => statusTarget && setStatus.mutate(
          { groupId: statusTarget.id, status: statusTarget.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE', version: statusTarget.version },
          { onSuccess: (group) => { setStatusTarget(null); setMessage(`Group ${group.displayName} updated.`); } }
        )}
        onCancel={() => setStatusTarget(null)}
      />

      <GroupMembersDialog key={membersGroup?.id ?? 'closed'} group={membersGroup} canWrite={canWrite} onClose={() => setMembersGroup(null)} />
    </div>
  );
}
