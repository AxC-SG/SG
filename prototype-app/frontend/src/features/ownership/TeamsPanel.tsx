import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { SegmentedControl } from '../../components/SegmentedControl';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { TeamAliasesDialog } from './TeamAliasesDialog';
import { useCreateTeamMutation, useOwnershipTeamsQuery, useUpdateTeamMutation } from './queries';
import type { OwnershipTeam } from './types';

type StatusFilter = 'ACTIVE' | 'ARCHIVED' | '';

const COLUMNS: DataTableColumn[] = [
  { id: 'name', label: 'Team', header: 'Team', priority: 'essential', initialSize: 240, minWidth: 160 },
  { id: 'ticket', label: 'Ticket assignment group', header: 'Ticket assignment group', initialSize: 220, minWidth: 160 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 120 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 280, minWidth: 240 }
];

type Draft = { name: string; ticketAssignmentGroup: string };

/** Canonical teams (plan §6.7): the only ownership targets. Names and aliases share one tenant-wide namespace. */
export function TeamsPanel({ canWrite }: { canWrite: boolean }) {
  const [query, setQuery] = React.useState('');
  const [status, setStatus] = React.useState<StatusFilter>('ACTIVE');
  const teams = useOwnershipTeamsQuery(query.trim(), status);
  const create = useCreateTeamMutation();
  const update = useUpdateTeamMutation();
  const [editing, setEditing] = React.useState<OwnershipTeam | 'new' | null>(null);
  const [draft, setDraft] = React.useState<Draft>({ name: '', ticketAssignmentGroup: '' });
  const [aliasTeam, setAliasTeam] = React.useState<OwnershipTeam | null>(null);
  const [statusTarget, setStatusTarget] = React.useState<OwnershipTeam | null>(null);
  const [message, setMessage] = React.useState('');
  const nameRef = React.useRef<HTMLInputElement>(null);

  const openCreate = () => {
    create.reset();
    setDraft({ name: '', ticketAssignmentGroup: '' });
    setEditing('new');
  };
  const openEdit = (team: OwnershipTeam) => {
    update.reset();
    setDraft({ name: team.name, ticketAssignmentGroup: team.ticketAssignmentGroup ?? '' });
    setEditing(team);
  };
  const ticketGroup = draft.ticketAssignmentGroup.trim() || null;

  const save = () => {
    if (editing === 'new') {
      create.mutate({ name: draft.name.trim(), ticketAssignmentGroup: ticketGroup }, {
        onSuccess: (team) => { setEditing(null); setMessage(`Team ${team.name} created.`); }
      });
    } else if (editing) {
      update.mutate({
        teamId: editing.id,
        // PATCH replaces parent and ticket group as given; send the current parent to keep it.
        payload: { name: draft.name.trim(), parentTeamId: editing.parentTeamId, ticketAssignmentGroup: ticketGroup, version: editing.version }
      }, { onSuccess: (team) => { setEditing(null); setMessage(`Team ${team.name} saved.`); } });
    }
  };

  const toggleStatus = () => {
    if (!statusTarget) return;
    const next = statusTarget.status === 'ACTIVE' ? 'ARCHIVED' : 'ACTIVE';
    update.mutate({
      teamId: statusTarget.id,
      payload: { parentTeamId: statusTarget.parentTeamId, ticketAssignmentGroup: statusTarget.ticketAssignmentGroup, status: next, version: statusTarget.version }
    }, {
      onSuccess: (team) => { setStatusTarget(null); setMessage(`Team ${team.name} ${next === 'ARCHIVED' ? 'archived' : 'restored'}.`); }
    });
  };

  const rows = (teams.data ?? []).map((team) => ({
    id: team.id,
    cells: {
      name: { content: <strong>{team.name}</strong> },
      ticket: { content: team.ticketAssignmentGroup ?? <span className="panel-caption">Not mapped</span> },
      status: { content: <span className={`status-pill ${team.status === 'ACTIVE' ? 'status-success' : 'status-unknown'}`}>{team.status === 'ACTIVE' ? 'Active' : 'Archived'}</span> },
      actions: {
        content: (
          <div className="button-row">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAliasTeam(team)}>Aliases</button>
            {canWrite && <button type="button" className="btn btn-ghost btn-sm" onClick={() => openEdit(team)}>Edit</button>}
            {canWrite && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => { update.reset(); setStatusTarget(team); }}>
                {team.status === 'ACTIVE' ? 'Archive' : 'Restore'}
              </button>
            )}
          </div>
        )
      }
    }
  }));

  // Active is the default view, not a filter the user chose.
  const filtered = query.trim() !== '' || status !== 'ACTIVE';
  const state = teams.isPending ? 'pending' : teams.isError && !teams.data ? 'error'
    : rows.length > 0 ? 'ready' : filtered ? 'filtered-empty' : 'empty';
  const formError = editing === 'new' ? create.error : update.error;

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <label className="ownership-search">
          <span>Search teams</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name starts with…" />
        </label>
        <SegmentedControl<StatusFilter>
          ariaLabel="Team status"
          value={status}
          onChange={setStatus}
          options={[{ value: 'ACTIVE', label: 'Active' }, { value: 'ARCHIVED', label: 'Archived' }, { value: '', label: 'All' }]}
        />
        {canWrite && <button type="button" className="btn btn-primary" onClick={openCreate}>Create team</button>}
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Loading teams…"
        errorMessage={ownershipErrorText(teams.error, 'Teams could not be loaded.')}
        onRetry={() => void teams.refetch()}
        retrying={teams.isFetching}
        emptyTitle="No teams yet"
        emptyMessage="Teams are the accountable units ownership resolves to. Create one, or import teams from CSV."
        filteredEmptyMessage="No teams match this search."
        onClearFilters={() => { setQuery(''); setStatus('ACTIVE'); }}
        refreshError={teams.isError && teams.data ? 'The latest team list could not be loaded; showing the previous result.' : undefined}
        isRefreshing={teams.isFetching && !teams.isPending}
      >
        <DataTable storageKey="ownership-teams" columns={COLUMNS} rows={rows} label="Teams" />
      </AsyncSection>

      <OwnershipFormDialog
        isOpen={editing !== null}
        title={editing === 'new' ? 'Create team' : 'Edit team'}
        description="Names and aliases share one namespace: a name already used by another team or alias is rejected."
        submitLabel={editing === 'new' ? 'Create team' : 'Save team'}
        busy={create.isPending || update.isPending}
        busyMessage="Saving the team…"
        error={formError ? ownershipErrorText(formError, 'The team could not be saved.') : null}
        submitDisabled={draft.name.trim() === ''}
        onSubmit={save}
        onClose={() => setEditing(null)}
        initialFocusRef={nameRef}
      >
        <label>
          <span>Team name</span>
          <input ref={nameRef} required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} />
        </label>
        <label>
          <span>Ticket assignment group (optional)</span>
          <input
            value={draft.ticketAssignmentGroup}
            onChange={(event) => setDraft({ ...draft, ticketAssignmentGroup: event.target.value })}
            placeholder="External ServiceNow/Jira group"
          />
        </label>
      </OwnershipFormDialog>

      <ConfirmDialog
        isOpen={statusTarget !== null}
        title={statusTarget?.status === 'ACTIVE' ? `Archive ${statusTarget?.name}?` : `Restore ${statusTarget?.name}?`}
        message={
          <>
            {statusTarget?.status === 'ACTIVE'
              ? 'Claims that name an archived team stop counting; affected subjects re-resolve to their next eligible claim or become Unowned, and an Inactive owner review item is raised.'
              : 'Claims that name this team count again and affected subjects re-resolve.'}
            {update.isError && <div className="notice error" role="alert">{ownershipErrorText(update.error, 'The team could not be updated.')}</div>}
          </>
        }
        confirmLabel={statusTarget?.status === 'ACTIVE' ? 'Archive team' : 'Restore team'}
        busy={update.isPending}
        busyMessage="Updating the team…"
        onConfirm={toggleStatus}
        onCancel={() => setStatusTarget(null)}
      />

      <TeamAliasesDialog key={aliasTeam?.id ?? 'closed'} team={aliasTeam} canWrite={canWrite} onClose={() => setAliasTeam(null)} />
    </div>
  );
}
