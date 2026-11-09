import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { ownershipErrorText } from './errors';
import { OwnershipFormDialog } from './OwnershipFormDialog';
import { DIRECTORY_MIN_QUERY, useCreatePersonMutation, useDirectoryPeopleQuery, useSetPersonStatusMutation } from './queries';
import type { DirectoryPerson } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'name', label: 'Name', header: 'Name', priority: 'essential', initialSize: 220, minWidth: 160 },
  { id: 'email', label: 'Email', header: 'Email (masked)', initialSize: 220, minWidth: 160 },
  { id: 'employee', label: 'Employee ID', header: 'Employee ID (masked)', initialSize: 160 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 110 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 140 }
];

/**
 * Directory people (plan §6.2). They are ownership evidence and assignee profiles, never Scoutgrid logins. Names and
 * emails are encrypted per tenant, so search is by name prefix only and contact fields are always shown masked.
 */
export function PeoplePanel({ canWrite }: { canWrite: boolean }) {
  const [query, setQuery] = React.useState('');
  const people = useDirectoryPeopleQuery(query);
  const create = useCreatePersonMutation();
  const setStatus = useSetPersonStatusMutation();
  const [creating, setCreating] = React.useState(false);
  const [draft, setDraft] = React.useState({ displayName: '', email: '', employeeId: '' });
  const [statusTarget, setStatusTarget] = React.useState<DirectoryPerson | null>(null);
  const [message, setMessage] = React.useState('');
  const nameRef = React.useRef<HTMLInputElement>(null);
  const searchable = query.trim().length >= DIRECTORY_MIN_QUERY;

  const save = () => {
    create.mutate({
      displayName: draft.displayName.trim(),
      email: draft.email.trim() || undefined,
      employeeId: draft.employeeId.trim() || undefined
    }, {
      onSuccess: (person) => {
        setCreating(false);
        setMessage(`${person.displayName} added. Search by name to find them.`);
      }
    });
  };

  const toggle = () => {
    if (!statusTarget) return;
    const next = statusTarget.status === 'ACTIVE' ? 'INACTIVE' : 'ACTIVE';
    setStatus.mutate({ personId: statusTarget.id, status: next, version: statusTarget.version }, {
      onSuccess: (person) => {
        setStatusTarget(null);
        setMessage(`${person.displayName} ${next === 'INACTIVE' ? 'deactivated' : 'reactivated'}.`);
      }
    });
  };

  const rows = (people.data ?? []).map((person) => ({
    id: person.id,
    cells: {
      name: { content: <strong>{person.displayName}</strong> },
      email: { content: <span className="mono">{person.emailMasked ?? '—'}</span> },
      employee: { content: <span className="mono">{person.employeeIdMasked ?? '—'}</span> },
      status: { content: <span className={`status-pill ${person.status === 'ACTIVE' ? 'status-success' : 'status-unknown'}`}>{person.status === 'ACTIVE' ? 'Active' : 'Inactive'}</span> },
      actions: {
        content: canWrite ? (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => { setStatus.reset(); setStatusTarget(person); }}>
            {person.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
          </button>
        ) : null
      }
    }
  }));

  const state = !searchable ? 'empty' : people.isPending ? 'pending' : people.isError && !people.data ? 'error'
    : rows.length > 0 ? 'ready' : 'filtered-empty';

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <label className="ownership-search">
          <span>Search people by name</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`At least ${DIRECTORY_MIN_QUERY} letters`} />
        </label>
        {canWrite && (
          <button type="button" className="btn btn-primary" onClick={() => { create.reset(); setDraft({ displayName: '', email: '', employeeId: '' }); setCreating(true); }}>
            Add person
          </button>
        )}
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Searching people…"
        errorMessage={ownershipErrorText(people.error, 'People could not be searched.')}
        onRetry={() => void people.refetch()}
        retrying={people.isFetching}
        emptyTitle="Search the directory"
        emptyMessage={`Type at least ${DIRECTORY_MIN_QUERY} letters of a name. People are not listed in bulk because their details are encrypted personal data.`}
        filteredEmptyMessage="No people have a name starting with this text."
        onClearFilters={() => setQuery('')}
        isRefreshing={people.isFetching && !people.isPending}
      >
        <DataTable storageKey="ownership-people" columns={COLUMNS} rows={rows} label="People" />
      </AsyncSection>

      <OwnershipFormDialog
        isOpen={creating}
        title="Add person"
        description="A directory person can be a team member or an assignee profile. It does not create a Scoutgrid login."
        submitLabel="Add person"
        busy={create.isPending}
        busyMessage="Adding the person…"
        error={create.isError ? ownershipErrorText(create.error, 'The person could not be added.') : null}
        submitDisabled={draft.displayName.trim() === ''}
        onSubmit={save}
        onClose={() => setCreating(false)}
        initialFocusRef={nameRef}
      >
        <label>
          <span>Display name</span>
          <input ref={nameRef} required value={draft.displayName} onChange={(event) => setDraft({ ...draft, displayName: event.target.value })} />
        </label>
        <label>
          <span>Email (optional)</span>
          <input type="email" value={draft.email} onChange={(event) => setDraft({ ...draft, email: event.target.value })} />
        </label>
        <label>
          <span>Employee ID (optional)</span>
          <input value={draft.employeeId} onChange={(event) => setDraft({ ...draft, employeeId: event.target.value })} />
        </label>
      </OwnershipFormDialog>

      <ConfirmDialog
        isOpen={statusTarget !== null}
        title={statusTarget?.status === 'ACTIVE' ? `Deactivate ${statusTarget?.displayName}?` : `Reactivate ${statusTarget?.displayName}?`}
        message={
          <>
            {statusTarget?.status === 'ACTIVE'
              ? 'Claims that name this person stop counting. History and memberships are kept.'
              : 'Claims that name this person count again.'}
            {setStatus.isError && <div className="notice error" role="alert">{ownershipErrorText(setStatus.error, 'The person could not be updated.')}</div>}
          </>
        }
        confirmLabel={statusTarget?.status === 'ACTIVE' ? 'Deactivate' : 'Reactivate'}
        busy={setStatus.isPending}
        busyMessage="Updating the person…"
        onConfirm={toggle}
        onCancel={() => setStatusTarget(null)}
      />
    </div>
  );
}
