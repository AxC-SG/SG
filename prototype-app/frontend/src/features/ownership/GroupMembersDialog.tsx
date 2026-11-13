import React from 'react';
import { useQueries } from '@tanstack/react-query';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { Dialog } from '../../components/Dialog';
import { ownershipErrorText } from './errors';
import {
  DIRECTORY_MIN_QUERY,
  useAddMemberMutation,
  useDirectoryGroupMembersQuery,
  useDirectoryPeopleQuery,
  useRemoveMemberMutation
} from './queries';
import type { DirectoryGroup } from './types';

/** Names are looked up one person at a time, so only this many members are named; the rest are counted. */
const NAMED_MEMBER_LIMIT = 25;

export function GroupMembersDialog({ group, canWrite, onClose }: { group: DirectoryGroup | null; canWrite: boolean; onClose: () => void }) {
  const members = useDirectoryGroupMembersQuery(group?.id ?? null);
  const add = useAddMemberMutation();
  const remove = useRemoveMemberMutation();
  const [query, setQuery] = React.useState('');
  const candidates = useDirectoryPeopleQuery(canWrite ? query : '');
  const searchRef = React.useRef<HTMLInputElement>(null);

  const active = (members.data ?? []).filter((member) => member.status === 'ACTIVE');
  const named = active.slice(0, NAMED_MEMBER_LIMIT);
  const people = useQueries({
    queries: named.map((member) => ({
      queryKey: ['ownership', 'person', member.userId],
      queryFn: () => api.getDirectoryPerson(member.userId)
    }))
  });
  const memberIds = new Set(active.map((member) => member.userId));
  const busy = add.isPending || remove.isPending;
  const failure = add.error ?? remove.error;

  return (
    <Dialog
      isOpen={group !== null}
      title={group ? `Members of ${group.displayName}` : 'Members'}
      onClose={onClose}
      busy={busy}
      busyMessage="Saving the membership…"
      initialFocusRef={canWrite ? searchRef : undefined}
      className="confirm-dialog confirm-dialog-content ownership-dialog"
    >
      {failure && <div className="notice error" role="alert">{ownershipErrorText(failure, 'The membership could not be saved.')}</div>}
      <AsyncSection
        state={members.isPending ? 'pending' : members.isError ? 'error' : active.length === 0 ? 'empty' : 'ready'}
        loadingLabel="Loading members…"
        errorMessage={ownershipErrorText(members.error, 'Members could not be loaded.')}
        onRetry={() => void members.refetch()}
        emptyMessage="This group has no active members."
      >
        <ul className="ownership-alias-list" aria-label="Members">
          {named.map((member, index) => {
            const person = people[index];
            const label = person?.data?.displayName ?? (person?.isError ? 'Name unavailable' : 'Loading…');
            return (
              <li key={member.userId}>
                <span>{label}</span>
                {person?.data?.emailMasked && <span className="panel-caption mono">{person.data.emailMasked}</span>}
                {canWrite && group && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    aria-label={`Remove ${person?.data?.displayName ?? 'member'} from ${group.displayName}`}
                    disabled={busy}
                    onClick={() => remove.mutate({ groupId: group.id, userId: member.userId })}
                  >
                    Remove
                  </button>
                )}
              </li>
            );
          })}
        </ul>
        {active.length > named.length && (
          <p className="panel-caption">and {(active.length - named.length).toLocaleString()} more members (not named here).</p>
        )}
      </AsyncSection>

      {canWrite && group && (
        <div className="ownership-member-add">
          <label className="ownership-search">
            <span>Add a person</span>
            <input ref={searchRef} type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={`At least ${DIRECTORY_MIN_QUERY} letters of a name`} />
          </label>
          {query.trim().length >= DIRECTORY_MIN_QUERY && (
            <ul className="ownership-alias-list" aria-label="Matching people">
              {candidates.isPending && <li className="panel-caption">Searching…</li>}
              {candidates.isError && <li className="panel-caption">People could not be searched.</li>}
              {(candidates.data ?? []).filter((person) => !memberIds.has(person.id)).map((person) => (
                <li key={person.id}>
                  <span>{person.displayName}</span>
                  {person.emailMasked && <span className="panel-caption mono">{person.emailMasked}</span>}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    disabled={busy}
                    onClick={() => add.mutate({ groupId: group.id, userId: person.id }, { onSuccess: () => setQuery('') })}
                  >
                    Add
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <div className="confirm-dialog-actions">
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Close</button>
      </div>
    </Dialog>
  );
}
