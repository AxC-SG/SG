import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable, type DataTableColumn } from '../../components/DataTable';
import { ownershipErrorText } from './errors';
import { type MappingChange, MappingChangeDialog } from './MappingChangeDialog';
import { describeMappingChange } from './mappingText';
import { useDismissGroupMappingMutation, useGroupMappingGroupsQuery } from './queries';
import type { ExternalGroupRow } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'group', label: 'ServiceNow group', header: 'ServiceNow group', priority: 'essential', initialSize: 260, minWidth: 180 },
  { id: 'source', label: 'Source', header: 'Source', priority: 'optional', initialSize: 180 },
  { id: 'team', label: 'Mapped team', header: 'Mapped team', priority: 'essential', initialSize: 200, minWidth: 140 },
  { id: 'suggestion', label: 'Suggestion', header: 'Suggestion', initialSize: 200 },
  { id: 'actions', label: 'Actions', header: 'Actions', priority: 'essential', initialSize: 300, minWidth: 220 }
];

/**
 * Group-to-team mappings (Phase 0B contract §1.8). A ServiceNow group reaches a team only through an active mapping an
 * admin confirmed after previewing its impact. The directory sync suggests a team when the group's name exactly equals a
 * team name or alias; a suggestion does nothing until it is confirmed.
 */
export function MappingsPanel({ canMap }: { canMap: boolean }) {
  const [query, setQuery] = React.useState('');
  const groups = useGroupMappingGroupsQuery(query);
  const dismiss = useDismissGroupMappingMutation();
  const [change, setChange] = React.useState<MappingChange | null>(null);
  const [dismissing, setDismissing] = React.useState<ExternalGroupRow | null>(null);
  const [message, setMessage] = React.useState('');

  const rows = (groups.data ?? []).map((group) => ({
    id: group.externalGroupId,
    cells: {
      group: {
        content: (
          <div>
            <strong>{group.displayName}</strong>
            {group.status !== 'ACTIVE' && <> <span className="status-pill status-unknown">Inactive</span></>}
          </div>
        )
      },
      source: { content: group.sourceName },
      team: { content: group.active ? <span>{group.active.teamName}</span> : <span>Not mapped</span> },
      suggestion: { content: group.suggestion ? <span title="Exact name match; not active until confirmed">{group.suggestion.teamName}</span> : '—' },
      actions: {
        content: canMap ? (
          <div className="button-row">
            {group.suggestion && (
              <>
                <button type="button" className="btn btn-ghost btn-sm"
                  onClick={() => setChange({ group, mode: 'map', teamId: group.suggestion?.teamId })}>Review suggestion</button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => { dismiss.reset(); setDismissing(group); }}>Dismiss</button>
              </>
            )}
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setChange({ group, mode: 'map' })}>
              {group.active ? 'Change team' : 'Map to team'}
            </button>
            {group.active && (
              <button type="button" className="btn btn-ghost btn-sm" onClick={() => setChange({ group, mode: 'retire' })}>Retire</button>
            )}
          </div>
        ) : <span>—</span>
      }
    }
  }));

  const state = groups.isPending ? 'pending' : groups.isError && !groups.data ? 'error'
    : rows.length > 0 ? 'ready' : query.trim() ? 'filtered-empty' : 'empty';

  return (
    <div className="ownership-panel">
      <div className="ownership-toolbar">
        <label className="ownership-search">
          <span>Search ServiceNow groups</span>
          <input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name starts with…" />
        </label>
      </div>
      {message && <div className="notice success" role="status">{message}</div>}
      <AsyncSection
        state={state}
        loadingLabel="Loading ServiceNow groups…"
        errorMessage={ownershipErrorText(groups.error, 'ServiceNow groups could not be loaded.')}
        onRetry={() => void groups.refetch()}
        retrying={groups.isFetching}
        emptyTitle="No ServiceNow groups yet"
        emptyMessage="Groups appear here after a ServiceNow identity source has synced."
        filteredEmptyMessage="No groups match this search."
        onClearFilters={() => setQuery('')}
        refreshError={groups.isError && groups.data ? 'The latest groups could not be loaded; showing the previous result.' : undefined}
        isRefreshing={groups.isFetching && !groups.isPending}
      >
        <DataTable storageKey="ownership-group-mappings" columns={COLUMNS} rows={rows} label="Group-to-team mappings" />
      </AsyncSection>

      {change && (
        <MappingChangeDialog
          key={`${change.group.externalGroupId}-${change.mode}-${change.teamId ?? ''}`}
          change={change}
          onClose={() => setChange(null)}
          onDone={(result) => {
            setChange(null);
            setMessage(`${result.mapping.state === 'ACTIVE' ? `Mapped to ${result.mapping.teamName}.` : 'Mapping retired.'} ${describeMappingChange(result)}`);
          }}
        />
      )}

      <ConfirmDialog
        isOpen={dismissing !== null}
        title={`Dismiss the suggestion for ${dismissing?.displayName ?? ''}?`}
        message={
          <>
            The suggested team is not proposed again for this group. You can still map it manually.
            {dismiss.isError && <div className="notice error" role="alert">{ownershipErrorText(dismiss.error, 'The suggestion could not be dismissed.')}</div>}
          </>
        }
        confirmLabel="Dismiss suggestion"
        busy={dismiss.isPending}
        busyMessage="Dismissing the suggestion…"
        onConfirm={() => dismissing?.suggestion && dismiss.mutate(dismissing.suggestion.id, {
          onSuccess: () => { setDismissing(null); setMessage('Suggestion dismissed.'); }
        })}
        onCancel={() => setDismissing(null)}
      />
    </div>
  );
}
