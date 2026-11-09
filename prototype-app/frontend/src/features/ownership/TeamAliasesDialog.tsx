import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { Dialog } from '../../components/Dialog';
import { ownershipErrorText } from './errors';
import { useAddAliasMutation, useOwnershipTeamAliasesQuery, useRemoveAliasMutation } from './queries';
import type { OwnershipTeam } from './types';

// Source kinds the team_alias table accepts. Provenance only: every alias shares the tenant-wide team namespace.
const SOURCE_KINDS = [
  ['SERVICENOW', 'ServiceNow CMDB value'],
  ['AWS', 'AWS account field or tag'],
  ['GCP', 'GCP project field or label'],
  ['MANUAL', 'Other / manual']
] as const;

/**
 * Exact source values (support group, owner tag) that resolve to this team (plan §6.7). There is no fuzzy matching:
 * an unmapped value stays in review until an alias for exactly that value exists. The parent keys this dialog by team,
 * so opening another team starts from a clean draft and mutation state.
 */
export function TeamAliasesDialog({ team, canWrite, onClose }: { team: OwnershipTeam | null; canWrite: boolean; onClose: () => void }) {
  const aliases = useOwnershipTeamAliasesQuery(team?.id ?? null);
  const add = useAddAliasMutation();
  const remove = useRemoveAliasMutation();
  const [alias, setAlias] = React.useState('');
  const [sourceKind, setSourceKind] = React.useState<string>('SERVICENOW');
  const inputRef = React.useRef<HTMLInputElement>(null);
  const busy = add.isPending || remove.isPending;

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    if (!team || alias.trim() === '' || busy) return;
    add.mutate({ teamId: team.id, alias: alias.trim(), sourceKind }, { onSuccess: () => setAlias('') });
  };

  const items = aliases.data ?? [];
  const failure = add.error ?? remove.error;

  return (
    <Dialog
      isOpen={team !== null}
      title={team ? `Aliases for ${team.name}` : 'Aliases'}
      onClose={onClose}
      busy={busy}
      busyMessage="Saving the alias…"
      initialFocusRef={canWrite ? inputRef : undefined}
      className="confirm-dialog confirm-dialog-content ownership-dialog"
    >
      <div className="confirm-dialog-message">
        A source value matching an alias exactly (ignoring case) is attributed to this team. Changing an alias re-resolves
        the subjects that carry that value.
      </div>
      {failure && <div className="notice error" role="alert">{ownershipErrorText(failure, 'The alias could not be saved.')}</div>}
      <AsyncSection
        state={aliases.isPending ? 'pending' : aliases.isError ? 'error' : items.length === 0 ? 'empty' : 'ready'}
        loadingLabel="Loading aliases…"
        errorMessage={ownershipErrorText(aliases.error, 'Aliases could not be loaded.')}
        onRetry={() => void aliases.refetch()}
        emptyMessage="No aliases yet. Source values must match the team name exactly until an alias is added."
      >
        <ul className="ownership-alias-list">
          {items.map((item) => (
            <li key={item.id}>
              <span className="mono">{item.alias}</span>
              <span className="panel-caption">{item.sourceKind}</span>
              {canWrite && (
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  aria-label={`Remove alias ${item.alias}`}
                  disabled={busy}
                  onClick={() => team && remove.mutate({ teamId: team.id, aliasId: item.id })}
                >
                  Remove
                </button>
              )}
            </li>
          ))}
        </ul>
      </AsyncSection>
      {canWrite && (
        <form className="ownership-dialog-form" onSubmit={submit}>
          <div className="form-grid">
            <label>
              <span>New alias</span>
              <input ref={inputRef} value={alias} onChange={(event) => setAlias(event.target.value)} placeholder="e.g. SN-PAYMENTS-OPS" />
            </label>
            <label>
              <span>Source</span>
              <select value={sourceKind} onChange={(event) => setSourceKind(event.target.value)}>
                {SOURCE_KINDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
          </div>
          <div className="confirm-dialog-actions">
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Close</button>
            <button type="submit" className="btn btn-primary" disabled={busy || alias.trim() === ''}>
              {add.isPending ? 'Adding…' : 'Add alias'}
            </button>
          </div>
        </form>
      )}
      {!canWrite && (
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      )}
    </Dialog>
  );
}
