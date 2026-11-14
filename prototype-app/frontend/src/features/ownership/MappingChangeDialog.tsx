import { useMutation } from '@tanstack/react-query';
import React from 'react';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';
import { ownershipErrorText } from './errors';
import { useActivateGroupMappingMutation, useOwnershipTeamsQuery, useRetireGroupMappingMutation } from './queries';
import type { ExternalGroupRow, GroupMappingChange, GroupMappingImpact } from './types';

export type MappingChange = { group: ExternalGroupRow; mode: 'map' | 'retire'; teamId?: string };

type Props = {
  change: MappingChange | null;
  onClose: () => void;
  onDone: (result: GroupMappingChange) => void;
};

/**
 * Map an external group to a team, or retire its mapping (Phase 0B contract §1.8). The admin previews the impact first:
 * the CMDB CIs whose support group is this group, their subjects and their open findings. The change is sent with that
 * preview's token, so a change made by someone else in between is refused rather than overwritten.
 */
export function MappingChangeDialog({ change, onClose, onDone }: Props) {
  const teams = useOwnershipTeamsQuery('', 'ACTIVE', change?.mode === 'map');
  const preview = useMutation<GroupMappingImpact, Error, { externalGroupId: string; teamId: string | null }>({
    mutationFn: ({ externalGroupId, teamId }) => api.previewGroupMapping(externalGroupId, teamId)
  });
  const activate = useActivateGroupMappingMutation();
  const retire = useRetireGroupMappingMutation();
  const [teamId, setTeamId] = React.useState(change?.teamId ?? '');
  const [reason, setReason] = React.useState('');
  const [confirmLarge, setConfirmLarge] = React.useState(false);

  if (!change) return null;
  const mapping = change.mode === 'map';
  const impact = preview.data;
  const save = mapping ? activate : retire;
  const busy = preview.isPending || save.isPending;
  const targetTeam = mapping ? teamId || null : null;
  const canPreview = !mapping || Boolean(teamId);
  const canConfirm = Boolean(impact) && (!impact?.largeChange || confirmLarge);

  const pickTeam = (next: string) => {
    setTeamId(next);
    preview.reset(); // an impact belongs to one target
    save.reset();
  };

  const confirm = () => {
    if (!impact) return;
    const done = { onSuccess: onDone };
    if (mapping) {
      activate.mutate({ externalGroupId: change.group.externalGroupId, teamId, reason: reason.trim() || undefined,
        previewToken: impact.previewToken, confirmLarge }, done);
    } else if (change.group.active) {
      retire.mutate({ mappingId: change.group.active.id, reason: reason.trim() || undefined, previewToken: impact.previewToken, confirmLarge }, done);
    }
  };

  return (
    <Dialog
      isOpen
      title={mapping ? `Map ${change.group.displayName} to a team` : `Retire the mapping for ${change.group.displayName}?`}
      onClose={onClose}
      busy={busy}
      busyMessage={preview.isPending ? 'Calculating the impact…' : 'Saving the mapping…'}
      className="confirm-dialog confirm-dialog-content ownership-dialog"
    >
      <div className="ownership-dialog-form">
        <p className="confirm-dialog-message">
          {mapping
            ? 'CMDB CIs whose support group is this ServiceNow group will be owned by the chosen team. Groups never become teams by themselves.'
            : 'CIs that named this group fall back to team name or alias matching. Their current owner stays until the value maps, expires or is cleared.'}
        </p>
        <div className="form-grid">
          {mapping && (
            <label>
              <span>Team</span>
              <select value={teamId} onChange={(event) => pickTeam(event.target.value)} disabled={busy}>
                <option value="">Choose a team…</option>
                {(teams.data ?? []).map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
              </select>
            </label>
          )}
          <label>
            <span>Reason (optional)</span>
            <input value={reason} maxLength={500} onChange={(event) => setReason(event.target.value)} disabled={busy} />
          </label>
        </div>
        {teams.isError && <div className="notice error" role="alert">{ownershipErrorText(teams.error, 'Teams could not be loaded.')}</div>}
        {preview.isError && <div className="notice error" role="alert">{ownershipErrorText(preview.error, 'The impact could not be calculated.')}</div>}
        {impact && (
          <section aria-label="Impact">
            {!impact.sameInstance && (
              <div className="notice warning" role="status">
                This group's source is not on the CMDB connector's instance, so no CI can reference it.
              </div>
            )}
            <dl className="ownership-counts">
              <div><dt>CMDB CIs</dt><dd>{impact.affectedCis.toLocaleString()}</dd></div>
              <div><dt>Subjects</dt><dd>{impact.affectedSubjects.toLocaleString()}</dd></div>
              <div><dt>Open findings</dt><dd>{impact.openFindings.toLocaleString()}</dd></div>
            </dl>
            {impact.largeChange && (
              <label>
                <input type="checkbox" checked={confirmLarge} onChange={(event) => setConfirmLarge(event.target.checked)} />
                <span>I confirm this change affects more than 10,000 CIs; the next CMDB sync applies it.</span>
              </label>
            )}
          </section>
        )}
        {save.isError && <div className="notice error" role="alert">{ownershipErrorText(save.error, 'The mapping could not be saved.')}</div>}
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Cancel</button>
          {!impact ? (
            <button type="button" className="btn btn-primary" disabled={busy || !canPreview}
              onClick={() => preview.mutate({ externalGroupId: change.group.externalGroupId, teamId: targetTeam })}>
              Preview impact
            </button>
          ) : (
            <button type="button" className="btn btn-primary" disabled={busy || !canConfirm} onClick={confirm}>
              {mapping ? 'Confirm mapping' : 'Retire mapping'}
            </button>
          )}
        </div>
      </div>
    </Dialog>
  );
}
