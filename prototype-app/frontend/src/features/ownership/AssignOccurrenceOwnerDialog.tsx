import React from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';
import { occurrenceErrorText } from './occurrenceErrors';
import type { OccurrenceAssignmentPreview, OccurrenceKind } from './occurrenceTypes';
import { useOwnershipTeamsQuery } from './queries';

const MAX_REASON = 500;

function newKey(): string {
  return typeof crypto !== 'undefined' && 'randomUUID' in crypto ? crypto.randomUUID() : `k-${Date.now()}-${Math.random()}`;
}

/**
 * Assigns an owner team to one BOM or CBOM occurrence (Phase 0B §3.7): pick a team and a reason, preview what changes,
 * then confirm. The assignment is a claim on this occurrence only; sibling occurrences of the package keep their owner.
 */
export function AssignOccurrenceOwnerDialog({ kind, rowId, rowLabel, isOpen, onClose, onAssigned }: {
  kind: OccurrenceKind; rowId: string; rowLabel: string; isOpen: boolean; onClose: () => void; onAssigned: () => void;
}) {
  const client = useQueryClient();
  const teams = useOwnershipTeamsQuery('', 'ACTIVE', isOpen);
  const [teamId, setTeamId] = React.useState('');
  const [reason, setReason] = React.useState('');
  const [expiresAt, setExpiresAt] = React.useState('');
  const [preview, setPreview] = React.useState<OccurrenceAssignmentPreview | null>(null);
  const [key] = React.useState(newKey);

  const run = useMutation({ mutationFn: () => api.previewOccurrenceAssignment(kind, rowId, teamId), onSuccess: setPreview });
  const assign = useMutation({
    mutationFn: () => api.assignOccurrenceOwner(kind, rowId, {
      teamId, reason: reason.trim(), expiresAt: expiresAt ? new Date(`${expiresAt}T00:00:00Z`).toISOString() : null,
    }, key),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['inventory-components'] });
      void client.invalidateQueries({ queryKey: ['cbom-inventory'] });
      onAssigned();
      onClose();
    },
  });
  // The preview depends on the chosen team; changing it asks for a new preview.
  const chooseTeam = (next: string) => { setTeamId(next); setPreview(null); run.reset(); assign.reset(); };
  const reasonOk = reason.trim() !== '' && reason.trim().length <= MAX_REASON;
  const error = assign.isError ? assign.error : run.isError ? run.error : null;

  return (
    <Dialog isOpen={isOpen} title="Assign owner" onClose={onClose} busy={assign.isPending} busyMessage="Assigning the owner…">
      <p>Assign an owner team to <strong>{rowLabel}</strong>. This applies to this occurrence only, not every occurrence of this package.</p>
      <label>
        <span>Owner team</span>
        <select value={teamId} onChange={(event) => chooseTeam(event.target.value)}>
          <option value="">Choose a team</option>
          {(teams.data ?? []).map((team) => <option key={team.id} value={team.id}>{team.name}</option>)}
        </select>
      </label>
      <label>
        <span>Reason (required)</span>
        <textarea maxLength={MAX_REASON} value={reason} onChange={(event) => setReason(event.target.value)} />
      </label>
      <label>
        <span>Expires (optional)</span>
        <input type="date" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
      </label>
      {error && <div className="notice error" role="alert">{occurrenceErrorText(error)}</div>}
      {preview && (
        <div className="notice" role="status">
          <strong>Preview</strong>
          <ul>
            <li>{preview.affectedFindings} finding{preview.affectedFindings === 1 ? '' : 's'} on this occurrence would be affected.</li>
            <li>{preview.wouldChange ? 'The effective owner of this occurrence would change.' : 'The effective owner of this occurrence would not change.'}</li>
            {preview.alreadyEffective && <li>This team is already the effective owner.</li>}
            {preview.blockedByDirectClaim && <li>A higher-precedence claim currently sets the owner, so this assignment may not take effect.</li>}
            {preview.conflict && <li>The occurrence currently has a conflict between owners.</li>}
          </ul>
        </div>
      )}
      <div className="button-row">
        <button type="button" className="btn btn-secondary" disabled={assign.isPending} onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-secondary" disabled={!teamId || !reasonOk || run.isPending || assign.isPending} onClick={() => run.mutate()}>
          {run.isPending ? 'Previewing…' : 'Preview'}
        </button>
        <button type="button" className="btn btn-primary" disabled={!preview || preview.alreadyEffective || assign.isPending} onClick={() => assign.mutate()}>
          {assign.isPending ? 'Assigning…' : 'Confirm assignment'}
        </button>
      </div>
    </Dialog>
  );
}
