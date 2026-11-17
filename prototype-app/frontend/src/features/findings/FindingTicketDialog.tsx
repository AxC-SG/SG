import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, ticketRoutingChangedPreview } from '../../api/client';
import { Dialog } from '../../components/Dialog';
import type { TicketPreview, TicketPreviewRequest } from '../connect/types';
import { MAX_OVERRIDE_REASON, routingSourceLabel } from './ticketRouting';

type RoutingChoice = { selectedAssignmentGroup?: string; assignmentGroupOverride?: string; overrideReason?: string };

/**
 * Ticket confirmation for one finding (Phase 0B §4.9). With canonical routing the owner team and the external
 * assignment group are shown separately, create sends the preview's hash, and a 409 TICKET_ROUTING_CHANGED replaces
 * the preview and asks for a new confirmation instead of retrying. Without canonical routing today's behaviour holds.
 */
export function FindingTicketDialog({ findingId, isOpen, onClose, onCreated }: {
  findingId: string; isOpen: boolean; onClose: () => void; onCreated: () => void;
}) {
  const client = useQueryClient();
  const [choice, setChoice] = React.useState<RoutingChoice>({});
  const [group, setGroup] = React.useState('');
  const [override, setOverride] = React.useState(false);
  const [overrideGroup, setOverrideGroup] = React.useState('');
  const [reason, setReason] = React.useState('');
  const [fresh, setFresh] = React.useState<TicketPreview | null>(null);

  const request: TicketPreviewRequest = { findingIds: [findingId], ...choice };
  const previewQuery = useQuery({
    queryKey: ['ticket-preview', findingId, choice],
    queryFn: () => api.previewTickets(request),
    enabled: isOpen,
    staleTime: 0,
    gcTime: 0,
  });
  const preview = fresh ?? previewQuery.data ?? null;
  const create = useMutation({
    mutationFn: () => api.createFindingTicket(findingId, preview?.canonical
      ? { routingHash: preview.routingHash ?? undefined, ...choice }
      : {}),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['finding-ticket-attempts', findingId] });
      onCreated();
      onClose();
    },
    onError: (error) => {
      const changed = ticketRoutingChangedPreview(error);
      if (changed) setFresh(changed);
    },
  });
  const routingChanged = create.isError && ticketRoutingChangedPreview(create.error) !== null;

  const applyChoice = (next: RoutingChoice) => { setFresh(null); create.reset(); setChoice(next); };
  const reasonTrimmed = reason.trim();
  const overrideInvalid = override && (overrideGroup.trim() === '' || reasonTrimmed === '' || reasonTrimmed.length > MAX_OVERRIDE_REASON);
  const overrideApplied = !override || (choice.assignmentGroupOverride === overrideGroup.trim() && choice.overrideReason === reasonTrimmed);
  const canCreate = preview !== null && !create.isPending && !overrideInvalid && overrideApplied
    && (!preview.canonical || (!!preview.routingHash && preview.batches.length > 0));

  return (
    <Dialog isOpen={isOpen} title="Create ticket" onClose={onClose} busy={create.isPending} busyMessage="Creating the ticket…">
      {previewQuery.isPending && fresh === null && <p className="muted" role="status">Checking where this ticket would go…</p>}
      {previewQuery.isError && fresh === null && <div className="notice error" role="alert">The routing preview could not be loaded.</div>}
      {routingChanged && (
        <div className="notice warning" role="alert">Ownership or routing changed since this preview. Review the updated routing below and confirm again.</div>
      )}
      {create.isError && !routingChanged && <div className="notice error" role="alert">{create.error instanceof Error ? create.error.message : 'The ticket could not be created.'}</div>}
      {preview && !preview.canonical && (
        <p>Ticket routing for this finding follows the existing behaviour. The ticket goes to the active ticketing system with its usual assignment group.</p>
      )}
      {preview?.canonical && (
        <>
          {preview.batches.map((batch) => (
            <dl key={`${batch.bucket}:${batch.teamId ?? ''}`} className="ticket-routing-batch">
              <dt>Owner team</dt><dd>{batch.bucket === 'UNOWNED' ? 'Unowned' : batch.teamName ?? 'Team'}</dd>
              <dt>Assignment group</dt><dd>{batch.assignmentGroup ?? 'None'}</dd>
              <dt>Routing source</dt><dd>{routingSourceLabel(batch.routingSource)}</dd>
            </dl>
          ))}
          {preview.unroutable.length > 0 && (
            <div className="notice warning" role="status">
              <strong>Cannot be routed automatically</strong>
              <ul>{preview.unroutable.map((item) => <li key={item.findingId}>{item.displayId ?? item.findingId}: {item.reason}</li>)}</ul>
            </div>
          )}
          {preview.excluded.length > 0 && (
            <ul className="panel-caption">{preview.excluded.map((item) => <li key={item.findingId}>Excluded {item.displayId ?? item.findingId}: {item.reason}</li>)}</ul>
          )}
          {preview.batches.length === 0 && (
            <div className="ticket-select-group">
              <label><span>Assignment group</span><input value={group} onChange={(event) => setGroup(event.target.value)} /></label>
              <button type="button" className="btn btn-secondary btn-sm" disabled={group.trim() === ''}
                onClick={() => applyChoice({ selectedAssignmentGroup: group.trim() })}>Use this group</button>
            </div>
          )}
          <label>
            <input type="checkbox" checked={override} onChange={(event) => {
              setOverride(event.target.checked);
              if (!event.target.checked) applyChoice({ selectedAssignmentGroup: choice.selectedAssignmentGroup });
            }} />
            <span>Override group</span>
          </label>
          {override && (
            <div className="ticket-override">
              <label><span>Override assignment group</span><input value={overrideGroup} onChange={(event) => setOverrideGroup(event.target.value)} /></label>
              <label>
                <span>Reason for the override</span>
                <textarea required maxLength={MAX_OVERRIDE_REASON} value={reason} onChange={(event) => setReason(event.target.value)} />
              </label>
              <p className="panel-caption">{reasonTrimmed.length} of {MAX_OVERRIDE_REASON} characters. The override and reason are recorded on the ticket attempt.</p>
              <button type="button" className="btn btn-secondary btn-sm" disabled={overrideInvalid}
                onClick={() => applyChoice({ ...choice, assignmentGroupOverride: overrideGroup.trim(), overrideReason: reasonTrimmed })}>Apply override</button>
              {!overrideApplied && !overrideInvalid && <p className="panel-caption">Apply the override to see the updated routing.</p>}
            </div>
          )}
        </>
      )}
      <div className="button-row">
        <button type="button" className="btn btn-secondary" disabled={create.isPending} onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={!canCreate} onClick={() => create.mutate()}>
          {create.isPending ? 'Creating…' : routingChanged ? 'Confirm updated routing' : 'Create ticket'}
        </button>
      </div>
    </Dialog>
  );
}
