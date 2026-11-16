import React from 'react';
import { useActor } from '../auth/context';
import { canCreateTickets } from '../auth/roles';
import { FindingTicketDialog } from './FindingTicketDialog';

/** "Create ticket" for an open finding that has none yet; only for roles the server accepts for ticketing. */
export function FindingCreateTicketAction({ findingId, status, incidentId, onCreated }: {
  findingId: string; status: string; incidentId?: string | null; onCreated: () => void;
}) {
  const actor = useActor();
  const [open, setOpen] = React.useState(false);
  if (status !== 'OPEN' || incidentId || !canCreateTickets(actor)) return null;
  return (
    <>
      <button type="button" className="fd3-action-btn" onClick={() => setOpen(true)}>Create ticket</button>
      <FindingTicketDialog findingId={findingId} isOpen={open} onClose={() => setOpen(false)} onCreated={onCreated} />
    </>
  );
}
