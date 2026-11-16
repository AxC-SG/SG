import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { OwnershipSummary } from '../../types/ownership';
import { ownerChangedSinceTicket } from './ticketRouting';

/** Calm note on finding detail: the owner team differs from the one recorded when the ticket was raised. Nothing is reassigned. */
export function OwnerChangedSinceTicketNote({ findingId, ownership }: { findingId: string; ownership: OwnershipSummary | undefined }) {
  const attempts = useQuery({ queryKey: ['finding-ticket-attempts', findingId], queryFn: () => api.listFindingTicketAttempts(findingId) });
  if (!ownerChangedSinceTicket(attempts.data, ownership)) return null;
  return (
    <div className="notice" role="status">
      Owner changed since ticket: the owner team is now different from the one recorded when the ticket was raised.
      The existing ticket was not reassigned.
    </div>
  );
}
