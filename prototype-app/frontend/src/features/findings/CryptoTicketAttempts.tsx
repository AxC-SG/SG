import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { FindingTicketDialog } from './FindingTicketDialog';
import { routingSourceLabel } from './ticketRouting';

/** Ticket push history for a CRYPTO finding; a failed push can be retried with the crypto template. */
export function CryptoTicketAttempts({ findingId, ticketed, canRetry, onTicketed }: {
  findingId: string; ticketed: boolean; canRetry: boolean; onTicketed: () => void;
}) {
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const attemptsQuery = useQuery({ queryKey: ['finding-ticket-attempts', findingId], queryFn: () => api.listFindingTicketAttempts(findingId) });
  const attempts = attemptsQuery.data ?? [];
  if (attemptsQuery.isPending || (attempts.length === 0 && !attemptsQuery.isError)) return null;
  const latest = attempts[0];

  return (
    <section className="panel crypto-ticket-attempts" aria-labelledby={`ticket-attempts-${findingId}`}>
      <h3 id={`ticket-attempts-${findingId}`}>Ticket attempts</h3>
      {attemptsQuery.isError ? <div className="notice error" role="alert">Ticket attempts could not be loaded.</div> : (
        <ul>
          {attempts.slice(0, 5).map((attempt) => (
            <li key={attempt.id}>
              <strong>{attempt.outcome === 'SUCCEEDED' ? 'Created' : 'Failed'}</strong>
              {' '}{new Date(attempt.attemptedAt).toLocaleString()} · {attempt.provider ?? 'no provider'} · {attempt.template === 'CRYPTO' ? 'crypto template' : 'default template'}
              {attempt.ticketKey ? ` · ${attempt.ticketKey}` : ''}
              {attempt.assignmentGroup ? ` · group ${attempt.assignmentGroup} (${routingSourceLabel(attempt.routingSource)})` : ''}
              {attempt.overrideReason ? <div className="panel-caption">Override reason: {attempt.overrideReason}</div> : null}
              {attempt.errorMessage ? <div className="panel-caption">{attempt.errorMessage}</div> : null}
            </li>
          ))}
        </ul>
      )}
      {latest?.outcome === 'FAILED' && !ticketed && canRetry && (
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => setDialogOpen(true)}>Retry ticket</button>
      )}
      <FindingTicketDialog findingId={findingId} isOpen={dialogOpen} onClose={() => setDialogOpen(false)} onCreated={onTicketed} />
    </section>
  );
}
