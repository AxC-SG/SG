import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';

/** Ticket push history for a CRYPTO finding; a failed push can be retried with the crypto template. */
export function CryptoTicketAttempts({ findingId, ticketed, canRetry, onTicketed }: {
  findingId: string; ticketed: boolean; canRetry: boolean; onTicketed: () => void;
}) {
  const client = useQueryClient();
  const attemptsQuery = useQuery({ queryKey: ['finding-ticket-attempts', findingId], queryFn: () => api.listFindingTicketAttempts(findingId) });
  const retry = useMutation({
    mutationFn: () => api.createFindingTicket(findingId, {}),
    onSettled: () => { void client.invalidateQueries({ queryKey: ['finding-ticket-attempts', findingId] }); },
    onSuccess: onTicketed,
  });
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
              {attempt.errorMessage ? <div className="panel-caption">{attempt.errorMessage}</div> : null}
            </li>
          ))}
        </ul>
      )}
      {latest?.outcome === 'FAILED' && !ticketed && canRetry && (
        <button type="button" className="btn btn-secondary btn-sm" disabled={retry.isPending} onClick={() => retry.mutate()}>
          {retry.isPending ? 'Retrying…' : 'Retry ticket'}
        </button>
      )}
      {retry.isError && <div className="notice error" role="alert">{retry.error instanceof Error ? retry.error.message : 'The ticket could not be created.'}</div>}
    </section>
  );
}
