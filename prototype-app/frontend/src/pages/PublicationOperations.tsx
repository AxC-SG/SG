import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { intelligenceApi, type PublicationAction } from '../features/intelligence/api';

export function PublicationOperations({ candidateId }: { candidateId: string }) {
  const client = useQueryClient();
  const [filter, setFilter] = React.useState('');
  const progress = useQuery({ queryKey: ['publication-progress', candidateId], queryFn: () => intelligenceApi.progress(candidateId), refetchInterval: 5000 });
  const control = useMutation({ mutationFn: (action: PublicationAction) => intelligenceApi.control(candidateId, action), onSuccess: () => { void client.invalidateQueries({ queryKey: ['publication-progress', candidateId] }); void client.invalidateQueries({ queryKey: ['intelligence-candidate', candidateId] }); } });
  const value = progress.data;
  const effectiveStatus = value?.requested_action === 'CANCEL' ? 'CANCELLED' : value?.requested_action === 'PAUSE' ? 'PAUSED' : value?.status;
  const actions: PublicationAction[] = !value ? [] : effectiveStatus === 'PAUSED' ? ['RESUME', 'CANCEL'] : effectiveStatus === 'FAILED' ? ['RETRY', 'CANCEL'] : ['RUNNING', 'BUILDING', 'PUBLICATION_QUEUED', 'QUEUED', 'RETRY_WAIT'].includes(effectiveStatus ?? '') ? ['PAUSE', 'CANCEL'] : [];
  return <section aria-label="Publication operations">
    <h4>Publication operations</h4>
    {progress.isLoading && <p role="status">Loading publication progress…</p>}
    {progress.error && <p role="alert">Progress unavailable: {String(progress.error)}</p>}
    {control.error && <p role="alert">Action failed: {String(control.error)}</p>}
    {value && <>
      <p role="status">{effectiveStatus} · {value.phase}</p>
      {value.requested_action && <p>Requested: {value.requested_action}. The worker applies this request at its next control check; it does not confirm that the current transaction has stopped.</p>}
      <p>Legacy publication has no resumable checkpoint. Pause or cancellation rolls back the current attempt; resume starts that attempt again.</p>
      <p>{value.processed.toLocaleString()} processed{value.total !== null && value.total > 0 ? ` / ${value.total.toLocaleString()} (${Math.min(100, value.processed / value.total * 100).toFixed(1)}%)` : ' · Total unknown'}</p>
      {value.total !== null && value.total > 0 && <progress aria-label="Publication progress" value={value.processed} max={value.total} />}
      <p>Started: {value.started_at ? new Date(value.started_at).toLocaleString() : 'Not reported'} · Last heartbeat: {value.heartbeat_at ? new Date(value.heartbeat_at).toLocaleString() : 'Not reported'} · Attempts: {value.attempt_count}</p>
      <details><summary>Checkpoint</summary><pre>{JSON.stringify(value.checkpoint, null, 2) ?? 'Not reported'}</pre></details>
      {actions.filter(action => !value.requested_action || (value.requested_action === 'PAUSE' && ['RESUME', 'CANCEL'].includes(action))).map(action => <button key={action} type="button" className="btn btn-secondary" disabled={control.isPending} onClick={() => { if (action !== 'CANCEL' || window.confirm('Cancel publication? The legacy path rolls back all uncommitted work in this attempt and cannot resume from its observed checkpoint. A cancelled candidate cannot resume. The active release remains available.')) control.mutate(action); }}>{action.charAt(0) + action.slice(1).toLowerCase()}</button>)}
      <label>Search activities<input value={filter} onChange={event => setFilter(event.target.value)} /></label>
      <ul aria-label="Publication activities">{value.events.filter(event => `${event.level} ${event.message}`.toLowerCase().includes(filter.toLowerCase())).map(event => <li key={event.id}><time>{new Date(event.created_at).toLocaleString()}</time> · <strong>{event.level}</strong> · {event.message}</li>)}</ul>
      {!value.events.length && <p>No activities reported yet.</p>}
    </>}
  </section>;
}
