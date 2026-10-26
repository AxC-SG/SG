import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type AiBaselineObservation } from '../../api/client';
import { timeAgo } from '../../lib/time';

const labels: Record<string, string> = {
  UNAPPROVED: 'Approval required', UNCHANGED: 'Unchanged since approval',
  CHANGED_AFTER_APPROVAL: 'Changed after approval',
  BASELINE_UNKNOWN_REAPPROVAL_REQUIRED: 'Reapproval required: approval evidence or comparison version unavailable',
  CONTROL_WEAKENED: 'Control detached or explicitly weakened',
  CONTROL_CONFIGURATION_CHANGED_REVIEW_REQUIRED: 'Control configuration changed; review required',
  CONFIGURATION_UNKNOWN: 'Unknown: incomplete or incomparable control evidence',
};

export function AiBaselineSection({ artifactId, canApprove, component, version }: {
  artifactId: string; canApprove: boolean; component: string; version: string;
}) {
  const client = useQueryClient();
  const baselines = useQuery({ queryKey: ['ai-baselines', artifactId], queryFn: () => api.getAiBaselines(artifactId) });
  const observations = useQuery({ queryKey: ['ai-baseline-observations', artifactId], queryFn: () => api.getAiBaselineObservations(artifactId) });
  const history = useQuery({ queryKey: ['ai-baseline-history', artifactId], queryFn: () => api.getAiBaselineHistory(artifactId) });
  const mutation = useMutation({
    mutationFn: (action: { observation: AiBaselineObservation; mode: 'approve' | 'reapprove' } | { digestKind: string; mode: 'revoke' }) => action.mode === 'revoke'
      ? api.revokeAiBaseline(artifactId, action.digestKind)
      : api.approveAiBaselineObservation(artifactId, action.observation, action.mode === 'reapprove'),
    onSuccess: async () => {
      await Promise.all(['ai-baselines', 'ai-baseline-observations', 'ai-baseline-history', 'ai-security-findings-all', 'ai-grid-setup-actions', 'ai-asset-posture']
        .map(key => client.invalidateQueries({ queryKey: [key] })));
    },
  });
  return <section className="fd3-panel" aria-label="Approved baselines">
    <div className="fd3-panel-title">Approved baselines</div>
    <p>{component} · Inventory version: {version}</p>
    {observations.isLoading || baselines.isLoading ? <p>Loading baselines…</p>
      : observations.isError || baselines.isError ? <p role="alert">Baseline evidence could not be loaded.</p>
        : (observations.data ?? []).length === 0 && (baselines.data ?? []).length === 0 ? <p>No comparable observations collected. Assessment remains unknown.</p>
          : <table className="data-table"><thead><tr><th>Definition / control</th><th>Comparison evidence</th><th>Observation age</th><th>Approval</th></tr></thead><tbody>
            {observations.data?.map(observation => {
              const baseline = baselines.data?.find(item => item.digestKind === observation.digestKind);
              return <tr key={observation.digestKind}>
                <td>{observation.digestKind.replace(/_/g, ' ')}<div className="panel-caption">Observation version: {observation.observationVersion ?? 'Not observed'}</div></td>
                <td>{observation.stale ? 'Unknown: stale evidence' : labels[observation.comparisonOutcome] ?? 'Unknown'}<div className="panel-caption">Source run: {observation.sourceRunId}</div>
                  {(observation.changedFields?.length ?? 0) > 0 && <div className="panel-caption">Observed differences: {observation.changedFields?.join(', ')}</div>}</td>
                <td>{timeAgo(observation.observedAt) ?? observation.observedAt}</td>
                <td>{baseline?.approvalStatus ?? 'Not approved'}
                  {canApprove && <div className="button-row">
                    <button type="button" className="btn btn-secondary" disabled={mutation.isPending || observation.stale}
                      onClick={() => mutation.mutate({ observation, mode: baseline ? 'reapprove' : 'approve' })}>
                      {baseline ? 'Reapprove current observation' : 'Approve current observation'}
                    </button>
                    {baseline?.approvalStatus === 'APPROVED' && <button type="button" className="btn btn-secondary" disabled={mutation.isPending}
                      onClick={() => mutation.mutate({ digestKind: observation.digestKind, mode: 'revoke' })}>Revoke</button>}
                  </div>}
                </td>
              </tr>;
            })}
            {baselines.data?.filter(baseline => !observations.data?.some(observation => observation.digestKind === baseline.digestKind)).map(baseline => <tr key={baseline.digestKind}>
              <td>{baseline.digestKind.replace(/_/g, ' ')}</td><td>Unknown: current observation unavailable</td><td>Not observed</td>
              <td>{baseline.approvalStatus}{canApprove && baseline.approvalStatus === 'APPROVED' && <button type="button" className="btn btn-secondary" disabled={mutation.isPending}
                onClick={() => mutation.mutate({ digestKind: baseline.digestKind, mode: 'revoke' })}>Revoke</button>}</td>
            </tr>)}
          </tbody></table>}
    {mutation.isError && <p role="alert">Approval could not be updated. Reload the evidence and try again.</p>}
    <details><summary>Approval history</summary>
      {history.isError ? <p role="alert">Approval history could not be loaded.</p> : history.isLoading ? <p>Loading history…</p>
        : (history.data ?? []).length === 0 ? <p>No approval history.</p>
          : <ul>{history.data?.map(event => <li key={event.id}>{event.digestKind.replace(/_/g, ' ')}: {event.action} by {event.actor ?? 'Unknown'} at {new Date(event.recordedAt).toLocaleString()}</li>)}</ul>}
    </details>
  </section>;
}
