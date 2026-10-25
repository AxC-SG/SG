import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { api } from '../api/client';
import type { AiGridExposureSummary } from '../features/ai-security/types';

function readableJson(value: string): string {
  try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
}

function ExposureDetail({ exposureId }: { exposureId: string }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const detail = useQuery({
    queryKey: ['ai-grid-exposure', exposureId],
    queryFn: () => api.getAiGridExposure(exposureId),
  });
  const disposition = useMutation({
    mutationFn: (value: string) => api.dispositionAiGridExposure(exposureId, value, 'Analyst review'),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['ai-grid-exposures'] }),
        queryClient.invalidateQueries({ queryKey: ['ai-grid-exposure', exposureId] }),
      ]);
    },
  });
  if (detail.isLoading) return <section className="panel"><p>Loading exposure…</p></section>;
  if (detail.isError || !detail.data) return <section className="panel"><p>Exposure could not be loaded.</p></section>;
  const { exposure: summary, observations, associations } = detail.data;
  return (
    <section className="ai-security-page ai-exposure-detail">
      <button type="button" className="btn btn-secondary" onClick={() => navigate('/findings/ai/exposures')}>← All exposures</button>
      <header className="ai-security-hero findings">
        <div><span className="ai-security-kicker">{summary.correlationId} · v{summary.correlationVersion}</span>
          <h2>{summary.title}</h2><p>{summary.impact}</p></div>
        <span className={`severity-badge ${summary.severity.toLowerCase()}`}>{summary.severity}</span>
        <span className="status-pill">{summary.state.replace(/_/g, ' ')}</span>
      </header>
      <div className="ai-exposure-grid">
        <article className="panel"><h3>Root cause</h3><p>{summary.rootCause}</p><p className="mono">{summary.rootCauseArtifactId}</p></article>
        <article className="panel"><h3>Recommended breakpoint</h3><p>{summary.breakpoint}</p></article>
        <article className="panel"><h3>Confidence</h3><p>{Math.round(summary.confidence * 100)}% · {summary.confidenceMethod}</p>
          <p>Validating evidence is time-bound and producer-calibrated.</p></article>
      </div>
      <section className="panel"><h3>Path and evidence history</h3>{observations.map((observation) => (
        <details key={observation.id}><summary>{observation.state.replace(/_/g, ' ')} · {new Date(observation.observedAt).toLocaleString()}</summary>
          <p>Valid {new Date(observation.validFrom).toLocaleString()} → {observation.validUntil ? new Date(observation.validUntil).toLocaleString() : 'open'}</p>
          <pre>{readableJson(observation.pathJson)}</pre><pre>{readableJson(observation.evidenceJson)}</pre>
        </details>))}</section>
      <section className="panel"><h3>Affected subjects</h3><ul>{associations.map((item, index) => (
        <li key={`${item.role}-${item.systemId ?? item.artifactId}-${index}`}>{item.role}: <span className="mono">{item.systemId ?? item.artifactId}</span></li>
      ))}</ul></section>
      <div className="button-row"><button type="button" className="btn btn-primary" disabled={disposition.isPending} onClick={() => disposition.mutate('ACCEPTED')}>Accept exposure</button>
        <button type="button" className="btn btn-secondary" disabled={disposition.isPending} onClick={() => disposition.mutate('FALSE_POSITIVE')}>Mark false positive</button></div>
    </section>
  );
}

export function AiExposuresPage() {
  const { exposureId } = useParams<{ exposureId?: string }>();
  const navigate = useNavigate();
  const [cursor, setCursor] = React.useState<string | undefined>();
  const exposures = useQuery({ queryKey: ['ai-grid-exposures', cursor], queryFn: () => api.listAiGridExposures(cursor) });
  const priorities = useQuery({ queryKey: ['ai-exposure-priorities'], queryFn: api.listAiExposurePriorities });
  if (exposureId) return <ExposureDetail exposureId={exposureId} />;
  const items: AiGridExposureSummary[] = exposures.data?.items ?? [];
  return <section className="ai-security-page"><header className="ai-security-hero findings"><div>
    <span className="ai-security-kicker">Cross-system paths backed by temporal evidence</span><h2>AI Exposures</h2>
    <p>Hypotheses remain separate until trusted evidence validates the complete path.</p></div></header>
    {exposures.isLoading ? <section className="panel"><p>Loading exposures…</p></section> : exposures.isError ? <section className="panel"><p>Exposures could not be loaded.</p></section> :
      <section className="panel ai-security-table-panel"><table className="data-table"><thead><tr><th>Exposure</th><th>Priority</th><th>State</th><th>Owner</th><th>Confidence</th><th>Systems</th><th>Observed</th></tr></thead><tbody>
        {items.map((item) => {
          const priority = priorities.data?.find((candidate) => candidate.id === item.id);
          return <tr key={item.id} tabIndex={0} onClick={() => navigate(`/findings/ai/exposures/${item.id}`)} onKeyDown={(event) => { if (event.key === 'Enter') navigate(`/findings/ai/exposures/${item.id}`); }}>
          <td><span className={`severity-badge ${item.severity.toLowerCase()}`}>{item.severity}</span><strong>{item.title}</strong><small>{item.correlationId}</small></td>
          <td>{priority ? <><strong>{priority.priority}</strong><small>{priority.severityPoints}+{priority.confidencePoints}+{priority.publicExposurePoints}+{priority.criticalityPoints}+{priority.recencyPoints}</small></> : '—'}</td>
          <td><span className="status-pill">{item.state.replace(/_/g, ' ')}</span></td><td>{priority?.owner ?? 'Unowned'}</td><td>{Math.round(item.confidence * 100)}%</td><td>{item.affectedSystems}</td><td>{new Date(item.lastObservedAt).toLocaleString()}</td>
        </tr>;
        })}</tbody></table>{items.length === 0 ? <div className="empty-state"><p>No exposure paths observed.</p></div> : null}
        {exposures.data?.nextCursor ? <button type="button" className="btn btn-secondary" onClick={() => setCursor(exposures.data?.nextCursor ?? undefined)}>Next page</button> : null}</section>}
  </section>;
}
