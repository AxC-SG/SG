import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { intelligenceApi, type Candidate } from '../features/intelligence/api';

export function IntelligenceReviewPanel() {
  const client = useQueryClient();
  const [selected, setSelected] = React.useState<string[]>([]);
  const [params, setParams] = useSearchParams();
  const candidateId = params.get('candidate');
  const setCandidateId = (id: string) => { const next = new URLSearchParams(params); next.set('candidate', id); setParams(next, { replace: true }); };
  const [page, setPage] = React.useState(0);
  const [reviewed, setReviewed] = React.useState<string | null>(null);
  const [reason, setReason] = React.useState('');
  const [releaseId, setReleaseId] = React.useState<string | null>(null);
  const [processingPage, setProcessingPage] = React.useState(0);
  const approvalKey = React.useRef<{ candidate: string; key: string } | null>(null);
  const runs = useQuery({ queryKey: ['intelligence-review-runs'], queryFn: () => api.listSyncRuns({ category: 'vulnerability', limit: 200 }) });
  const candidate = useQuery({ queryKey: ['intelligence-candidate', candidateId], queryFn: () => intelligenceApi.candidate(candidateId!), enabled: !!candidateId,
    refetchInterval: (query) => ['BUILDING', 'PUBLICATION_QUEUED'].includes(query.state.data?.status ?? '') ? 2000 : false });
  const records = useQuery({ queryKey: ['intelligence-records', candidateId, page], queryFn: () => intelligenceApi.records(candidateId!, page), enabled: !!candidateId && !!candidate.data?.digest });
  const releases = useQuery({ queryKey: ['intelligence-releases', candidate.data?.status], queryFn: intelligenceApi.releases, refetchInterval: 5000 });
  const processing = useQuery({ queryKey: ['intelligence-processing', releaseId, processingPage], queryFn: () => intelligenceApi.processing(releaseId!, processingPage), enabled: !!releaseId, refetchInterval: 5000 });
  const build = useMutation({ mutationFn: () => intelligenceApi.create(selected), onSuccess: (value) => { setCandidateId(value.id); setPage(0); setReviewed(null); approvalKey.current = null; } });
  const approve = useMutation({ mutationFn: (value: Candidate) => { if (approvalKey.current?.candidate !== value.id) approvalKey.current = { candidate: value.id, key: crypto.randomUUID() }; return intelligenceApi.publish(value, approvalKey.current.key); }, onSuccess: () => client.invalidateQueries({ queryKey: ['intelligence-candidate'] }) });
  const reject = useMutation({ mutationFn: () => intelligenceApi.reject(candidateId!, reason), onSuccess: () => client.invalidateQueries({ queryKey: ['intelligence-candidate'] }) });
  const withdraw = useMutation({ mutationFn: (id: string) => intelligenceApi.withdraw(id, crypto.randomUUID()), onSuccess: () => client.invalidateQueries({ queryKey: ['intelligence-releases'] }) });
  const errors = [runs.error, candidate.error, records.error, releases.error, processing.error, build.error, approve.error, reject.error, withdraw.error].filter(Boolean);
  const completed = (runs.data ?? []).filter((run) => ['completed', 'success'].includes(run.status.toLowerCase()) && !run.syncType.startsWith('EOL_'));
  const value = candidate.data;
  return <section className="panel">
    <div className="panel-header"><h3>Review and publish intelligence</h3><button type="button" className="btn btn-secondary" onClick={() => void runs.refetch()}>Refresh runs</button></div>
    <p>Select completed feed runs. Required unpublished predecessors are included in the candidate for review.</p>
    {errors.map((error, index) => <p className="notice error" role="alert" key={index}>{error instanceof Error ? error.message : 'Request failed'}</p>)}
    {runs.isLoading && <p role="status">Loading feed runs…</p>}
    <fieldset disabled={build.isPending}><legend>Completed runs</legend>
      {!completed.length && !runs.isLoading && <p>No completed runs are available.</p>}
      {completed.map((run) => <label key={run.id} style={{ display: 'block', marginBlock: 8 }}><input type="checkbox" checked={selected.includes(run.id)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, run.id] : current.filter((id) => id !== run.id))} /> {run.syncType} · {new Date(run.completedAt ?? run.startedAt).toLocaleString()} · {run.recordsFetched} fetched</label>)}
    </fieldset>
    <button type="button" className="btn btn-primary" disabled={!selected.length || build.isPending} onClick={() => build.mutate()}>{build.isPending ? 'Building…' : 'Build review candidate'}</button>
    {value && <div aria-live="polite">
      <h4>Candidate · {value.status}</h4>
      {value.error_code && <p className="notice error">{value.error_code}. Build a new candidate after addressing this issue.</p>}
      <p>Base release: {value.base_release_id ?? 'Empty intelligence'} · Policy: {value.normalization_policy}</p>
      <p>Selected runs: {value.selected_run_ids.length} · Expanded runs: {value.expanded_run_ids.length}</p>
      <details><summary>Expanded run selection</summary><ul>{value.expanded_run_ids.map((id) => <li key={id}>{id}</li>)}</ul></details>
      <dl>{Object.entries(value.quality_report).map(([key, count]) => <React.Fragment key={key}><dt>{key.replace(/_/g, ' ')}</dt><dd>{count}</dd></React.Fragment>)}</dl>
      {value.digest && <p>Content digest: <code style={{ overflowWrap: 'anywhere' }}>{value.digest}</code></p>}
      {records.data && <><div style={{ overflowX: 'auto' }}><table className="data-table"><thead><tr><th>Canonical identifier</th><th>Change</th><th>Source</th><th>Quality</th><th>Evidence</th></tr></thead><tbody>{records.data.map((record) => <tr key={record.id}><td>{record.external_id}</td><td>{record.kind}</td><td>{record.source_system}</td><td>{record.validation}</td><td><details><summary>View prepared evidence</summary><pre style={{ maxWidth: 600, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(record.payload, null, 2)}</pre></details></td></tr>)}</tbody></table></div>
        <button type="button" className="btn btn-secondary" disabled={!page} onClick={() => setPage((current) => current - 1)}>Previous records</button><span> Page {page + 1} </span><button type="button" className="btn btn-secondary" disabled={records.data.length < 50} onClick={() => setPage((current) => current + 1)}>Next records</button></>}
      {value.status === 'READY' && <><label style={{ display: 'block', marginBlock: 16 }}><input type="checkbox" checked={reviewed === `${value.id}:${value.digest}`} onChange={(event) => setReviewed(event.target.checked ? `${value.id}:${value.digest}` : null)} /> I reviewed the expanded selection, prepared changes, and exclusions for this digest.</label>
        <button type="button" className="btn btn-primary" disabled={reviewed !== `${value.id}:${value.digest}` || approve.isPending || reject.isPending} onClick={() => approve.mutate(value)}>Approve and publish</button>
        <label style={{ display: 'block', marginBlock: 12 }}>Rejection reason<input value={reason} maxLength={2000} onChange={(event) => setReason(event.target.value)} /></label><button type="button" className="btn btn-secondary" disabled={!reason.trim() || reject.isPending || approve.isPending} onClick={() => reject.mutate()}>Reject candidate</button></>}
      {value.status === 'PUBLISHED' && <p role="status">Published. Tenant processing is scheduled automatically.</p>}
    </div>}
    <h4>Release history</h4>
    {(releases.data ?? []).map((release, index) => <article key={release.id} className="panel"><p>Release {release.generation} · {release.kind} · {new Date(release.published_at).toLocaleString()} · {release.actor}</p><button type="button" className="btn btn-secondary" onClick={() => { setReleaseId(release.id); setProcessingPage(0); }}>View tenant processing</button>{index === 0 && <button type="button" className="btn btn-secondary" disabled={withdraw.isPending} onClick={() => withdraw.mutate(release.id)}>Withdraw active release</button>}</article>)}
    {processing.data && <><h4>Tenant processing</h4><ul>{processing.data.map((tenant) => <li key={tenant.tenant_id}>{tenant.tenant_id} · {tenant.status} · revision {tenant.completed_revision}/{tenant.required_revision} · generation {tenant.completed_generation}{tenant.last_error ? ` · ${tenant.last_error}` : ''}</li>)}</ul><button type="button" className="btn btn-secondary" disabled={!processingPage} onClick={() => setProcessingPage((current) => current - 1)}>Previous tenants</button><button type="button" className="btn btn-secondary" disabled={processing.data.length < 50} onClick={() => setProcessingPage((current) => current + 1)}>Next tenants</button></>}
  </section>;
}
