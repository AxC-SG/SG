import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { apiRequest } from '../api/client';

type Kind = 'ALL' | 'CVE' | 'OTHER';
type Status = 'ALL' | 'ACTIVE' | 'WITHDRAWN';
type CatalogPage = {
  items: Array<{
    id: string; externalId: string; kind: Kind; status: Status; title: string;
    severity: string; cvssScore: number | null; epssScore: number | null; inKev: boolean; sourceSystems: string[];
  }>;
  size: number; hasMore: boolean; nextAfterExternalId: string | null; nextAfterId: string | null;
};
type Cursor = { afterExternalId: string; afterId: string } | null;
type PipelineProgress = {
  acquisition: { source: string; status: string; fetchedRecords: number; failedRecords: number } | null;
  publication: { activeGeneration: number; pendingReviewCandidates: number; pendingPublicationJobs: number };
  tenantDelivery: { activeTenants: number; currentTenants: number; updatingTenants: number; failedTenants: number; staleCheckpoints: number };
  catalogInventory: { canonicalRecords: number; activeCanonicalRecords: number;
    withdrawnCanonicalRecords: number; sourceObservationRows: number };
  sources: Array<{ source: string; latestRunId: string | null; latestRunStatus: string | null;
    latestFetchedRecords: number; historicalCoverageStatus: string;
    observedWindowCount: number; observedFilterScopeCount: number; latestObservedIntervalEnd: string | null;
    evidenceRole: string; acquisitionScope: string; tenantPolicySelectable: boolean }>;
  assetEvaluationStatus: string;
};
type NvdScopes = { items: Array<{ feedKey: string; observedWindowCount: number;
  firstObservedIntervalStart: string; latestObservedIntervalEnd: string }>;
  hasMore: boolean; nextAfterFeedKey: string | null };
type NvdGaps = { feedKey: string; from: string; to: string; observedWindowCount: number;
  unobservedIntervals: Array<{ from: string; to: string }>; historicalCoverageStatus: 'UNKNOWN' };
type NvdBaselinePlan = { feedKey: string; from: string; to: string; historicalCoverageStatus: 'UNKNOWN';
  partitions: Array<{ from: string; to: string; observedWindowCount: number;
    unobservedIntervals: Array<{ from: string; to: string }> }> };

export function CentralCatalogPage() {
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<Kind>('ALL');
  const [status, setStatus] = useState<Status>('ACTIVE');
  const [page, setPage] = useState(0);
  const [cursors, setCursors] = useState<Cursor[]>([null]);
  const cursor = cursors[page];
  const resetPages = () => { setPage(0); setCursors([null]); };
  const result = useQuery({
    queryKey: ['platform-central-catalog', query, kind, status, cursor],
    queryFn: () => apiRequest<CatalogPage>(`/platform/vuln-repo/records/cursor?${new URLSearchParams({
      query, kind, status, size: '25', ...(cursor ?? {})
    })}`)
  });
  const progress = useQuery({ queryKey: ['platform-intelligence-progress'], enabled: false,
    queryFn: () => apiRequest<PipelineProgress>('/platform/intelligence/progress') });
  const [scopeLoaded, setScopeLoaded] = useState(false);
  const [scopeCursor, setScopeCursor] = useState<string | null>(null);
  const [selectedScope, setSelectedScope] = useState('');
  const [fromDate, setFromDate] = useState(() => new Date(Date.now() - 30 * 86400000).toISOString().slice(0, 10));
  const [toDate, setToDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [dateError, setDateError] = useState('');
  const scopes = useQuery({ queryKey: ['nvd-observed-scopes', scopeCursor], enabled: scopeLoaded,
    queryFn: () => apiRequest<NvdScopes>(`/platform/intelligence/progress/nvd-observed-scopes${scopeCursor
      ? `?${new URLSearchParams({ afterFeedKey: scopeCursor })}` : ''}`) });
  const gaps = useMutation({ mutationFn: (input: { feedKey: string; from: string; to: string }) =>
    apiRequest<NvdGaps>(`/platform/intelligence/progress/nvd-observed-gaps?${new URLSearchParams(input)}`) });
  const baselinePlan = useMutation({ mutationFn: (input: { feedKey: string; from: string; to: string }) =>
    apiRequest<NvdBaselinePlan>(`/platform/intelligence/progress/nvd-baseline-plan?${new URLSearchParams(input)}`) });

  return <section className="panel">
    <h2>Central intelligence catalog</h2>
    <p>Published CVEs and other advisory records. Inclusion here does not mean a tenant has an affected asset.
      Withdrawn records remain available for historical review; acquisition and staging are separate.</p>
    <section aria-label="Intelligence pipeline progress">
      <h3>Pipeline progress</h3>
      <button type="button" disabled={progress.isFetching} onClick={() => { void progress.refetch(); }}>Load pipeline status</button>
      {progress.isFetching ? <p role="status">Loading pipeline status…</p> : null}
      {progress.isError ? <p role="alert">Could not load pipeline status: {progress.error.message}</p> : null}
      {progress.data ? <ul>
        <li>Acquisition: {progress.data.acquisition
          ? `${progress.data.acquisition.source} ${progress.data.acquisition.status}; ${progress.data.acquisition.fetchedRecords} fetched source records, ${progress.data.acquisition.failedRecords} failed`
          : 'No platform feed run recorded'}</li>
        <li>Publication: active generation {progress.data.publication.activeGeneration}; {progress.data.publication.pendingReviewCandidates} candidates awaiting review, {progress.data.publication.pendingPublicationJobs} publication jobs pending</li>
        <li>Catalog inventory: {progress.data.catalogInventory.canonicalRecords} canonical records ({progress.data.catalogInventory.activeCanonicalRecords} active, {progress.data.catalogInventory.withdrawnCanonicalRecords} withdrawn); {progress.data.catalogInventory.sourceObservationRows} source-observation rows. These are stored rows, not CVEs fetched in the latest run or proof of complete source history.</li>
        <li>Tenant delivery: {progress.data.tenantDelivery.currentTenants} current, {progress.data.tenantDelivery.updatingTenants} updating, {progress.data.tenantDelivery.failedTenants} failed of {progress.data.tenantDelivery.activeTenants} active tenants; stale partial-scan checkpoints: {progress.data.tenantDelivery.staleCheckpoints} (will restart)</li>
        <li>Asset evaluation: {progress.data.assetEvaluationStatus === 'NOT_SEPARATELY_TRACKED'
          ? 'not separately tracked yet; no affected-asset count is implied.' : progress.data.assetEvaluationStatus}</li>
      </ul> : null}
      {progress.data ? <table><caption>Per-source acquisition evidence; observed windows are not proof of complete history</caption>
        <thead><tr><th scope="col">Source</th><th scope="col">Evidence role</th><th scope="col">Acquisition scope</th><th scope="col">Policy-selectable</th><th scope="col">Latest run</th><th scope="col">Fetched in latest run</th><th scope="col">Observed windows</th><th scope="col">Historical coverage</th></tr></thead>
        <tbody>{progress.data.sources.map(source => <tr key={source.source}>
          <td>{source.source}</td><td>{source.evidenceRole.replace(/_/g, ' ')}</td>
          <td>{source.acquisitionScope.replace(/_/g, ' ')}</td><td>{source.tenantPolicySelectable ? 'Yes' : 'No'}</td>
          <td>{source.latestRunStatus ?? 'No run recorded'}</td>
          <td>{source.latestRunId ? source.latestFetchedRecords : 'Unknown'}</td>
          <td>{source.observedWindowCount} across {source.observedFilterScopeCount} filter scope{source.observedFilterScopeCount === 1 ? '' : 's'}</td>
          <td>{source.historicalCoverageStatus === 'UNKNOWN' ? 'Unknown — no completeness proof' : source.historicalCoverageStatus}</td>
        </tr>)}</tbody>
      </table> : null}
    </section>
    <section aria-label="NVD observed-window diagnostic">
      <h3>NVD observed-window diagnostic</h3>
      <p>Read-only, per filter scope. Unobserved time is not a count of missing CVEs; even no gaps does not prove a complete historical catalog.</p>
      <button type="button" disabled={scopes.isFetching} onClick={() => {
        if (!scopeLoaded) setScopeLoaded(true);
        else if (scopeCursor) { setScopeCursor(null); setSelectedScope(''); gaps.reset(); baselinePlan.reset(); }
        else void scopes.refetch();
      }}>Load NVD filter scopes</button>
      {scopes.isFetching ? <p role="status">Loading NVD filter scopes…</p> : null}
      {scopes.isError ? <p role="alert">Could not load NVD filter scopes: {scopes.error.message}</p> : null}
      {scopes.data && !scopes.isError ? <>
        {scopes.data.items.length === 0 ? <p>No NVD interval observations in this scope page.</p> :
          <label>NVD filter scope <select value={selectedScope} onChange={(event) => {
            setSelectedScope(event.target.value); gaps.reset(); baselinePlan.reset(); setDateError('');
          }}><option value="">Choose a scope</option>{scopes.data.items.map(scope =>
            <option key={scope.feedKey} value={scope.feedKey}>{scope.feedKey} — {scope.observedWindowCount} observed windows</option>)}</select></label>}
        {scopes.data.hasMore ? <button type="button" disabled={scopes.isFetching} onClick={() => {
          setScopeCursor(scopes.data.nextAfterFeedKey); setSelectedScope(''); gaps.reset(); baselinePlan.reset();
        }}>Next NVD scopes</button> : null}
      </> : null}
      <form onSubmit={(event) => {
        event.preventDefault();
        const from = Date.parse(`${fromDate}T00:00:00Z`);
        const to = Date.parse(`${toDate}T00:00:00Z`);
        if (!selectedScope || !Number.isFinite(from) || !Number.isFinite(to) || to <= from || to - from > 120 * 86400000) {
          gaps.reset(); setDateError('Choose a scope and a positive UTC interval of at most 120 days.'); return;
        }
        setDateError(''); gaps.mutate({ feedKey: selectedScope, from: new Date(from).toISOString(), to: new Date(to).toISOString() });
      }}>
        <label>From date (UTC, inclusive) <input type="date" value={fromDate} required onChange={(event) => {
          setFromDate(event.target.value); gaps.reset(); baselinePlan.reset(); setDateError('');
        }} /></label>
        <label>To date (UTC, exclusive) <input type="date" value={toDate} required onChange={(event) => {
          setToDate(event.target.value); gaps.reset(); baselinePlan.reset(); setDateError('');
        }} /></label>
        <button type="submit" disabled={!selectedScope || gaps.isPending}>Inspect observed intervals</button>
        <button type="button" disabled={!selectedScope || baselinePlan.isPending} onClick={() => {
          const from = Date.parse(`${fromDate}T00:00:00Z`);
          const to = Date.parse(`${toDate}T00:00:00Z`);
          if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from ||
              to - from > 366 * 40 * 86400000 || to > Date.now()) {
            baselinePlan.reset(); setDateError('Choose a past UTC interval of at most 40 years.'); return;
          }
          setDateError(''); baselinePlan.mutate({ feedKey: selectedScope,
            from: new Date(from).toISOString(), to: new Date(to).toISOString() });
        }}>Plan baseline windows</button>
      </form>
      {dateError ? <p role="alert">{dateError}</p> : null}
      {gaps.isPending ? <p role="status">Inspecting NVD observations…</p> : null}
      {gaps.isError ? <p role="alert">Could not inspect NVD observations: {gaps.error.message}</p> : null}
      {gaps.data ? <div>
        <p>{gaps.data.observedWindowCount} overlapping observed windows. Historical coverage: unknown — no completeness proof.</p>
        {gaps.data.unobservedIntervals.length === 0 ? <p>No unobserved intervals in this selected range; this does not certify completeness.</p> :
          <ul>{gaps.data.unobservedIntervals.map(interval => <li key={`${interval.from}-${interval.to}`}>
            No successful interval observation from {interval.from} to {interval.to}
          </li>)}</ul>}
      </div> : null}
      {baselinePlan.isPending ? <p role="status">Planning NVD windows…</p> : null}
      {baselinePlan.isError ? <p role="alert">Could not plan NVD windows: {baselinePlan.error.message}</p> : null}
      {baselinePlan.data ? <div>
        <p>{baselinePlan.data.partitions.length} bounded windows. Historical completeness remains unknown; these are observation gaps, not missing-CVE counts.</p>
        <ol>{baselinePlan.data.partitions.map(partition => <li key={partition.from}>
          {partition.from} to {partition.to}: {partition.observedWindowCount} observed run windows;{' '}
          {partition.unobservedIntervals.length === 0 ? 'no unobserved time (not a completeness certificate)' :
            `${partition.unobservedIntervals.length} unobserved interval(s)`}
        </li>)}</ol>
      </div> : null}
    </section>
    <form onSubmit={(event) => { event.preventDefault(); setQuery(draft.trim()); resetPages(); }}>
      <label>Search identifier or title <input value={draft} onChange={(event) => setDraft(event.target.value)} /></label>
      <button type="submit" className="btn btn-secondary">Search</button>
      <label>Record kind <select value={kind} onChange={(event) => { setKind(event.target.value as Kind); resetPages(); }}>
        <option value="ALL">All records</option><option value="CVE">CVEs</option><option value="OTHER">Other advisories</option>
      </select></label>
      <label>Publication status <select value={status} onChange={(event) => { setStatus(event.target.value as Status); resetPages(); }}>
        <option value="ACTIVE">Active</option><option value="WITHDRAWN">Withdrawn</option><option value="ALL">All statuses</option>
      </select></label>
    </form>
    {result.isPending ? <p role="status">Loading central catalog…</p> : null}
    {result.isError ? <div role="alert">
      <p>Could not load central catalog: {result.error.message}</p>
      <button type="button" onClick={() => { void result.refetch(); }}>Retry</button>
    </div> : null}
    {result.data && !result.isError ? <>
      <p role="status">Showing page {page + 1} of matching records. Counts are not recalculated during deep browsing.</p>
      {result.data.items.length === 0 ? <p>No published records match these filters.</p> :
        <table>
          <caption>Central catalog records</caption>
          <thead><tr>{['Identifier', 'Kind', 'Status', 'Title', 'Sources', 'Severity', 'CVSS', 'EPSS', 'CISA KEV'].map((heading) =>
            <th key={heading} scope="col">{heading}</th>)}</tr></thead>
          <tbody>{result.data.items.map((record) => <tr key={record.id}>
            <td><Link to={`/vuln-repo/intel/${encodeURIComponent(record.externalId)}`}>{record.externalId}</Link></td>
            <td>{record.kind}</td><td>{record.status}</td><td>{record.title}</td>
            <td>{record.sourceSystems.length ? record.sourceSystems.join(', ') : 'No source observation'}</td>
            <td>{record.severity}</td>
            <td>{record.cvssScore ?? 'Unknown'}</td>
            <td>{record.epssScore == null ? 'Unknown' : `${(record.epssScore * 100).toFixed(2)}%`}</td>
            <td>{record.inKev ? 'Yes' : 'No'}</td>
          </tr>)}</tbody>
        </table>}
      <button type="button" disabled={page === 0 || result.isFetching} onClick={() => setPage((value) => value - 1)}>Previous</button>
      <span> Page {page + 1} </span>
      <button type="button" disabled={!result.data.hasMore || !result.data.nextAfterExternalId || !result.data.nextAfterId || result.isFetching}
        onClick={() => { const nextExternalId = result.data?.nextAfterExternalId; const nextId = result.data?.nextAfterId;
          if (!nextExternalId || !nextId) return;
          setCursors((value) => [...value.slice(0, page + 1), { afterExternalId: nextExternalId, afterId: nextId }]);
          setPage((value) => value + 1);
        }}>Next</button>
    </> : null}
  </section>;
}
