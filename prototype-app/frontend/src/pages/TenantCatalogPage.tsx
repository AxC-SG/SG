import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '../api/client';

type Build = { id: string; policyVersion: number; generation: number; status: string; scanned: number; matched: number; lastError: string | null };
type Member = { vulnerabilityId: string; externalId: string; reason: string; withdrawn: boolean };
type FindingComparison = { selectedRecords: number; existingFindingRows: number; unlinkedFindingRows: number; findingRowsOutsideSelection: number; distinctRecordsOutsideSelection: number;
  openOutsideSelection: number; suppressedOutsideSelection: number; resolvedOutsideSelection: number; autoClosedOutsideSelection: number };
type OrgCveComparison = { selectedRecords: number; existingOrgCveRecords: number; overlappingRecords: number;
  orgCveRecordsOutsideSelection: number; selectedWithoutOrgCveRecord: number };
type DifferenceDirection = 'ORG_OUTSIDE_SELECTION' | 'SELECTED_WITHOUT_ORG';
type DifferencePage = { direction: DifferenceDirection; records: Array<{ vulnerabilityId: string; externalId: string }>;
  nextAfterId: string | null; complete: boolean };
type InputStatus = { buildId: string; current: boolean; reason: string;
  policyVersion: number; latestPolicyVersion: number; latestPolicy: boolean };
type ActivationReadiness = { buildId: string; localChecksPass: boolean; activationEnabled: boolean; blockers: string[] };
type LegacyCompatibility = { enabledSources: string[]; gaps: Array<{ source: string; fields: string[]; reason: string; canonicalSource: string | null }> };
type Override = { revision: number; operation: string; reason: string; expiresAt: string | null; createdAt: string };
const root = '/intelligence/catalog-policy';
const running = (status: string) => status === 'QUEUED' || status === 'BUILDING';

export function TenantCatalogPage({ tenantId }: { tenantId: string }) {
  const client = useQueryClient();
  const [version, setVersion] = useState('');
  const [selectedBuild, setSelectedBuild] = useState('');
  const [after, setAfter] = useState<string | null>(null);
  const [recordInput, setRecordInput] = useState('');
  const [record, setRecord] = useState('');
  const request = useRef<{ version: number; id: string } | null>(null);
  const versions = useQuery({ queryKey: ['catalog-versions', tenantId],
    queryFn: () => apiRequest<Array<{ version: number }>>(`${root}/versions`) });
  const builds = useQuery({ queryKey: ['catalog-builds', tenantId],
    queryFn: () => apiRequest<Build[]>(`${root}/builds`),
    refetchInterval: query => query.state.data?.some(build => running(build.status)) ? 3000 : false });
  const selectedVersion = Number(version || versions.data?.[0]?.version || 0);
  const create = useMutation({
    mutationFn: () => {
      if (!request.current || request.current.version !== selectedVersion) request.current = { version: selectedVersion, id: crypto.randomUUID() };
      return apiRequest<Build>(`${root}/builds`, { method: 'POST', body: JSON.stringify({ requestId: request.current.id, policyVersion: selectedVersion }) });
    },
    onSuccess: async build => {
      request.current = null; setSelectedBuild(build.id); setAfter(null);
      await client.invalidateQueries({ queryKey: ['catalog-builds', tenantId] });
    }
  });
  const cancel = useMutation({ mutationFn: (id: string) => apiRequest<Build>(`${root}/builds/${id}/cancel`, { method: 'POST' }),
    onSuccess: async () => { await client.invalidateQueries({ queryKey: ['catalog-builds', tenantId] }); } });
  const members = useQuery({ queryKey: ['catalog-build-members', tenantId, selectedBuild, after], enabled: Boolean(selectedBuild),
    queryFn: () => apiRequest<Member[]>(`${root}/builds/${selectedBuild}/members${after ? `?afterId=${after}` : ''}`) });
  const selectedStatus = builds.data?.find(build => build.id === selectedBuild)?.status;

  return <section className="panel">
    <h2>Tenant catalog workspace</h2>
    <p>Build a review-only catalog from a saved policy. Builds do not activate a catalog, remove central records, or change findings.</p>
    <LegacySettingsReview tenantId={tenantId} />
    <h3>Shadow builds</h3>
    <p>Save a policy in Catalog policy preview first. A worker processes up to 100 records per batch. Changed inputs require a new build.</p>
    {versions.isPending || builds.isPending ? <p role="status">Loading catalog workspace…</p> : null}
    {versions.isError || builds.isError ? <div role="alert">Could not load catalog workspace.
      <button type="button" onClick={() => { void versions.refetch(); void builds.refetch(); }}>Retry workspace</button></div> : null}
    <label>Saved policy version <select value={version || String(versions.data?.[0]?.version ?? '')} disabled={create.isPending}
      onChange={event => { setVersion(event.target.value); create.reset(); }}>
      {!versions.data?.length ? <option value="">No saved policy</option> : null}
      {versions.data?.map(item => <option key={item.version} value={item.version}>Version {item.version}</option>)}
    </select></label>
    <button type="button" disabled={!selectedVersion || !versions.isSuccess || !builds.isSuccess || create.isPending || builds.data.some(build => running(build.status))}
      onClick={() => create.mutate()}>Build review catalog</button>
    <button type="button" onClick={() => { void builds.refetch(); if (selectedBuild) void members.refetch(); }}>Refresh progress</button>
    {create.isPending ? <p role="status">Requesting build…</p> : null}
    {create.isError ? <p role="alert">Build request failed: {create.error.message}. Retrying the same version reuses the request ID.</p> : null}
    {cancel.isError ? <p role="alert">Could not cancel build: {cancel.error.message}</p> : null}
    {builds.data?.length === 0 ? <p>No catalog builds yet.</p> : null}
    <ul>{builds.data?.map(build => <li key={build.id}>
      Policy {build.policyVersion}: {build.status} — {build.scanned} scanned, {build.matched} selected.
      {build.lastError ? <span> {build.lastError === 'INPUTS_CHANGED' ? 'Inputs changed. Start a new build.' : 'Batch failed. Worker retries are bounded; inspect status before rebuilding.'}</span> : null}
      <button type="button" onClick={() => { setSelectedBuild(build.id); setAfter(null); }}>Inspect policy {build.policyVersion} build</button>
      {running(build.status) ? <button type="button" disabled={cancel.isPending} onClick={() => cancel.mutate(build.id)}>Cancel policy {build.policyVersion} build</button> : null}
    </li>)}</ul>
    {selectedBuild ? <section aria-label="Selected catalog members">
      <h3>Selected records (review only)</h3>
      <p>Partial builds may have incomplete membership. READY means the scan completed, not that the catalog is active or still current.</p>
      {selectedStatus === 'READY' ? <><InputFreshness key={`inputs:${tenantId}:${selectedBuild}`} tenantId={tenantId} buildId={selectedBuild} />
        <ActivationReview key={`activation:${tenantId}:${selectedBuild}`} tenantId={tenantId} buildId={selectedBuild} />
        <OrgCveImpact key={`org-cves:${tenantId}:${selectedBuild}`} tenantId={tenantId} buildId={selectedBuild} />
        <FindingImpact key={`findings:${tenantId}:${selectedBuild}`} tenantId={tenantId} buildId={selectedBuild} /></> : null}
      {members.isPending ? <p role="status">Loading selected records…</p> : null}
      {members.isError ? <p role="alert">Could not load records: {members.error.message}</p> : null}
      {members.data?.length === 0 ? <p>No records on this page.</p> : null}
      <ul>{members.data?.map(member => <li key={member.vulnerabilityId}>{member.externalId} — {member.reason === 'MANUAL_INCLUDE' ? 'Manually included' : 'Policy match'}
        {member.withdrawn ? ' (now withdrawn)' : ''}
        <button type="button" onClick={() => { setRecord(member.vulnerabilityId); setRecordInput(member.vulnerabilityId); }}>Manage {member.externalId}</button>
      </li>)}</ul>
      <button type="button" disabled={!after || members.isFetching} onClick={() => setAfter(null)}>First records</button>
      <button type="button" disabled={members.data?.length !== 100 || members.isFetching}
        onClick={() => setAfter(members.data?.[members.data.length - 1]?.vulnerabilityId ?? null)}>Next records</button>
    </section> : null}
    <h3>Manual inclusions and exclusions</h3>
    <p>Select a record above or enter its central record UUID. Overrides affect preview and new builds, not existing findings.</p>
    <form onSubmit={event => { event.preventDefault(); setRecord(recordInput.trim()); }}>
      <label>Central record UUID <input value={recordInput} required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        onChange={event => setRecordInput(event.target.value)} /></label>
      <button type="submit">Load override history</button>
    </form>
    {record ? <CatalogOverrideEditor key={`${tenantId}:${record}`} tenantId={tenantId} recordId={record} /> : null}
  </section>;
}

function ActivationReview({ tenantId, buildId }: { tenantId: string; buildId: string }) {
  const review = useQuery({ queryKey: ['catalog-activation-readiness', tenantId, buildId], enabled: false,
    queryFn: () => apiRequest<ActivationReadiness>(`${root}/builds/${buildId}/activation-readiness`) });
  return <section aria-label="Activation readiness review">
    <button type="button" disabled={review.isFetching} onClick={() => { void review.refetch(); }}>Check activation readiness</button>
    {review.isFetching ? <p role="status">Checking cutover prerequisites…</p> : null}
    {review.isError ? <p role="alert">Could not check activation readiness: {review.error.message}</p> : null}
    {review.data && !review.isError && !review.isFetching ? <div role="status">
      <p>Activation is unavailable. {review.data.localChecksPass ? 'Local build checks pass, but release qualification remains open.'
        : 'Local build checks need attention before cutover.'}</p>
      <p>Blockers: {review.data.blockers.join(', ')}. This check does not activate a catalog or change findings.</p>
    </div> : null}
  </section>;
}

function OrgCveImpact({ tenantId, buildId }: { tenantId: string; buildId: string }) {
  const comparison = useQuery({ queryKey: ['catalog-org-cve-comparison', tenantId, buildId], enabled: false,
    queryFn: () => apiRequest<OrgCveComparison>(`${root}/builds/${buildId}/org-cve-comparison`) });
  return <div>
    <button type="button" disabled={comparison.isFetching} onClick={() => { void comparison.refetch(); }}>Compare organization CVE records</button>
    {comparison.isFetching ? <p role="status">Counting organization CVE records…</p> : null}
    {comparison.isError ? <p role="alert">Could not compare organization CVE records: {comparison.error.message}. Build inputs may have changed.</p> : null}
    {comparison.data && !comparison.isError && !comparison.isFetching ? <p role="status">
      {comparison.data.existingOrgCveRecords} existing organization CVE records; {comparison.data.overlappingRecords} overlap this selection;
      {' '}{comparison.data.orgCveRecordsOutsideSelection} existing records fall outside; {comparison.data.selectedWithoutOrgCveRecord} selected records have no organization CVE row.
      {' '}These materialized rows are not a complete legacy eligibility baseline. This comparison does not change them or activate the catalog.
    </p> : null}
    <OrgCveDifferences buildId={buildId} />
  </div>;
}

function OrgCveDifferences({ buildId }: { buildId: string }) {
  const [direction, setDirection] = useState<DifferenceDirection>('ORG_OUTSIDE_SELECTION');
  const [after, setAfter] = useState<string | null>(null);
  const page = useMutation({ mutationFn: async (request: { direction: DifferenceDirection; after: string | null }) => ({
    ...await apiRequest<DifferencePage>(`${root}/builds/${buildId}/org-cve-differences?direction=${request.direction}${request.after ? `&afterId=${request.after}` : ''}`),
    requestedAfter: request.after
  }) });
  const current = page.isSuccess && page.data.direction === direction && page.data.requestedAfter === after;
  return <div>
    <label>Difference type <select value={direction} onChange={event => {
      setDirection(event.target.value as DifferenceDirection); setAfter(null); page.reset();
    }}>
      <option value="ORG_OUTSIDE_SELECTION">Existing organization CVEs outside selection</option>
      <option value="SELECTED_WITHOUT_ORG">Selected CVEs without organization record</option>
    </select></label>
    <button type="button" disabled={page.isPending} onClick={() => { setAfter(null); page.mutate({ direction, after: null }); }}>Inspect differences</button>
    {page.isPending ? <p role="status">Loading up to 50 differences…</p> : null}
    {page.isError ? <p role="alert">Could not load differences: {page.error.message}. Build inputs may have changed.</p> : null}
    {current ? <><p>Showing {page.data.records.length} observed differences on this page; these rows do not prove legacy eligibility parity.</p>
      <ul>{page.data.records.map(record => <li key={record.vulnerabilityId}>{record.externalId} — {record.vulnerabilityId}</li>)}</ul>
      <button type="button" disabled={!after || page.isPending} onClick={() => { setAfter(null); page.mutate({ direction, after: null }); }}>First differences</button>
      <button type="button" disabled={page.data.complete || !page.data.nextAfterId || page.isPending} onClick={() => {
        const next = page.data.nextAfterId; setAfter(next); page.mutate({ direction, after: next });
      }}>Next differences</button>
    </> : null}
  </div>;
}

function LegacySettingsReview({ tenantId }: { tenantId: string }) {
  const report = useQuery({ queryKey: ['catalog-legacy-compatibility', tenantId], enabled: false,
    queryFn: () => apiRequest<LegacyCompatibility>(`${root}/legacy-compatibility`) });
  return <section aria-label="Legacy source settings review">
    <h3>Legacy source settings</h3>
    <p>Check which existing source settings cannot be expressed by a catalog policy before planning a migration. This check does not change settings or create a policy.</p>
    <button type="button" disabled={report.isFetching} onClick={() => { void report.refetch(); }}>Check legacy settings</button>
    {report.isFetching ? <p role="status">Checking legacy settings…</p> : null}
    {report.isError ? <p role="alert">Could not check legacy settings: {report.error.message}</p> : null}
    {report.data && !report.isError && !report.isFetching ? <div role="status">
      <p>Enabled source preferences: {report.data.enabledSources.join(', ') || 'none'}.</p>
      {report.data.gaps.length ? <><p>These settings need manual review; a catalog policy does not preserve them:</p>
        <ul>{report.data.gaps.map((gap, index) => <li key={`${gap.source}:${index}`}>{gap.source || 'Unknown source'} — {gap.reason === 'SOURCE_ALIAS_NOT_APPLIED'
          ? `saved alias is not applied to the ${gap.canonicalSource || 'canonical'} preference; review it manually`
          : gap.reason}{gap.fields.length ? ` (${gap.fields.join(', ')})` : ''}</li>)}</ul></>
        : <p>No configured filter gaps were found. This does not prove equivalent tenant membership or authorize activation.</p>}
    </div> : null}
  </section>;
}

function InputFreshness({ tenantId, buildId }: { tenantId: string; buildId: string }) {
  const status = useQuery({ queryKey: ['catalog-build-input-status', tenantId, buildId], enabled: false,
    queryFn: () => apiRequest<InputStatus>(`${root}/builds/${buildId}/input-status`) });
  return <div>
    <button type="button" disabled={status.isFetching} onClick={() => { void status.refetch(); }}>Check build inputs</button>
    {status.isFetching ? <p role="status">Checking build inputs…</p> : null}
    {status.isError ? <p role="alert">Could not check build inputs: {status.error.message}</p> : null}
    {status.data && !status.isError && !status.isFetching ? <>
      <p role={status.data.current ? 'status' : 'alert'}>
        {status.data.current ? 'At the last check, build inputs matched. Recheck before review; this does not activate the catalog or certify source coverage.'
          : 'At the last check, build inputs had changed. Start a new review build before comparing or considering activation.'}
      </p>
      {!status.data.latestPolicy ? <p role="alert">This build uses saved policy version {status.data.policyVersion}, but version {status.data.latestPolicyVersion} is now latest. Review the intended version before any future activation.</p> : null}
    </> : null}
  </div>;
}

function FindingImpact({ tenantId, buildId }: { tenantId: string; buildId: string }) {
  const comparison = useQuery({ queryKey: ['catalog-finding-comparison', tenantId, buildId], enabled: false,
    queryFn: () => apiRequest<FindingComparison>(`${root}/builds/${buildId}/finding-comparison`) });
  return <div>
    <button type="button" disabled={comparison.isFetching} onClick={() => { void comparison.refetch(); }}>Compare with existing findings</button>
    {comparison.isFetching ? <p role="status">Counting existing findings…</p> : null}
    {comparison.isError ? <p role="alert">Could not compare findings: {comparison.error.message}. Build inputs may have changed.</p> : null}
    {comparison.data && !comparison.isError && !comparison.isFetching ? <p role="status">{comparison.data.selectedRecords} selected records. {comparison.data.existingFindingRows} existing finding rows reference central records;
      {' '}{comparison.data.findingRowsOutsideSelection} rows across {comparison.data.distinctRecordsOutsideSelection} records are outside this selection.
      {' '}{comparison.data.unlinkedFindingRows} other finding rows have no central vulnerability link and cannot be compared.
      {' '}Status: {comparison.data.openOutsideSelection} open, {comparison.data.suppressedOutsideSelection} suppressed,
      {' '}{comparison.data.resolvedOutsideSelection} resolved, {comparison.data.autoClosedOutsideSelection} auto-closed.
      This is a review count; existing findings remain unchanged.</p> : null}
  </div>;
}

function CatalogOverrideEditor({ tenantId, recordId }: { tenantId: string; recordId: string }) {
  const client = useQueryClient();
  const [operation, setOperation] = useState('EXCLUDE');
  const [reason, setReason] = useState('');
  const [expiry, setExpiry] = useState('');
  const history = useQuery({ queryKey: ['catalog-overrides', tenantId, recordId],
    queryFn: () => apiRequest<Override[]>(`${root}/overrides/${recordId}`) });
  const save = useMutation({ mutationFn: () => apiRequest<Override>(`${root}/overrides/${recordId}`, { method: 'POST', body: JSON.stringify({
    expectedRevision: history.data?.[0]?.revision ?? 0, operation, reason: reason.trim(),
    expiresAt: operation !== 'RESTORE' && expiry ? new Date(expiry).toISOString() : null
  }) }), onSuccess: async () => { await client.invalidateQueries({ queryKey: ['catalog-overrides', tenantId, recordId] }); } });
  return <section aria-label="Override editor">
    {history.isPending ? <p role="status">Loading override history…</p> : null}
    {history.isError ? <p role="alert">Could not load override history: {history.error.message}</p> : null}
    <button type="button" disabled={save.isPending} onClick={() => { void history.refetch(); }}>Reload override history</button>
    <form onChange={() => save.reset()} onSubmit={event => { event.preventDefault(); save.mutate(); }}>
      <fieldset disabled={save.isPending || !history.isSuccess || history.isFetching}>
        <legend>Record an override</legend>
        <label>Operation <select value={operation} onChange={event => setOperation(event.target.value)}>
          <option value="EXCLUDE">Exclude from selection</option><option value="INCLUDE">Include in selection</option>
          <option value="RESTORE">Restore policy selection</option>
        </select></label>
        <label>Reason <textarea required maxLength={500} value={reason} onChange={event => setReason(event.target.value)} /></label>
        {operation !== 'RESTORE' ? <label>Optional expiry (local time) <input type="datetime-local" value={expiry} onChange={event => setExpiry(event.target.value)} /></label> : null}
        <button type="submit" disabled={!reason.trim() || (operation === 'RESTORE' && !history.data?.length)}>Save override</button>
      </fieldset>
    </form>
    {save.isError ? <p role="alert">Override failed: {save.error.message}. Reload history before retrying a conflict.</p> : null}
    {save.isSuccess ? <p role="status">Override saved. Restart preview or build a new catalog to see its effect.</p> : null}
    {history.data?.length === 0 ? <p>No override history for this record.</p> : null}
    <details><summary>Recent override history (up to 100)</summary><ol>{history.data?.map(entry => <li key={entry.revision}>
      Revision {entry.revision}: {entry.operation} — {entry.reason} · {new Date(entry.createdAt).toLocaleString()}
      {entry.expiresAt ? ` · Expires ${new Date(entry.expiresAt).toLocaleString()}` : ''}
    </li>)}</ol></details>
  </section>;
}
