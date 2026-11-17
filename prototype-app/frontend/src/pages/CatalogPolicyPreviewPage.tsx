import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiRequest } from '../api/client';

type Rule = { op: string; field?: string; number?: number; flag?: boolean; children?: Rule[] };
type FactEvidence = { observationId: string; sourceSystem: string; sourceRecordId: string; payloadHash: string | null; cvssVersion: string | null };
type Preview = {
  overrideState: string;
  sourceState: string;
  generation: number; scanned: number; matched: number; nextAfterId: string | null; complete: boolean;
  matches: Array<{ id: string; externalId: string; facts: {
    publicationYear: number | null; cvss: number | null; epss: number | null; cisaKev: boolean | null;
  }; attribution: { publicationYear: FactEvidence | null; cvss: FactEvidence | null;
    epss: FactEvidence | null; cisaKev: FactEvidence | null; sourcePresence: FactEvidence | null } }>;
};
type SavedPolicyVersion = { version: number; sha256: string; createdAt: string; policy: unknown };

export function CatalogPolicyPreviewPage({ tenantId }: { tenantId: string }) {
  const [year, setYear] = useState('2020');
  const [score, setScore] = useState('6');
  const [operator, setOperator] = useState('GT');
  const [scoreResolution, setScoreResolution] = useState('MAX_ALLOWED_OBSERVATION_V1');
  const [orKev, setOrKev] = useState(false);
  const [selectionMode, setSelectionMode] = useState<'THRESHOLD' | 'SOURCE_PRESENT'>('THRESHOLD');
  const [includeNonCve, setIncludeNonCve] = useState(false);
  const [sources, setSources] = useState(['nvd']);
  const settings = useQuery({ queryKey: ['catalog-policy-source-settings', tenantId],
    queryFn: () => apiRequest<Array<{ sourceSystem: string; enabledForCorrelation: boolean }>>('/connectors/vulnerability-sources') });
  const queryClient = useQueryClient();
  const versions = useQuery({ queryKey: ['catalog-versions', tenantId],
    queryFn: () => apiRequest<SavedPolicyVersion[]>('/intelligence/catalog-policy/versions') });
  const [result, setResult] = useState<Preview | null>(null);
  const currentPolicy = () => {
    const conjunction: Rule = { op: 'ALL', children: [
      { op: 'GTE', field: 'PUBLICATION_YEAR', number: Number(year) },
      { op: operator, field: 'CVSS', number: Number(score) }
    ] };
    const rule: Rule = selectionMode === 'SOURCE_PRESENT' ? { op: 'SOURCE_PRESENT' }
      : orKev ? { op: 'ANY', children: [conjunction, { op: 'EQ', field: 'CISA_KEV', flag: true }] } : conjunction;
    return { version: 1, sources, includeNonCve, scoreResolution, rule };
  };
  const preview = useMutation({
    mutationFn: (continueScan: boolean) => {
      return apiRequest<Preview>('/intelligence/catalog-policy/preview', { method: 'POST', body: JSON.stringify({
        policy: currentPolicy(),
        afterId: continueScan ? result?.nextAfterId : null,
        expectedGeneration: continueScan ? result?.generation : null,
        expectedOverrideState: continueScan ? result?.overrideState : null,
        expectedSourceState: continueScan ? result?.sourceState : null
      }) });
    },
    onSuccess: setResult,
    onError: () => setResult(null)
  });
  const save = useMutation({
    mutationFn: () => apiRequest<SavedPolicyVersion>('/intelligence/catalog-policy/versions', {
      method: 'POST', body: JSON.stringify({ expectedVersion: versions.data?.[0]?.version ?? 0, policy: currentPolicy() })
    }),
    onSuccess: async () => { await queryClient.invalidateQueries({ queryKey: ['catalog-versions', tenantId] }); }
  });
  const validSources = sources.length > 0 && sources.every(source => settings.data?.some(item => item.sourceSystem === source && item.enabledForCorrelation));

  return <section className="panel">
    <h2>Tenant catalog policy preview</h2>
    <p>Saved versions are immutable drafts for review. Saving does not activate catalog membership or change findings.</p>
    <p>Preview applies current manual exclusions and inclusions. Expired or restored overrides return to policy selection; withdrawn records stay excluded.</p>
    <p>Rules use the earliest publication date, not the CVE identifier year. CVSS uses the selected score mode;
      version-specific modes require explicit version evidence and never fall back to unversioned scores.
      Missing values do not pass comparisons. Missing CISA KEV evidence means unknown.</p>
    {settings.isPending ? <p role="status">Loading tenant sources…</p> : null}
    {settings.isError ? <div role="alert">Could not load tenant sources. <button type="button" onClick={() => { void settings.refetch(); }}>Retry sources</button></div> : null}
    <form onChange={() => { setResult(null); preview.reset(); save.reset(); }} onSubmit={(event) => { event.preventDefault(); preview.mutate(false); }}>
      <fieldset disabled={preview.isPending || save.isPending}>
        <legend>Selection rules</legend>
        <label>Selection mode <select value={selectionMode} onChange={event => setSelectionMode(event.target.value as 'THRESHOLD' | 'SOURCE_PRESENT')}>
          <option value="THRESHOLD">Publication year and CVSS threshold</option>
          <option value="SOURCE_PRESENT">Any CVE with evidence from selected sources</option>
        </select></label>
        {selectionMode === 'SOURCE_PRESENT' ? <p>This mode requires at least one current observation from an enabled selected source. It does not preserve legacy source-specific filters or prove equivalent tenant membership.</p> : <>
        <label>Publication year at least <input type="number" required min="0" max="9999" step="1" value={year} onChange={event => setYear(event.target.value)} /></label>
        <label>CVSS comparison <select value={operator} onChange={event => setOperator(event.target.value)}>
          <option value="GT">Greater than (&gt;)</option><option value="GTE">At least (≥)</option>
        </select></label>
        <label>CVSS threshold <input type="number" required min="0" max="10" step="0.1" value={score} onChange={event => setScore(event.target.value)} /></label>
        <label>CVSS score mode <select value={scoreResolution} onChange={event => setScoreResolution(event.target.value)}>
          <option value="MAX_ALLOWED_OBSERVATION_V1">Maximum reported (legacy, all versions)</option>
          <option value="MAX_ALLOWED_CVSS_V3_1">Maximum explicit CVSS v3.1 only</option>
          <option value="MAX_ALLOWED_CVSS_V4_0">Maximum explicit CVSS v4.0 only</option>
        </select></label>
        <label><input type="checkbox" checked={orKev} onChange={event => setOrKev(event.target.checked)} />OR listed in CISA KEV</label>
        </>}
        <label><input type="checkbox" checked={includeNonCve} onChange={event => setIncludeNonCve(event.target.checked)} />Include non-CVE records</label>
        <fieldset><legend>Allowed evidence sources</legend>
          {settings.data?.map(source => <label key={source.sourceSystem}>
            <input type="checkbox" checked={sources.includes(source.sourceSystem)} disabled={!source.enabledForCorrelation && !sources.includes(source.sourceSystem)}
              onChange={event => setSources(current => event.target.checked ? [...current, source.sourceSystem] : current.filter(value => value !== source.sourceSystem))} />
            {source.sourceSystem}{source.enabledForCorrelation ? '' : ' (disabled for this tenant)'}
          </label>)}
        </fieldset>
        {!validSources ? <p>Select at least one enabled evidence source.</p> : null}
        {selectionMode === 'THRESHOLD' && orKev && !sources.includes('kev') ? <p>Select the KEV source to evaluate the exploitation branch.</p> : null}
        <button type="submit" disabled={!validSources || (selectionMode === 'THRESHOLD' && orKev && !sources.includes('kev'))}>Preview from start</button>
        <button type="button" disabled={!validSources || (selectionMode === 'THRESHOLD' && orKev && !sources.includes('kev')) || !versions.isSuccess || versions.isFetching}
          onClick={(event) => { if (event.currentTarget.form?.reportValidity()) save.mutate(); }}>Save new policy version</button>
      </fieldset>
    </form>
    {save.isPending ? <p role="status">Saving immutable policy version…</p> : null}
    {save.isError ? <p role="alert">Could not save policy version: {save.error.message}</p> : null}
    {save.isSuccess ? <p role="status">Saved policy version {save.data.version}. It is not active.</p> : null}
    {versions.isError ? <p role="alert">Could not load saved policy versions: {versions.error.message}
      <button type="button" onClick={() => { void versions.refetch(); }}>Reload saved versions</button></p> : null}
    {versions.data?.length ? <details><summary>Saved policy versions ({versions.data.length})</summary>
      <ol>{versions.data.map(item => <li key={item.version}>Version {item.version} · {new Date(item.createdAt).toLocaleString()} · SHA-256 {item.sha256}</li>)}</ol>
    </details> : null}
    {preview.isPending ? <p role="status">Evaluating up to 100 published records…</p> : null}
    {preview.isError ? <p role="alert">{preview.error.message} Restart the preview after correcting the error.</p> : null}
    {result ? <div>
      <p role="status">This batch: {result.matched} matched out of {result.scanned} scanned. Published generation {result.generation}.</p>
      <p>{result.complete ? 'End of scan reached. Counts above are for this batch only.' : 'More records remain; these are not full-corpus counts.'}</p>
      <ul>{result.matches.map(match => <li key={match.id}>{match.externalId} — publication year {match.facts.publicationYear ?? 'unknown'},
        CVSS {match.facts.cvss ?? 'unknown'}, CISA KEV {match.facts.cisaKev == null ? 'unknown' : String(match.facts.cisaKev)}
        <details><summary>Fact sources</summary>
          <p>Current observation rows and fingerprints; not immutable source-version history.</p>
          <ul>{(['sourcePresence', 'publicationYear', 'cvss', 'epss', 'cisaKev'] as const).map(field => {
            const evidence = match.attribution?.[field];
            return evidence ? <li key={field}>{field === 'sourcePresence' ? 'Selected-source evidence' : field}: {evidence.sourceSystem} / {evidence.sourceRecordId} · observation <code>{evidence.observationId}</code>
              {field === 'cvss' && evidence.cvssVersion ? ` · CVSS v${evidence.cvssVersion}` : ''}
              {evidence.payloadHash ? ` · fingerprint ${evidence.payloadHash}` : ''}</li> : null;
          })}</ul>
        </details>
      </li>)}</ul>
      {!result.complete ? <button type="button" disabled={preview.isPending} onClick={() => preview.mutate(true)}>Preview next batch</button> : null}
    </div> : null}
  </section>;
}
