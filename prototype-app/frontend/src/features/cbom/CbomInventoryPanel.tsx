import { keepPreviousData, useQuery } from '@tanstack/react-query';
import React from 'react';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { ActiveFilterChips, Pager, ResultScope } from '../../components/QueueControls';
import { CbomContradictionsPanel } from './CbomContradictionsPanel';
import { CbomEvidenceDialog } from './CbomEvidenceDialog';
import { presenceLabel, severityBadgeClass, titleCase } from './labels';
import type { CbomInventoryFilters } from './types';

const PAGE_SIZE = 50;
const ASSET_TYPES = ['ALGORITHM', 'CERTIFICATE', 'PROTOCOL', 'RELATED_CRYPTO_MATERIAL', 'UNKNOWN'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const EVIDENCE_STATES = ['SUPPORTED', 'WITHDRAWN', 'CONFLICTING', 'LEGACY_UNKNOWN'];
const FILTER_LABELS: Record<keyof CbomInventoryFilters, string> = {
  q: 'Search', assetType: 'Asset type', primitive: 'Algorithm', severity: 'Severity', evidenceState: 'Evidence',
  custody: 'Custody', environment: 'Environment', bomId: 'Document',
};

/** Tenant-wide crypto inventory with analyst filters; rows open the evidence drawer. */
export function CbomInventoryPanel({ initialFilters = {}, showContradictions = false, canReview = false }: {
  initialFilters?: CbomInventoryFilters; showContradictions?: boolean; canReview?: boolean;
}) {
  const [filters, setFilters] = React.useState<CbomInventoryFilters>(initialFilters);
  const [draft, setDraft] = React.useState<CbomInventoryFilters>(initialFilters);
  const [page, setPage] = React.useState(0);
  const [selected, setSelected] = React.useState<string | null>(null);

  const query = useQuery({
    queryKey: ['cbom-inventory', filters, page],
    queryFn: () => api.listCbomInventory(filters, page, PAGE_SIZE),
    placeholderData: keepPreviousData,
  });
  const data = query.data;
  const filtered = Object.values(filters).some(Boolean);
  const state = query.isPending ? 'pending'
    : query.isError && !data ? 'error'
      : (data?.items.length ?? 0) === 0 ? (filtered ? 'filtered-empty' : 'empty')
        : 'ready';

  const apply = (next: CbomInventoryFilters) => { setFilters(next); setDraft(next); setPage(0); };
  const update = (key: keyof CbomInventoryFilters) =>
    (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setDraft({ ...draft, [key]: event.target.value || undefined });
  const chips = (Object.keys(filters) as Array<keyof CbomInventoryFilters>)
    .filter((key) => filters[key])
    .map((key) => ({
      key, label: FILTER_LABELS[key], value: key === 'bomId' ? 'This document' : titleCase(filters[key] as string),
      onRemove: () => apply({ ...filters, [key]: undefined }),
    }));

  return (
    <div className="panel cbom-inventory-panel">
      <div className="panel-header">
        <h3>Cryptographic inventory</h3>
        <span className="panel-caption">Active cryptographic assets across every CBOM in this workspace</span>
      </div>
      {showContradictions && <CbomContradictionsPanel canReview={canReview} />}
      <form className="cbom-filter-bar" onSubmit={(event) => { event.preventDefault(); apply(draft); }} aria-label="Filter cryptographic inventory">
        <label>Search<input type="search" value={draft.q ?? ''} onChange={update('q')} placeholder="Name or bom-ref" /></label>
        <label>Asset type
          <select value={draft.assetType ?? ''} onChange={update('assetType')}>
            <option value="">Any</option>
            {ASSET_TYPES.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
          </select>
        </label>
        <label>Algorithm<input value={draft.primitive ?? ''} onChange={update('primitive')} placeholder="e.g. rsa" /></label>
        <label>Open finding severity
          <select value={draft.severity ?? ''} onChange={update('severity')}>
            <option value="">Any</option>
            {SEVERITIES.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
          </select>
        </label>
        <label>Evidence presence
          <select value={draft.evidenceState ?? ''} onChange={update('evidenceState')}>
            <option value="">Any</option>
            {EVIDENCE_STATES.map((value) => <option key={value} value={value}>{titleCase(value)}</option>)}
          </select>
        </label>
        <label>Custody<input value={draft.custody ?? ''} onChange={update('custody')} placeholder="e.g. hsm" /></label>
        <label>Environment<input value={draft.environment ?? ''} onChange={update('environment')} placeholder="e.g. production" /></label>
        <button type="submit" className="btn btn-primary btn-sm">Apply filters</button>
      </form>
      <ActiveFilterChips filters={chips} onClearAll={() => apply({})} />
      <AsyncSection
        state={state}
        loadingLabel="Loading cryptographic inventory…"
        errorMessage="The cryptographic inventory could not be loaded."
        onRetry={() => void query.refetch()}
        retryLabel="Retry cryptographic inventory"
        retrying={query.isFetching}
        emptyMessage="No CBOM has reported cryptographic assets yet. Upload or push a CBOM to populate this inventory."
        filteredEmptyMessage="No cryptographic assets match these filters."
        onClearFilters={() => apply({})}
        isRefreshing={query.isFetching && !query.isPending}
        refreshError={query.isError && data ? 'The latest inventory refresh failed; showing the previous results.' : undefined}
      >
        {data && (
          <>
            <ResultScope offset={data.page * data.size} count={data.items.length} total={data.totalCapped ? null : data.total}
              noun="cryptographic asset" filtered={filtered} />
            {data.totalCapped && <p className="panel-caption">More than {data.total.toLocaleString()} assets match; refine the filters to narrow the list.</p>}
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Name</th><th>Asset type</th><th>Algorithm / parameters</th><th>Custody</th>
                    <th>Asset</th><th>Open findings</th><th>Evidence</th><th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <button type="button" className="btn btn-ghost btn-sm cbom-row-link" onClick={() => setSelected(item.id)}
                          aria-label={`Open evidence for ${item.name}`}>
                          {item.name}
                        </button>
                      </td>
                      <td><span className="tag">{titleCase(item.assetType)}</span></td>
                      <td>{[item.primitive, item.keySize ? `${item.keySize}-bit` : null, item.curve, item.protocolVersion].filter(Boolean).join(' · ') || '—'}</td>
                      <td>{item.storageLocation ?? '—'}</td>
                      <td>{item.assetName ?? '—'}{item.environment ? <span className="panel-caption"> · {item.environment}</span> : null}</td>
                      <td>
                        {item.openFindings === 0 ? '0' : (
                          <><span className={`status-badge ${severityBadgeClass(item.highestSeverity)}`}>{item.highestSeverity}</span> {item.openFindings}</>
                        )}
                      </td>
                      <td>{item.evidenceState ? presenceLabel(item.evidenceState) : '—'}</td>
                      <td>{item.riskScore == null ? '—' : item.riskScore.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={data.page} totalPages={null} hasNext={data.hasNext} disabled={query.isFetching}
              onPrevious={() => setPage((value) => Math.max(0, value - 1))} onNext={() => setPage((value) => value + 1)}
              label="Cryptographic inventory pages" />
          </>
        )}
      </AsyncSection>
      <CbomEvidenceDialog componentId={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
