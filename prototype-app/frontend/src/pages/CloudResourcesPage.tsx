import React from 'react';
import { Link } from 'react-router-dom';
import { pathForInventoryHostAsset } from '../app/routes';
import type { CloudResource, CloudResourceFacetValue, CloudResourceFilters } from '../features/connect/types';
import { useCloudResourcesQuery } from '../features/connect/queries';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import { formatTimestamp } from '../lib/time';

const PAGE_SIZE = 50;

const PROVIDER_LABELS: Record<string, string> = { aws: 'AWS', azure: 'Azure', gcp: 'Google Cloud' };

function providerLabel(provider?: string): string {
  return provider ? PROVIDER_LABELS[provider] ?? provider : '—';
}

function typeLabel(value?: string): string {
  if (!value) return '—';
  return value.toLowerCase().split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(' ');
}

type FilterKey = 'provider' | 'accountId' | 'region' | 'resourceType' | 'state';

function FacetSelect({ label, value, options, onChange, format }: {
  label: string;
  value?: string;
  options: CloudResourceFacetValue[];
  onChange: (value: string) => void;
  format?: (value: string) => string;
}) {
  return (
    <label>
      <span>{label}</span>
      <select value={value ?? ''} onChange={(e) => onChange(e.target.value)} aria-label={label}>
        <option value="">All</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {(format ?? ((v: string) => v))(option.value)} ({option.count})
          </option>
        ))}
      </select>
    </label>
  );
}

/** Every cloud-discovered asset, whichever connector found it (AWS, Azure or GCP). */
export function CloudResourcesPage() {
  const [filters, setFilters] = React.useState<CloudResourceFilters>({ page: 0, size: PAGE_SIZE });
  const [search, setSearch] = React.useState('');
  const debouncedSearch = useDebouncedValue(search, 300);
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const query = useCloudResourcesQuery({ ...filters, search: debouncedSearch || undefined });
  const data = query.data;

  const setFilter = (key: FilterKey, value: string) => {
    setFilters((current) => ({ ...current, [key]: value || undefined, page: 0 }));
  };

  const page = data?.page ?? 0;
  const totalPages = data?.totalPages ?? 0;

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>Cloud Resources</h3>
          <span className="panel-caption">
            Compute and platform resources discovered by the AWS, Azure and GCP connectors.
          </span>
        </div>
      </div>

      <div className="form-grid">
        <label>
          <span>Search</span>
          <input
            type="search"
            value={search}
            onChange={(e) => { setSearch(e.target.value); setFilters((c) => ({ ...c, page: 0 })); }}
            placeholder="Name or resource ID"
            aria-label="Search cloud resources"
          />
        </label>
        <FacetSelect label="Provider" value={filters.provider} options={data?.facets.providers ?? []}
                     onChange={(v) => setFilter('provider', v)} format={providerLabel} />
        <FacetSelect label="Account / project" value={filters.accountId} options={data?.facets.accounts ?? []}
                     onChange={(v) => setFilter('accountId', v)} />
        <FacetSelect label="Region" value={filters.region} options={data?.facets.regions ?? []}
                     onChange={(v) => setFilter('region', v)} />
        <FacetSelect label="Resource type" value={filters.resourceType} options={data?.facets.resourceTypes ?? []}
                     onChange={(v) => setFilter('resourceType', v)} format={typeLabel} />
        <FacetSelect label="State" value={filters.state} options={data?.facets.states ?? []}
                     onChange={(v) => setFilter('state', v)} format={typeLabel} />
      </div>

      {query.isError && (
        <div className="notice error" role="alert">
          Unable to load cloud resources. {query.error instanceof Error ? query.error.message : ''}
        </div>
      )}

      {query.isPending && !data ? (
        <p role="status">Loading cloud resources…</p>
      ) : data && data.items.length === 0 ? (
        <div className="empty-state">
          <p>No cloud resources match. Connect AWS or GCP under Connect → Sources to discover them.</p>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Account / project</th>
                <th>Region</th>
                <th>Type</th>
                <th>Size</th>
                <th>State</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map((resource: CloudResource) => (
                <React.Fragment key={resource.id}>
                  <tr>
                    <td>
                      {resource.assetType === 'HOST' ? (
                        <Link to={pathForInventoryHostAsset(resource.id)}>{resource.name}</Link>
                      ) : (
                        <strong>{resource.name}</strong>
                      )}
                      <button
                        type="button"
                        className="btn btn-secondary btn-inline"
                        style={{ marginLeft: 8 }}
                        aria-expanded={expanded === resource.id}
                        aria-label={`Details for ${resource.name}`}
                        onClick={() => setExpanded((current) => current === resource.id ? null : resource.id)}
                      >
                        {expanded === resource.id ? 'Hide' : 'Details'}
                      </button>
                    </td>
                    <td>{providerLabel(resource.provider)}</td>
                    <td>{resource.accountId ?? '—'}</td>
                    <td>{resource.availabilityZone ?? resource.region ?? '—'}</td>
                    <td>{typeLabel(resource.resourceType)}</td>
                    <td>{resource.instanceType ?? '—'}</td>
                    <td><span className={resource.state === 'ACTIVE' ? 'status-pill status-success' : 'status-pill'}>{typeLabel(resource.state)}</span></td>
                    <td>{formatTimestamp(resource.lastSeenAt)}</td>
                  </tr>
                  {expanded === resource.id && (
                    <tr>
                      <td colSpan={8}>
                        <div className="panel-caption">
                          <div><strong>Resource ID:</strong> <span className="mono">{resource.identifier}</span></div>
                          {resource.network && <div><strong>Network:</strong> {resource.network}{resource.subnet ? ` / ${resource.subnet}` : ''}</div>}
                          {resource.createdAt && <div><strong>Created:</strong> {formatTimestamp(resource.createdAt)}</div>}
                          <div>
                            <strong>Labels:</strong>{' '}
                            {Object.keys(resource.labels).length === 0
                              ? 'none'
                              : Object.entries(resource.labels).map(([key, value]) => `${key}=${value}`).join(', ')}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {totalPages > 1 && (
        <div className="button-row section-actions">
          <button type="button" className="btn btn-secondary" disabled={page <= 0}
                  onClick={() => setFilters((c) => ({ ...c, page: page - 1 }))}>Previous</button>
          <span className="panel-caption">Page {page + 1} of {totalPages} · {data?.totalItems} resources</span>
          <button type="button" className="btn btn-secondary" disabled={page + 1 >= totalPages}
                  onClick={() => setFilters((c) => ({ ...c, page: page + 1 }))}>Next</button>
        </div>
      )}
    </section>
  );
}
