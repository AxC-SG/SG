import React from 'react';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../../components/DataTable';
import { EolBadge } from '../../components/EolBadge';
import type {
  InventoryComponentRecord
} from './api-types';
import {
  buildHostReviewLabels,
  formatAssetType,
  formatInventorySourceSystem
} from './helpers';
import type { InventoryViewKey } from './types';

type Props = {
  selectedView: InventoryViewKey;
  error: string;
  loading: boolean;
  rows: InventoryComponentRecord[];
  componentPage: number;
  componentTotalPages: number;
  selectedHostAssetId: string | null;
  onOpenHostDetail: (assetId: string) => void;
  onPreviousComponentPage: () => void;
  onNextComponentPage: () => void;
};

const COMPONENT_COLUMNS: DataTableColumn[] = [
  { id: 'component', label: 'Component', header: 'Component', initialSize: 180 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 140 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 220 },
  { id: 'ecosystem', label: 'Ecosystem', header: 'Ecosystem', initialSize: 140 },
  { id: 'cves', label: 'CVEs', header: 'CVEs', initialSize: 180 },
  { id: 'group', label: 'Group', header: 'Group', initialSize: 160 },
  { id: 'normalizedName', label: 'Normalized Name', header: 'Normalized Name', initialSize: 180 },
  { id: 'normalizedVersion', label: 'Normalized Version', header: 'Normalized Version', initialSize: 160 },
  { id: 'license', label: 'License', header: 'License', initialSize: 160 },
  { id: 'scope', label: 'Scope', header: 'Scope', initialSize: 120 },
  { id: 'softwareIdentity', label: 'Software Identity', header: 'Software Identity', initialSize: 180 },
  { id: 'review', label: 'Review', header: 'Review', initialSize: 200 },
  { id: 'eolStatus', label: 'EOL Status', header: 'EOL Status', initialSize: 160 },
  { id: 'componentStatus', label: 'Component Status', header: 'Component Status', initialSize: 140 },
  { id: 'purl', label: 'PURL', header: 'PURL', initialSize: 220 },
  { id: 'assetType', label: 'Asset Type', header: 'Asset Type', initialSize: 120, defaultHidden: true },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 180, defaultHidden: true },
  { id: 'uploaded', label: 'Uploaded', header: 'Uploaded', initialSize: 180, defaultHidden: true },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180, defaultHidden: true }
];

const FILTERABLE_COLUMNS = ['component', 'group', 'version', 'ecosystem', 'license', 'scope', 'purl'] as const;
type FilterableColumn = typeof FILTERABLE_COLUMNS[number];

type ColumnFilters = Record<FilterableColumn, string>;

const EMPTY_FILTERS: ColumnFilters = {
  component: '',
  group: '',
  version: '',
  ecosystem: '',
  license: '',
  scope: '',
  purl: ''
};

const FILTER_LABELS: Record<FilterableColumn, string> = {
  component: 'Component',
  group: 'Group',
  version: 'Version',
  ecosystem: 'Ecosystem',
  license: 'License',
  scope: 'Scope',
  purl: 'PURL'
};

function formatDateTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : '-';
}

function buildComponentRows(
  selectedView: InventoryViewKey,
  rows: InventoryComponentRecord[],
  selectedHostAssetId: string | null,
  onOpenHostDetail: (assetId: string) => void
): DataTableRow[] {
  return rows.map((row) => ({
    id: row.id,
    rowProps: {
      className: selectedView === 'hosts' && row.assetId === selectedHostAssetId ? 'table-row-selected' : undefined
    },
    cells: {
      asset: {
        content: (
          <>
            {selectedView === 'hosts' ? (
              <button
                type="button"
                className="btn-link"
                onClick={() => onOpenHostDetail(row.assetId)}
              >
                {row.assetName}
              </button>
            ) : (
              <div>{row.assetName}</div>
            )}
            <div className="panel-caption mono">{row.assetIdentifier}</div>
            {selectedView === 'hosts' && (
              <div className="panel-caption">Open host detail</div>
            )}
          </>
        )
      },
      assetType: { content: formatAssetType(row.assetType) },
      component: { content: row.packageName },
      group: { content: row.packageGroup || '-', props: { className: 'mono' } },
      normalizedName: { content: row.normalizedName || '-', props: { className: 'mono' } },
      version: { content: row.version, props: { className: 'mono' } },
      normalizedVersion: { content: row.normalizedVersion || '-', props: { className: 'mono' } },
      ecosystem: { content: row.ecosystem || '-' },
      license: { content: row.license || '-' },
      scope: {
        content: row.scope
          ? <span className="status-pill status-auto_closed">{row.scope}</span>
          : '-'
      },
      softwareIdentity: { content: row.softwareIdentity || '-' },
      cves: {
        content: row.cveCount > 0 ? (
          <>
            <div>{row.cveCount} correlated CVE{row.cveCount === 1 ? '' : 's'}</div>
            {row.impactedCveCount > 0 && (
              <div className="panel-caption">{row.impactedCveCount} impacted</div>
            )}
            {row.cveIds.length > 0 && (
              <div className="panel-caption mono">{row.cveIds.join(', ')}</div>
            )}
          </>
        ) : (
          '-'
        )
      },
      review: {
        content: row.needsReview ? (
          <>
            <div className="panel-caption">
              {row.reviewItemCount} review item{row.reviewItemCount === 1 ? '' : 's'}
            </div>
            <div className="findings-inline-pill-row">
              {buildHostReviewLabels(row).map((label) => (
                <span key={`${row.id}-${label}`} className="status-pill status-in-progress">
                  {label}
                </span>
              ))}
            </div>
          </>
        ) : (
          <span className="status-pill status-suppressed">Clear</span>
        )
      },
      eolStatus: {
        content: (
          <EolBadge
            isEol={row.isEol}
            daysRemaining={row.eolDaysRemaining}
            eolDate={row.eolDate}
          />
        )
      },
      componentStatus: {
        content: (
          <span className={`status-pill ${row.componentStatus === 'ACTIVE' ? 'status-open' : 'status-auto_closed'}`}>
            {row.componentStatus}
          </span>
        )
      },
      purl: { content: row.purl || '-', props: { className: 'mono' } },
      source: {
        content: (
          <>
            <div>{row.sourceSystem ? formatInventorySourceSystem(row.sourceSystem) : '-'}</div>
            <div className="panel-caption">
              {row.sourceReference || row.sourceType || '-'}
            </div>
          </>
        )
      },
      uploaded: { content: formatDateTime(row.uploadedAt) },
      lastObserved: { content: formatDateTime(row.lastObservedAt) }
    }
  }));
}

function applyFilters(rows: InventoryComponentRecord[], filters: ColumnFilters): InventoryComponentRecord[] {
  return rows.filter((row) => {
    const checks: [FilterableColumn, string | undefined][] = [
      ['component', row.packageName],
      ['group', row.packageGroup],
      ['version', row.version],
      ['ecosystem', row.ecosystem],
      ['license', row.license],
      ['scope', row.scope],
      ['purl', row.purl]
    ];
    return checks.every(([col, value]) => {
      const filter = filters[col].trim().toLowerCase();
      if (!filter) return true;
      return (value ?? '').toLowerCase().includes(filter);
    });
  });
}

export function InventoryResultsPanel({
  selectedView,
  error,
  loading,
  rows,
  componentPage,
  componentTotalPages,
  selectedHostAssetId,
  onOpenHostDetail,
  onPreviousComponentPage,
  onNextComponentPage
}: Props) {
  const [filters, setFilters] = React.useState<ColumnFilters>(EMPTY_FILTERS);

  const tableColumns = React.useMemo(
    () => COMPONENT_COLUMNS.filter((column) => selectedView === 'hosts' || column.id !== 'review'),
    [selectedView]
  );

  const filteredRows = React.useMemo(
    () => applyFilters(rows, filters),
    [rows, filters]
  );

  const tableRows = React.useMemo(
    () => buildComponentRows(selectedView, filteredRows, selectedHostAssetId, onOpenHostDetail),
    [onOpenHostDetail, filteredRows, selectedHostAssetId, selectedView]
  );

  const hasActiveFilters = FILTERABLE_COLUMNS.some((col) => filters[col].trim() !== '');

  function handleFilterChange(col: FilterableColumn, value: string) {
    setFilters((prev) => ({ ...prev, [col]: value }));
  }

  function clearFilters() {
    setFilters(EMPTY_FILTERS);
  }

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>Component Inventory Records</h3>
        <span className="panel-caption">
          Inventory records are normalized and persisted consistently across application, container-image, and host inventory views.
        </span>
      </div>

      <div className="inventory-filter-row">
        {FILTERABLE_COLUMNS.map((col) => (
          <div key={col} className="inventory-filter-field">
            <label className="panel-caption" htmlFor={`filter-${col}`}>
              {FILTER_LABELS[col]}
            </label>
            <input
              id={`filter-${col}`}
              type="text"
              className="filter-input"
              placeholder={`Filter ${FILTER_LABELS[col].toLowerCase()}…`}
              value={filters[col]}
              onChange={(e) => handleFilterChange(col, e.target.value)}
            />
          </div>
        ))}
        {hasActiveFilters && (
          <div className="inventory-filter-field inventory-filter-clear">
            <label className="panel-caption">&nbsp;</label>
            <button type="button" className="btn btn-secondary btn-sm" onClick={clearFilters}>
              Clear filters
            </button>
          </div>
        )}
      </div>

      {error && <div className="notice error">Failed to load inventory: {error}</div>}

      {loading && rows.length === 0 ? (
        <div className="notice">Loading inventory records...</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">
          <p>
            No inventory records found for this view. Connect an SBOM source from <span className="mono">Connect &gt; Inventory Sources</span>.
          </p>
        </div>
      ) : (
        <>
          {hasActiveFilters && (
            <div className="panel-caption" style={{ padding: '4px 16px' }}>
              Showing {filteredRows.length} of {rows.length} records (filtered)
            </div>
          )}
          <div className="table-scroll">
            <DataTable
              storageKey="inventory-components-table-widths"
              columns={tableColumns}
              rows={tableRows}
            />
          </div>
          <div className="pagination-row">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onPreviousComponentPage}
              disabled={componentPage <= 0 || loading}
            >
              Previous
            </button>
            <span className="panel-caption pagination-caption">
              Page {componentTotalPages === 0 ? 0 : componentPage + 1} of {Math.max(componentTotalPages, 1)}
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onNextComponentPage}
              disabled={loading || componentTotalPages === 0 || componentPage + 1 >= componentTotalPages}
            >
              Next
            </button>
          </div>
        </>
      )}
    </section>
  );
}
