import React from 'react';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { useSyncRunsQuery } from '../features/connect/queries';
import type { SyncRun } from '../features/connect/types';

// ── helpers ──────────────────────────────────────────────────────────────────

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const s = Math.round((new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000);
  if (Number.isNaN(s) || s < 0) return 'n/a';
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

function formatSyncType(value: string): string {
  const n = value.trim().toUpperCase();
  if (n === 'SERVICENOW_CMDB') return 'ServiceNow CMDB';
  if (n === 'SCCM_CMDB') return 'SCCM / MECM';
  if (n === 'GITHUB_REPOSITORY_SBOM') return 'GitHub Repository SBOM';
  if (n === 'GITHUB_GHCR_SBOM') return 'GitHub GHCR SBOM';
  if (n === 'NVD') return 'NVD';
  if (n === 'KEV') return 'CISA KEV';
  if (n === 'GHSA') return 'GHSA';
  if (n === 'CSAF_MICROSOFT') return 'Microsoft CSAF + VEX';
  if (n === 'CSAF_REDHAT') return 'Red Hat CSAF + VEX';
  if (n === 'ADVISORY') return 'Advisory Imports';
  if (n === 'EOL_CATALOG_REFRESH') return 'EOL Catalog Refresh';
  if (n === 'EOL_RELEASE_REFRESH') return 'EOL Release Refresh';
  if (n === 'EOL_MAPPING_RESOLVE') return 'EOL Mapping Resolve';
  if (n === 'EOL_DENORMALIZE') return 'EOL Denormalize';
  if (n === 'EOL_FULL_REFRESH') return 'EOL Full Refresh';
  if (n === 'EOL_DATE_SWEEP') return 'EOL Date Sweep';
  return value;
}

function formatRunDomain(run: SyncRun): string {
  if (run.runDomain === 'INVENTORY') return 'Inventory';
  if (run.runDomain === 'VULN_INTEL') return 'Vuln Intel';
  if (run.runDomain === 'PROCESSING') return 'Processing';
  return run.runDomain ?? '';
}

function runStatusClass(value: string): string {
  const n = value.trim().toUpperCase();
  if (n === 'FAILED') return 'status-failure';
  if (n === 'PARTIAL_SUCCESS' || n === 'COMPLETED_WITH_ERRORS' || n === 'SUCCESS_WITH_WARNINGS') return 'status-warning';
  if (n === 'COMPLETED') return 'status-success';
  if (n === 'RUNNING' || n === 'STARTED' || n === 'QUEUED') return 'status-open';
  return `status-${value.toLowerCase().replace('_', '-')}`;
}

function formatRunStatus(value: string): string {
  return value.split('_').map((t) => t.charAt(0).toUpperCase() + t.slice(1).toLowerCase()).join(' ');
}

function parseMetadata(json?: string): Record<string, unknown> {
  if (!json?.trim()) return {};
  try { return JSON.parse(json) as Record<string, unknown>; }
  catch { return {}; }
}

function metaNum(meta: Record<string, unknown>, key: string): number | undefined {
  const v = meta[key];
  return typeof v === 'number' ? v : undefined;
}

function totalRecords(run: SyncRun, meta: Record<string, unknown>): string {
  // For inventory runs prefer metadata counts
  const assets = metaNum(meta, 'assetsIngested') ?? metaNum(meta, 'assetsUpserted');
  const rawComponents = metaNum(meta, 'componentsIngested')
    ?? ((metaNum(meta, 'inventoryComponentsCreated') ?? 0) + (metaNum(meta, 'inventoryComponentsUpdated') ?? 0));
  const components = rawComponents > 0 ? rawComponents : undefined;

  if (assets != null || components != null) {
    const parts: string[] = [];
    if (assets != null) parts.push(`${assets.toLocaleString()} assets`);
    if (components != null && components > 0) parts.push(`${components.toLocaleString()} components`);
    return parts.join(' · ') || '-';
  }

  // For vuln intel runs use record counters
  const total = run.recordsInserted + run.recordsUpdated;
  if (total === 0 && run.recordsFetched === 0) return '-';
  const parts: string[] = [];
  if (run.recordsFetched > 0) parts.push(`${run.recordsFetched.toLocaleString()} fetched`);
  if (run.recordsInserted > 0) parts.push(`${run.recordsInserted.toLocaleString()} created`);
  if (run.recordsUpdated > 0) parts.push(`${run.recordsUpdated.toLocaleString()} updated`);
  return parts.join(' · ') || '-';
}

function detailLine(label: string, value?: string | number | null) {
  if (value == null || value === '') return null;
  return (
    <div className="panel-caption" key={label}>
      {label}: {value}
    </div>
  );
}

// ── columns ───────────────────────────────────────────────────────────────────

const COLUMNS: DataTableColumn[] = [
  { id: 'type',      label: 'Type',      header: 'Type',      initialSize: 220 },
  { id: 'status',    label: 'Status',    header: 'Status',    initialSize: 150 },
  { id: 'started',   label: 'Started',   header: 'Started',   initialSize: 190 },
  { id: 'completed', label: 'Completed', header: 'Completed', initialSize: 190 },
  { id: 'duration',  label: 'Duration',  header: 'Duration',  initialSize: 110 },
  { id: 'records',   label: 'Records',   header: 'Records',   initialSize: 260 },
  { id: 'details',   label: 'Details',   header: 'Details',   initialSize: 100 },
];

function buildRows(runs: SyncRun[]): DataTableRow[] {
  return runs.map((run) => {
    const meta = parseMetadata(run.metadataJson);
    return {
      id: run.id,
      cells: {
        type: {
          content: (
            <>
              <div>{formatSyncType(run.syncType)}</div>
              <div className="panel-caption">{formatRunDomain(run)}</div>
            </>
          )
        },
        status: {
          content: (
            <>
              <span className={`status-pill ${runStatusClass(run.status)}`}>
                {formatRunStatus(run.status)}
              </span>
              {run.errorMessage && (
                <div className="panel-caption" style={{ color: 'var(--critical)', marginTop: 2 }}>
                  {run.errorMessage.length > 60 ? run.errorMessage.slice(0, 60) + '…' : run.errorMessage}
                </div>
              )}
            </>
          )
        },
        started:   { content: new Date(run.startedAt).toLocaleString() },
        completed: { content: run.completedAt ? new Date(run.completedAt).toLocaleString() : '—' },
        duration:  { content: humanDuration(run.startedAt, run.completedAt) },
        records:   { content: <span className="panel-caption" style={{ color: 'var(--text)' }}>{totalRecords(run, meta)}</span> },
        details: {
          content: (
            <details className="evidence-details">
              <summary>Details</summary>
              {detailLine('Fetched', run.recordsFetched)}
              {detailLine('Created', run.recordsInserted)}
              {detailLine('Updated', run.recordsUpdated)}
              {detailLine('Failed', run.recordsFailed ?? 0)}
              {detailLine('Assets discovered', metaNum(meta, 'assetsDiscovered'))}
              {detailLine('Assets ingested', metaNum(meta, 'assetsIngested'))}
              {detailLine('Assets upserted', metaNum(meta, 'assetsUpserted'))}
              {detailLine('Assets marked inactive', metaNum(meta, 'assetsMarkedInactive'))}
              {detailLine('Assets failed', metaNum(meta, 'assetsFailed'))}
              {detailLine('Components', metaNum(meta, 'componentsIngested'))}
              {detailLine('SSM assets ingested', metaNum(meta, 'ssmAssetsIngested'))}
              {detailLine('Software created', metaNum(meta, 'softwareInstancesCreated'))}
              {detailLine('Software updated', metaNum(meta, 'softwareInstancesUpdated'))}
              {detailLine('Findings', metaNum(meta, 'findingsGenerated'))}
              {detailLine('Hosts created', metaNum(meta, 'ciCreated'))}
              {detailLine('SW created', metaNum(meta, 'softwareInstancesCreated'))}
              {detailLine('SW updated', metaNum(meta, 'softwareInstancesUpdated'))}
              {detailLine('Error', run.errorMessage)}
            </details>
          )
        }
      }
    };
  });
}

// ── component ─────────────────────────────────────────────────────────────────

type IntegrationRunQueuePageProps = {
  title?: string;
  caption?: string;
  queryParams?: { category?: 'all' | 'inventory' | 'vulnerability' | 'vuln-intel' | 'processing'; limit?: number };
  storageKey?: string;
};

export function IntegrationRunQueuePage({
  title = 'Integration Run Queue',
  caption = 'All integration runs — inventory ingestion, vulnerability intel feeds, and processing jobs.',
  queryParams = { category: 'all', limit: 200 },
  storageKey = 'integration-run-queue-table-widths',
}: IntegrationRunQueuePageProps = {}) {
  const query = useSyncRunsQuery(queryParams);
  const rows = React.useMemo(() => buildRows(query.data ?? []), [query.data]);
  const loading = query.isPending && !query.data;
  const refreshing = query.isFetching;
  const error = query.error instanceof Error ? query.error.message : '';

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>{title}</h3>
          <span className="panel-caption">
            {caption}
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={refreshing}
            onClick={() => void query.refetch()}
          >
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      {loading ? (
        <div className="notice">Loading integration runs…</div>
      ) : rows.length === 0 ? (
        <div className="empty-state">
          <p>No integration runs recorded yet.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey={storageKey}
            columns={COLUMNS}
            rows={rows}
          />
        </div>
      )}
    </section>
  );
}
