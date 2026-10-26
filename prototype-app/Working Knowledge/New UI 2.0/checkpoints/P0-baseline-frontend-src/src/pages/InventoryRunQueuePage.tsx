import React from 'react';
import { Link } from 'react-router-dom';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { useIngestionJobsQuery, useSyncRunsQuery } from '../features/connect/queries';
import type { SyncRun } from '../features/connect/types';
import type { IngestionJob } from '../api/client';

type InventoryRunMetadata = {
  sourceSystem?: string;
  assetType?: string;
  assetsDiscovered?: number;
  assetsIngested?: number;
  assetsUpserted?: number;
  assetsFailed?: number;
  assetsMarkedInactive?: number;
  componentsIngested?: number;
  findingsGenerated?: number;
  triggerMode?: string;
  stage?: string;
  tableName?: string;
  scope?: string;
  installRowsProcessed?: number;
  discoveryRowsProcessed?: number;
  unmatchedDiscoveryRows?: number;
  ciCreated?: number;
  ciAliasesCreated?: number;
  softwareInstancesCreated?: number;
  softwareInstancesUpdated?: number;
  ssmAssetsIngested?: number;
  inventoryComponentsCreated?: number;
  inventoryComponentsUpdated?: number;
  message?: string;
  provider?: string;
  connectorId?: string;
  ingestionJobId?: string;
  accountId?: string;
  awsAccountId?: string;
  subscriptionId?: string;
  subscriptionIds?: string[];
  azureTenantId?: string;
  regions?: string[];
  resourceTypes?: string[];
  families?: string[];
  assetsUpdated?: number;
  subscriptionErrors?: Record<string, string>;
};

const INVENTORY_RUN_COLUMNS: DataTableColumn[] = [
  { id: 'type', label: 'Type', header: 'Type', initialSize: 220 },
  { id: 'status', label: 'Status', header: 'Status', initialSize: 160 },
  { id: 'started', label: 'Started', header: 'Started', initialSize: 180 },
  { id: 'duration', label: 'Duration', header: 'Duration', initialSize: 140 },
  { id: 'assets', label: 'Inventory items', header: 'Inventory items', initialSize: 130 },
  { id: 'components', label: 'Components', header: 'Components', initialSize: 120 },
  { id: 'findings', label: 'Findings', header: 'Findings', initialSize: 100 },
  { id: 'details', label: 'Details', header: 'Details', initialSize: 320 }
];

function parseRunMetadata(value?: string): InventoryRunMetadata {
  if (!value || !value.trim()) return {};
  try {
    return JSON.parse(value) as InventoryRunMetadata;
  } catch {
    return {};
  }
}

function humanDuration(startedAt: string, completedAt?: string): string {
  if (!completedAt) return 'In progress';
  const seconds = Math.round((new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000);
  if (Number.isNaN(seconds) || seconds < 0) return 'n/a';
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function isActiveRun(status: string): boolean {
  const value = status.trim().toUpperCase();
  return value === 'RUNNING' || value === 'STARTED' || value === 'QUEUED';
}

function isInventoryRunType(syncType: string): boolean {
  const normalized = syncType.trim().toUpperCase();
  return normalized.startsWith('GITHUB_')
    || normalized === 'SERVICENOW_CMDB'
    || normalized === 'SCCM_CMDB'
    || normalized === 'AWS_DISCOVERY'
    || normalized === 'AZURE_DISCOVERY'
    || normalized === 'AI_SECURITY_AWS_BEDROCK'
    || normalized === 'AI_SECURITY_AZURE_DISCOVERY'
    || normalized === 'AI_SECURITY_COPILOT_STUDIO';
}

function isInventoryRun(run: SyncRun): boolean {
  return run.runDomain === 'INVENTORY' || isInventoryRunType(run.syncType);
}

function isAiInventoryRun(run: SyncRun): boolean {
  return run.syncType.trim().toUpperCase().startsWith('AI_SECURITY_');
}

function aiJobAsRun(job: IngestionJob): SyncRun {
  const normalizedType = job.jobType.trim().toUpperCase();
  const provider = normalizedType === 'AI_SECURITY_AZURE_DISCOVERY'
    ? 'AZURE'
    : normalizedType === 'AI_SECURITY_COPILOT_STUDIO'
      ? 'MICROSOFT_COPILOT'
      : 'AWS';
  const connectorId = job.assetIdentifier.split(':').slice(1).join(':') || undefined;
  const status = job.status.trim().toUpperCase();
  const message = status === 'QUEUED'
    ? 'Waiting for the AI Security discovery worker to claim this job.'
    : status === 'RUNNING'
      ? 'The AI Security discovery worker is starting this run.'
      : job.failureMessage ?? undefined;
  return {
    id: `ingestion-job-${job.jobId}`,
    syncType: normalizedType,
    runDomain: 'INVENTORY',
    runClass: 'INGESTION',
    status: job.status,
    recordsFetched: 0,
    recordsInserted: 0,
    recordsUpdated: 0,
    recordsFailed: 0,
    startedAt: job.startedAt ?? job.requestedAt,
    completedAt: job.completedAt ?? undefined,
    errorMessage: status === 'FAILED' ? job.failureMessage ?? undefined : undefined,
    metadataJson: JSON.stringify({
      provider,
      connectorId,
      ingestionJobId: job.jobId,
      triggerMode: 'Connector',
      message
    })
  };
}

function hasReplacementSyncRun(job: IngestionJob, syncRuns: SyncRun[]): boolean {
  let resultRunId: string | undefined;
  if (job.resultJson) {
    try {
      const result = JSON.parse(job.resultJson) as { runId?: string };
      resultRunId = result.runId;
    } catch {
      // A malformed result should not hide the ingestion job from operators.
    }
  }
  if (resultRunId && syncRuns.some((run) => run.id === resultRunId)) return true;

  const connectorId = job.assetIdentifier.split(':').slice(1).join(':');
  if (!connectorId) return false;
  const requestedAt = new Date(job.requestedAt).getTime();
  return syncRuns.some((run) => {
    if (run.syncType.trim().toUpperCase() !== job.jobType.trim().toUpperCase()) return false;
    const metadata = parseRunMetadata(run.metadataJson);
    return metadata.connectorId === connectorId
      && new Date(run.startedAt).getTime() >= requestedAt;
  });
}

function queueLabel(run: SyncRun): string {
  if (!isActiveRun(run.status) || run.queuePosition == null) return '-';
  return run.queuePosition === 1 ? 'Running now' : `#${run.queuePosition}`;
}

function formatSourceSystem(value?: string): string {
  if (!value || value.trim().length === 0) return 'Unknown';
  const normalized = value.trim().toLowerCase();
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub';
  if (normalized === 'servicenow') return 'ServiceNow';
  return value;
}

function formatSyncType(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (normalized === 'AWS_DISCOVERY') return 'AWS Cloud Discovery';
  if (normalized === 'AZURE_DISCOVERY') return 'Azure Cloud Discovery';
  if (normalized === 'AI_SECURITY_AWS_BEDROCK') return 'AWS AI Discovery';
  if (normalized === 'AI_SECURITY_AZURE_DISCOVERY') return 'Azure AI Discovery';
  if (normalized === 'AI_SECURITY_COPILOT_STUDIO') return 'Microsoft Copilot Discovery';
  if (normalized === 'SERVICENOW_CMDB') return 'ServiceNow CMDB Live Sync';
  if (normalized === 'GITHUB_REPOSITORY_SBOM') return 'GitHub Repository SBOM';
  if (normalized === 'GITHUB_GHCR_SBOM') return 'GitHub GHCR SBOM';
  return value;
}

function formatRunStatus(value: string): string {
  return value
    .split('_')
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1).toLowerCase())
    .join(' ');
}

function runStatusClass(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (normalized === 'FAILED') return 'status-failure';
  if (normalized === 'PARTIAL' || normalized === 'PARTIAL_SUCCESS' || normalized === 'COMPLETED_WITH_ERRORS' || normalized === 'SUCCESS_WITH_WARNINGS') return 'status-warning';
  if (normalized === 'COMPLETED') return 'status-success';
  if (normalized === 'RUNNING' || normalized === 'STARTED') return 'status-open';
  if (normalized === 'QUEUED') return 'status-open';
  return `status-${value.toLowerCase().replace('_', '-')}`;
}

function formatCount(value?: number): string {
  return value == null ? '-' : String(value);
}

function readAssetsIngested(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  const metadataCount = metadata.assetsIngested ?? metadata.assetsUpserted;
  if (metadataCount != null) return metadataCount;
  if (run.syncType.trim().toUpperCase().startsWith('AI_SECURITY_')) {
    return run.recordsInserted;
  }
  return undefined;
}

function readComponentsIngested(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  if (metadata.componentsIngested != null) {
    return metadata.componentsIngested;
  }
  if (metadata.inventoryComponentsCreated != null || metadata.inventoryComponentsUpdated != null) {
    return (metadata.inventoryComponentsCreated ?? 0) + (metadata.inventoryComponentsUpdated ?? 0);
  }
  const normalizedType = run.syncType.trim().toUpperCase();
  if (normalizedType.startsWith('GITHUB_') && run.recordsInserted > 0) {
    return run.recordsInserted;
  }
  return undefined;
}

function readFindingsGenerated(run: SyncRun, metadata: InventoryRunMetadata): number | undefined {
  if (metadata.findingsGenerated != null) {
    return metadata.findingsGenerated;
  }
  const normalizedType = run.syncType.trim().toUpperCase();
  if (normalizedType.startsWith('GITHUB_') && run.recordsUpdated > 0) {
    return run.recordsUpdated;
  }
  return undefined;
}

function detailLine(label: string, value?: string | number | null) {
  if (value == null || value === '') {
    return null;
  }
  return (
    <div className="panel-caption" key={label}>
      {label}: {value}
    </div>
  );
}

function buildRunRows(runs: SyncRun[]): DataTableRow[] {
  return runs.map((run) => {
    const metadata = parseRunMetadata(run.metadataJson);

    return {
      id: run.id,
      cells: {
        type: {
          content: (
            <>
              <div>
                {isAiInventoryRun(run) ? (
                  <Link to="/inventory/ai">{formatSyncType(run.syncType)}</Link>
                ) : formatSyncType(run.syncType)}
              </div>
              <div className="panel-caption">
                {formatSourceSystem(metadata.sourceSystem ?? metadata.provider)}
              </div>
            </>
          )
        },
        status: {
          content: (
            <>
              <span className={`status-pill ${runStatusClass(run.status)}`}>
                {formatRunStatus(run.status)}
              </span>
              {isActiveRun(run.status) && run.queuePosition != null && (
                <div className="panel-caption">{queueLabel(run)}</div>
              )}
            </>
          )
        },
        started: { content: new Date(run.startedAt).toLocaleString() },
        duration: { content: humanDuration(run.startedAt, run.completedAt) },
        assets: { content: formatCount(readAssetsIngested(run, metadata)) },
        components: { content: formatCount(readComponentsIngested(run, metadata)) },
        findings: { content: formatCount(readFindingsGenerated(run, metadata)) },
        details: {
          content: (
            <details className="evidence-details">
              <summary>Details</summary>
              {detailLine('Trigger', metadata.triggerMode)}
              {detailLine('Provider', metadata.provider)}
              {detailLine('Connector ID', metadata.connectorId)}
              {detailLine('Ingestion job ID', metadata.ingestionJobId)}
              {detailLine('AWS account', metadata.accountId ?? metadata.awsAccountId)}
              {detailLine('Azure tenant', metadata.azureTenantId)}
              {detailLine('Azure subscription', metadata.subscriptionId)}
              {detailLine('Azure subscriptions', metadata.subscriptionIds?.join(', '))}
              {detailLine('Regions', metadata.regions?.join(', '))}
              {detailLine('Resource types', metadata.resourceTypes?.join(', '))}
              {detailLine('Resource families', metadata.families?.join(', '))}
              {detailLine('Scope', metadata.scope)}
              {detailLine('Stage', metadata.stage)}
              {detailLine('Table', metadata.tableName)}
              {detailLine('Assets discovered', metadata.assetsDiscovered)}
              {detailLine('Assets ingested', metadata.assetsIngested)}
              {detailLine('Assets upserted', metadata.assetsUpserted)}
              {detailLine('Assets updated', metadata.assetsUpdated)}
              {detailLine('Assets marked inactive', metadata.assetsMarkedInactive)}
              {detailLine('Assets failed', metadata.assetsFailed)}
              {detailLine('AI artifacts observed', isAiInventoryRun(run) ? run.recordsFetched : null)}
              {detailLine('Fetched', run.recordsFetched)}
              {detailLine('Failed', run.recordsFailed ?? 0)}
              {detailLine('Inserted', run.recordsInserted)}
              {detailLine('Updated', run.recordsUpdated)}
              {detailLine('Install rows', metadata.installRowsProcessed)}
              {detailLine('Discovery rows', metadata.discoveryRowsProcessed)}
              {detailLine('Unmatched discovery', metadata.unmatchedDiscoveryRows)}
              {detailLine('Hosts created', metadata.ciCreated)}
              {detailLine('Aliases created', metadata.ciAliasesCreated)}
              {detailLine('SSM assets ingested', metadata.ssmAssetsIngested)}
              {detailLine('Software created', metadata.softwareInstancesCreated)}
              {detailLine('Software updated', metadata.softwareInstancesUpdated)}
              {detailLine('Components created', metadata.inventoryComponentsCreated)}
              {detailLine('Components updated', metadata.inventoryComponentsUpdated)}
              {detailLine('Findings generated', metadata.findingsGenerated)}
              {detailLine('Completed', run.completedAt ? new Date(run.completedAt).toLocaleString() : null)}
              {detailLine('Message', metadata.message)}
              {detailLine(
                'Subscription errors',
                metadata.subscriptionErrors
                  ? Object.values(metadata.subscriptionErrors).join(' | ')
                  : null
              )}
              {detailLine('Error', run.errorMessage)}
            </details>
          )
        }
      }
    };
  });
}

export function InventoryRunQueuePage() {
  const inventoryRunsQuery = useSyncRunsQuery({ category: 'inventory', limit: 100 });
  const ingestionJobsQuery = useIngestionJobsQuery();
  const inventoryRuns = React.useMemo(
    () => {
      const syncRuns = (inventoryRunsQuery.data ?? []).filter((run) => isInventoryRun(run));
      const visibleAiJobs = (ingestionJobsQuery.data?.items ?? [])
        .filter((job) => ['QUEUED', 'RUNNING', 'FAILED'].includes(job.status.trim().toUpperCase()))
        .filter((job) => job.jobType.trim().toUpperCase().startsWith('AI_SECURITY_'))
        .filter((job) => !hasReplacementSyncRun(job, syncRuns))
        .map(aiJobAsRun);
      return [...visibleAiJobs, ...syncRuns];
    },
    [ingestionJobsQuery.data, inventoryRunsQuery.data]
  );
  const loading = (inventoryRunsQuery.isPending && !inventoryRunsQuery.data)
    || (ingestionJobsQuery.isPending && !ingestionJobsQuery.data);
  const refreshing = inventoryRunsQuery.isFetching || ingestionJobsQuery.isFetching;
  const queryError = inventoryRunsQuery.error ?? ingestionJobsQuery.error;
  const error = queryError instanceof Error ? queryError.message : '';
  const queueRows = React.useMemo(() => buildRunRows(inventoryRuns), [inventoryRuns]);

  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h3>Inventory Run Queue</h3>
          <span className="panel-caption">
            One row per inventory ingestion run across host, application, and container sources.
          </span>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            disabled={refreshing}
            onClick={() => {
              void inventoryRunsQuery.refetch();
              void ingestionJobsQuery.refetch();
            }}
          >
            {refreshing ? 'Refreshing...' : 'Refresh Queue'}
          </button>
        </div>
      </div>

      {error && <div className="notice error">{error}</div>}

      {loading ? (
        <div className="notice">Loading inventory-source runs...</div>
      ) : queueRows.length === 0 ? (
        <div className="empty-state">
          <p>No inventory-source runs have been recorded yet.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="inventory-run-queue-runs-table-widths"
            columns={INVENTORY_RUN_COLUMNS}
            rows={queueRows}
          />
        </div>
      )}
    </section>
  );
}
