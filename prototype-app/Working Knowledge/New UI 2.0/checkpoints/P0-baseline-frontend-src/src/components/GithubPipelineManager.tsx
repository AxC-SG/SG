import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type { GithubSbomSource, SyncRun } from '../features/connect/types';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from './DataTable';
import { useGithubSbomSourcesQuery, useSyncRunsQuery } from '../features/connect/queries';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';

type GithubSourcePath = 'dependency-graph/sbom' | 'ghcr/attestations' | 'repository/cbom' | 'repository/aibom';

type Props = {
  title?: string;
  caption?: string;
};

const GITHUB_PIPELINE_COLUMNS: DataTableColumn[] = [
  { id: 'statusDot', label: 'Status', header: '', initialSize: 48 },
  { id: 'name', label: 'Name', header: 'Name', initialSize: 180 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 260 },
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 220 },
  { id: 'frequency', label: 'Frequency', header: 'Frequency', initialSize: 120 },
  { id: 'token', label: 'Token', header: 'Token', initialSize: 120 },
  { id: 'enabled', label: 'Enabled', header: 'Enabled', initialSize: 100 },
  { id: 'lastRun', label: 'Last Run', header: 'Last Run', initialSize: 180 },
  { id: 'action', label: 'Action', header: 'Action', initialSize: 220 }
];

function pipelineStatusMeta(status?: string | null): { cls: string; label: string } {
  if (!status) return { cls: 'pipeline-dot--none', label: 'Never run' };
  if (status === 'SUCCESS') return { cls: 'pipeline-dot--success', label: 'Success' };
  if (status === 'FAILURE') return { cls: 'pipeline-dot--failure', label: 'Failed' };
  if (status === 'PARTIAL_SUCCESS') return { cls: 'pipeline-dot--active', label: 'Partial success' };
  return { cls: 'pipeline-dot--active', label: status };
}

function githubSourceTypeLabel(path?: string | null): string {
  if (path === 'ghcr/attestations') return 'GHCR Image SBOM';
  if (path === 'repository/cbom') return 'Repository CBOM';
  if (path === 'repository/aibom') return 'Repository AI BOM';
  return 'Repository SBOM';
}

function githubSourceTargetLabel(source: GithubSbomSource): string {
  return source.path === 'ghcr/attestations'
    ? `ghcr.io/${source.owner}`
    : `${source.owner}/${source.repo}`;
}


function isSyncRunTerminal(run?: SyncRun | null): boolean {
  if (!run) return false;
  const value = run.status.trim().toUpperCase();
  return value === 'COMPLETED' || value === 'PARTIAL_SUCCESS' || value === 'FAILED';
}

function describeQueuedRun(label: string, run: SyncRun): string {
  return `${label} ${run.status}. Track status in Connect > Inventory Run Queue.`;
}

function describeCompletedRun(label: string, run: SyncRun): string {
  const status = run.status.trim().toUpperCase();
  if (status === 'FAILED') {
    return run.errorMessage
      ? `${label} failed: ${run.errorMessage}`
      : `${label} failed. Review Connect > Inventory Run Queue for details.`;
  }
  if (status === 'PARTIAL_SUCCESS') {
    return `${label} completed with partial success. Discovered ${run.recordsFetched}, failed ${run.recordsFailed}, components ${run.recordsInserted}, findings ${run.recordsUpdated}.`;
  }
  return `${label} completed. Discovered ${run.recordsFetched}, components ${run.recordsInserted}, findings ${run.recordsUpdated}.`;
}

function pendingGithubRun(runId: string, syncType: SyncRun['syncType'], status: string): SyncRun {
  return {
    id: runId,
    syncType,
    runDomain: 'INVENTORY',
    runClass: 'INGESTION',
    status,
    recordsFetched: 0,
    recordsInserted: 0,
    recordsUpdated: 0,
    recordsFailed: 0,
    startedAt: new Date().toISOString()
  };
}

export function GithubPipelineManager({
  title = 'GitHub SBOM Ingestion',
  caption = 'Run repository or GHCR SBOM ingestion on demand and save reusable pipelines. View ingestion history in Connect > Inventory Run Queue.'
}: Props) {
  const queryClient = useQueryClient();
  const [activeGithubRunId, setActiveGithubRunId] = React.useState<string | null>(null);
  const [activeGithubRunLabel, setActiveGithubRunLabel] = React.useState('GitHub ingestion');
  const [sourceBusyId, setSourceBusyId] = React.useState<string | null>(null);
  const [sourceMessage, setSourceMessage] = React.useState('');
  const [editingSourceId, setEditingSourceId] = React.useState<string | null>(null);

  const [sourceName, setSourceName] = React.useState('');
  const [sourceOwner, setSourceOwner] = React.useState('');
  const [sourceRepo, setSourceRepo] = React.useState('');
  const [sourcePath, setSourcePath] = React.useState<GithubSourcePath>('dependency-graph/sbom');
  const [sourceFrequency, setSourceFrequency] = React.useState<'ONCE' | 'INTERVAL'>('ONCE');
  const [sourceIntervalHours, setSourceIntervalHours] = React.useState('1');
  const [sourceEnabled, setSourceEnabled] = React.useState(true);
  const [sourceToken, setSourceToken] = React.useState('');
  const sourceAssetType: 'APPLICATION' | 'CONTAINER_IMAGE' =
    sourcePath === 'ghcr/attestations' ? 'CONTAINER_IMAGE' : 'APPLICATION';
  const isRepoFileScan = sourcePath === 'repository/cbom' || sourcePath === 'repository/aibom';
  const githubSourcesQuery = useGithubSbomSourcesQuery();
  const activeRunsQuery = useSyncRunsQuery(
    { category: 'inventory', limit: 50 },
    activeGithubRunId != null,
    RUN_QUEUE_REFRESH_INTERVAL_MS
  );
  const githubSources = React.useMemo(() => githubSourcesQuery.data ?? [], [githubSourcesQuery.data]);
  const isEditingSource = editingSourceId != null;

  const resetForm = React.useCallback(() => {
    setEditingSourceId(null);
    setSourceName('');
    setSourceOwner('');
    setSourceRepo('');
    setSourcePath('dependency-graph/sbom');
    setSourceFrequency('ONCE');
    setSourceIntervalHours('1');
    setSourceEnabled(true);
    setSourceToken('');
  }, []);

  const loadSourceIntoForm = React.useCallback((source: GithubSbomSource) => {
    setEditingSourceId(source.id);
    setSourceName(source.name);
    setSourceOwner(source.owner);
    setSourceRepo(source.repo ?? '');
    setSourcePath((source.path as GithubSourcePath) ?? 'dependency-graph/sbom');
    setSourceFrequency(source.frequency);
    setSourceIntervalHours(String(Math.max(1, Math.round((source.intervalMinutes ?? 60) / 60))));
    setSourceEnabled(source.enabled);
    setSourceToken('');
    setSourceMessage(`Editing GitHub pipeline "${source.name}"`);
  }, []);

  const refreshGithubView = React.useCallback(async () => {
    const result = await githubSourcesQuery.refetch();
    if (result.error) {
      setSourceMessage(result.error instanceof Error ? result.error.message : String(result.error));
    }
  }, [githubSourcesQuery]);

  React.useEffect(() => {
    if (!activeGithubRunId) {
      return;
    }
    const run = (activeRunsQuery.data ?? []).find((candidate) => candidate.id === activeGithubRunId);
    if (!run || !isSyncRunTerminal(run)) {
      return;
    }
    setActiveGithubRunId(null);
    setSourceMessage(describeCompletedRun(activeGithubRunLabel, run));
    void refreshGithubView();
  }, [activeGithubRunId, activeGithubRunLabel, activeRunsQuery.data, refreshGithubView]);

  const runGithubOnce = async (): Promise<void> => {
    if (!sourceOwner.trim()) {
      setSourceMessage('GitHub owner is required');
      return;
    }
    if (isRepoFileScan && !sourceRepo.trim()) {
      setSourceMessage('GitHub repository is required for CBOM/AI BOM file scan');
      return;
    }
    if (sourcePath === 'dependency-graph/sbom' && !sourceRepo.trim()) {
      const proceed = window.confirm(
        `Repository is empty. This will ingest SBOMs for all repositories under "${sourceOwner.trim()}". Continue?`
      );
      if (!proceed) {
        return;
      }
    }

    setSourceMessage('');
    setActiveGithubRunId(null);
    setSourceBusyId('run-once');
    try {
      if (sourcePath === 'ghcr/attestations') {
        const run = await api.queueGithubGhcrRun(sourceOwner.trim());
        setActiveGithubRunId(run.runId);
        setActiveGithubRunLabel('GHCR ingestion');
        setSourceMessage(describeQueuedRun('GHCR ingestion', pendingGithubRun(run.runId, 'GITHUB_GHCR_SBOM', run.status)));
        await Promise.all([refreshGithubView(), activeRunsQuery.refetch()]);
      } else if (isRepoFileScan) {
        const bomLabel = sourcePath === 'repository/cbom' ? 'CBOM' : 'AI BOM';
        const syncType = sourcePath === 'repository/cbom' ? 'GITHUB_REPOSITORY_CBOM' : 'GITHUB_REPOSITORY_AIBOM';
        const run = await api.queueGithubRepositoryRun({
          owner: sourceOwner.trim(),
          repo: sourceRepo.trim(),
          includeAllRepos: false,
          assetType: sourceAssetType,
          path: sourcePath
        });
        setActiveGithubRunId(run.runId);
        setActiveGithubRunLabel(`GitHub ${bomLabel} file scan`);
        setSourceMessage(describeQueuedRun(`GitHub ${bomLabel} file scan`, pendingGithubRun(run.runId, syncType as SyncRun['syncType'], run.status)));
        await Promise.all([refreshGithubView(), activeRunsQuery.refetch()]);
      } else {
        const run = await api.queueGithubRepositoryRun({
          owner: sourceOwner.trim(),
          repo: sourceRepo.trim() || undefined,
          includeAllRepos: !sourceRepo.trim(),
          assetType: sourceAssetType
        });
        setActiveGithubRunId(run.runId);
        setActiveGithubRunLabel('GitHub repository ingestion');
        setSourceMessage(describeQueuedRun('GitHub repository ingestion', pendingGithubRun(run.runId, 'GITHUB_REPOSITORY_SBOM', run.status)));
        await Promise.all([refreshGithubView(), activeRunsQuery.refetch()]);
      }
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
    }
  };

  const saveGithubSource = React.useCallback(async (): Promise<void> => {
    if (!sourceName.trim()) {
      setSourceMessage('Pipeline name is required');
      return;
    }
    if (!sourceOwner.trim()) {
      setSourceMessage('GitHub owner is required');
      return;
    }
    if ((sourcePath === 'dependency-graph/sbom' || isRepoFileScan) && !sourceRepo.trim()) {
      setSourceMessage('GitHub repository is required for this source type');
      return;
    }

    setSourceMessage('');
    setSourceBusyId(isEditingSource ? `update:${editingSourceId}` : 'create');
    try {
      const payload = {
        name: sourceName.trim(),
        owner: sourceOwner.trim(),
        repo: sourcePath !== 'ghcr/attestations' ? sourceRepo.trim() : '',
        path: sourcePath,
        assetType: sourceAssetType,
        frequency: sourceFrequency,
        intervalMinutes: sourceFrequency === 'INTERVAL' ? Math.max(5, (Number(sourceIntervalHours) || 1) * 60) : undefined,
        enabled: sourceEnabled,
        githubToken: sourceToken.trim() || undefined
      };
      if (editingSourceId) {
        await api.updateGithubSbomSource(editingSourceId, payload);
        setSourceMessage('GitHub pipeline updated');
      } else {
        await api.createGithubSbomSource(payload);
        setSourceMessage('GitHub pipeline created');
      }
      await queryClient.invalidateQueries({ queryKey: ['github-sbom-sources'] });
      await refreshGithubView();
      resetForm();
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
    }
  }, [editingSourceId, isEditingSource, queryClient, refreshGithubView, resetForm, sourceEnabled, sourceFrequency, sourceIntervalHours, sourceName, sourceOwner, sourcePath, sourceRepo, sourceToken, sourceAssetType]);

  const runGithubSource = React.useCallback(async (id: string): Promise<void> => {
    setSourceBusyId(id);
    setSourceMessage('');
    setActiveGithubRunId(null);
    try {
      const run = await api.runGithubSbomSource(id);
      const source = githubSources.find((row) => row.id === id);
      const label = source ? `${source.name} run` : 'GitHub pipeline run';
      setActiveGithubRunId(run.runId);
      setActiveGithubRunLabel(label);
      setSourceMessage(describeQueuedRun(
        label,
        pendingGithubRun(
          run.runId,
          source?.path === 'ghcr/attestations' ? 'GITHUB_GHCR_SBOM'
            : source?.path === 'repository/cbom' ? 'GITHUB_REPOSITORY_CBOM'
            : source?.path === 'repository/aibom' ? 'GITHUB_REPOSITORY_AIBOM'
            : 'GITHUB_REPOSITORY_SBOM',
          run.status
        )
      ));
      await Promise.all([refreshGithubView(), activeRunsQuery.refetch()]);
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
    }
  }, [activeRunsQuery, githubSources, refreshGithubView]);

  const deleteGithubSource = React.useCallback(async (id: string): Promise<void> => {
    const source = githubSources.find((row) => row.id === id);
    const confirmed = window.confirm(`Delete GitHub pipeline "${source?.name ?? 'this pipeline'}"?`);
    if (!confirmed) {
      return;
    }

    setSourceBusyId(`delete:${id}`);
    setSourceMessage('');
    try {
      await api.deleteGithubSbomSource(id);
      setSourceMessage(`Deleted GitHub pipeline "${source?.name ?? id}"`);
      if (editingSourceId === id) {
        resetForm();
      }
      await queryClient.invalidateQueries({ queryKey: ['github-sbom-sources'] });
      await refreshGithubView();
    } catch (e) {
      setSourceMessage(e instanceof Error ? e.message : String(e));
    } finally {
      setSourceBusyId(null);
    }
  }, [editingSourceId, githubSources, queryClient, refreshGithubView, resetForm]);

  const githubPipelineRows = React.useMemo<DataTableRow[]>(() => (
    githubSources.map((source) => {
      const dot = pipelineStatusMeta(source.lastRunStatus);
      return {
        id: source.id,
        cells: {
          statusDot: {
            content: (
              <span
                className={`pipeline-dot ${dot.cls}`}
                title={source.lastError ? `${dot.label}: ${source.lastError}` : dot.label}
              />
            )
          },
          name: { content: source.name },
          source: { content: `${githubSourceTypeLabel(source.path)}: ${githubSourceTargetLabel(source)}` },
          asset: { content: `${source.assetName} (${source.assetIdentifier})` },
          frequency: {
            content: source.frequency === 'ONCE' ? 'Once' : `Every ${Math.round(source.intervalMinutes / 60)}h`
          },
          token: {
            content: source.hasToken
              ? <span className="badge badge-success" title="A per-pipeline token is configured">Token set</span>
              : <span className="muted">Global</span>
          },
          enabled: { content: source.enabled ? 'Yes' : 'No' },
          lastRun: { content: source.lastRunAt ? new Date(source.lastRunAt).toLocaleString() : 'Never' },
          action: {
            content: (
              <>
                <button
                  type="button"
                  className="btn btn-secondary btn-inline"
                  onClick={() => loadSourceIntoForm(source)}
                  disabled={sourceBusyId != null}
                >
                  Edit
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-inline"
                  onClick={() => void runGithubSource(source.id)}
                  disabled={sourceBusyId != null}
                >
                  {sourceBusyId === source.id ? 'Running...' : 'Run Now'}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary btn-inline"
                  onClick={() => void deleteGithubSource(source.id)}
                  disabled={sourceBusyId != null}
                >
                  {sourceBusyId === `delete:${source.id}` ? 'Deleting...' : 'Delete'}
                </button>
              </>
            )
          }
        }
      };
    })
  ), [deleteGithubSource, githubSources, loadSourceIntoForm, runGithubSource, sourceBusyId]);

  return (
    <section className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className="panel-caption">{caption}</span>
      </div>

      <div className="form-section">
        <h4 className="form-section-title">Integration Inputs</h4>
        <div className="form-grid ingestion-grid">
          <label>Pipeline Name (saved pipelines only)
            <input value={sourceName} onChange={(e) => setSourceName(e.target.value)} placeholder="payments-main-sbom" />
          </label>
          <label>Source Type
            <select value={sourcePath} onChange={(e) => setSourcePath(e.target.value as GithubSourcePath)}>
              <option value="dependency-graph/sbom">GitHub Repository SBOM</option>
              <option value="ghcr/attestations">GHCR Image SBOM (all images)</option>
              <option value="repository/cbom">Repository CBOM (file scan)</option>
              <option value="repository/aibom">Repository AI BOM (file scan)</option>
            </select>
          </label>
          <label>GitHub Owner
            <input value={sourceOwner} onChange={(e) => setSourceOwner(e.target.value)} placeholder="org-name" />
          </label>
          {sourcePath === 'ghcr/attestations' ? (
            <div className="inline-note">
              GHCR mode discovers every container package and image digest under <span className="mono">ghcr.io/{sourceOwner.trim() || 'owner'}</span> and ingests each attested SBOM separately.
              It requires a backend GitHub token with <span className="mono">read:packages</span> access.
              Run Once uses only the owner. Pipeline name is only required if you want to save a reusable pipeline.
            </div>
          ) : isRepoFileScan ? (
            <label>GitHub Repo
              <input value={sourceRepo} onChange={(e) => setSourceRepo(e.target.value)} placeholder="service-repo" />
              <span className="field-hint">
                Scans the repo file tree for <code>{sourcePath === 'repository/cbom' ? '*.cbom.json / *.cbom.xml' : '*.aibom.json / *.aibom.xml / *.ai-bom.json / *.ml-bom.json'}</code> files.
              </span>
            </label>
          ) : (
            <label>GitHub Repo
              <input value={sourceRepo} onChange={(e) => setSourceRepo(e.target.value)} placeholder="service-repo" />
            </label>
          )}
          <label>GitHub Token (optional)
            <input
              type="password"
              value={sourceToken}
              onChange={(e) => setSourceToken(e.target.value)}
              placeholder={isEditingSource
                ? 'ghp_… leave blank to keep the current token or use the global backend token'
                : 'ghp_… leave blank to use the global backend token'}
              autoComplete="new-password"
            />
          </label>
        </div>
      </div>

      <div className="form-section">
        <h4 className="form-section-title">Schedule Configuration (saved pipelines only)</h4>
        <div className="form-grid ingestion-grid">
          <label>Frequency
            <select value={sourceFrequency} onChange={(e) => setSourceFrequency(e.target.value as 'ONCE' | 'INTERVAL')}>
              <option value="ONCE">Once</option>
              <option value="INTERVAL">Every N hours</option>
            </select>
          </label>
          {sourceFrequency === 'INTERVAL' && (
            <label>Interval (hours)
              <input
                type="number"
                min={1}
                max={24}
                value={sourceIntervalHours}
                onChange={(e) => setSourceIntervalHours(e.target.value)}
              />
            </label>
          )}
          <label>Enabled
            <select value={sourceEnabled ? 'true' : 'false'} onChange={(e) => setSourceEnabled(e.target.value === 'true')}>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </label>
        </div>
      </div>

      <div className="button-row form-submit-row">
        <button
          type="button"
          className="btn btn-primary"
          onClick={runGithubOnce}
          disabled={sourceBusyId != null}
        >
          {sourceBusyId === 'run-once' ? 'Running...' : 'Run Once'}
        </button>
        <button type="button" className="btn btn-secondary" onClick={saveGithubSource} disabled={sourceBusyId != null}>
          {sourceBusyId === 'create'
            ? 'Saving...'
            : sourceBusyId === `update:${editingSourceId}`
              ? 'Updating...'
              : isEditingSource
                ? 'Update Pipeline'
                : 'Save Auto Pipeline'}
        </button>
        {isEditingSource && (
          <button type="button" className="btn btn-secondary" onClick={resetForm} disabled={sourceBusyId != null}>
            Cancel Edit
          </button>
        )}
        <button type="button" className="btn btn-secondary" onClick={() => void refreshGithubView()} disabled={sourceBusyId != null}>
          Refresh
        </button>
      </div>
      {sourceMessage && <div className="notice">{sourceMessage}</div>}

      {githubSources.length === 0 ? (
        <div className="empty-state">
          <p>No GitHub auto-ingestion pipelines configured.</p>
        </div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey="github-source-pipelines-table-widths"
            columns={GITHUB_PIPELINE_COLUMNS}
            rows={githubPipelineRows}
          />
        </div>
      )}

    </section>
  );
}
