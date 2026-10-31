import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { pathForConnectView, pathForInventoryView } from '../app/routes';
import { InfoTooltip } from '../components/InfoTooltip';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  GcpConnectionTestResponse,
  GcpDiscoveryConfig,
  GcpDiscoveryTarget,
  GcpDiscoveryTargetRequest,
  SyncTriggerResponse
} from '../features/connect/types';
import { useGcpDiscoveryConfigQuery, useGcpDiscoveryTargetsQuery } from '../features/connect/queries';
import { ConnectorConfigLoadError } from '../features/connect/ConnectorConfigLoadError';
import { grantCommands } from '../features/connect/gcp';
import { formatTimestamp } from '../lib/time';

const RESOURCE_TYPE_LABELS: Record<string, string> = {
  COMPUTE_INSTANCE: 'Compute Engine VMs (with OS packages)',
  GKE_CLUSTER: 'GKE clusters',
  CLOUD_RUN_SERVICE: 'Cloud Run services',
  CLOUD_FUNCTION: 'Cloud Functions',
  CLOUD_SQL_INSTANCE: 'Cloud SQL instances',
  STORAGE_BUCKET: 'Cloud Storage buckets',
  ARTIFACT_REGISTRY_REPOSITORY: 'Artifact Registry repositories'
};

function statusTone(status?: string): 'success' | 'warning' | 'error' {
  const normalized = status?.trim().toUpperCase();
  if (normalized === 'FAILED') return 'error';
  if (normalized === 'SUCCESS_WITH_WARNINGS') return 'warning';
  return 'success';
}

function statusLabel(status?: string): string {
  const normalized = status?.trim().toUpperCase();
  if (normalized === 'FAILED') return 'Connection failed';
  if (normalized === 'SUCCESS_WITH_WARNINGS') return 'Connection succeeded with warnings';
  return 'Connection successful';
}

function emptyTargetForm(supported: string[]): GcpDiscoveryTargetRequest {
  return { projectId: '', displayName: '', enabled: true, resourceTypes: [...supported] };
}

export function GcpDiscoveryConnectorPage() {
  const actor = useActor();
  const canManage = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const configQuery = useGcpDiscoveryConfigQuery();
  const config: GcpDiscoveryConfig | null = configQuery.data ?? null;
  const targetsQuery = useGcpDiscoveryTargetsQuery(Boolean(config?.id));
  const targets: GcpDiscoveryTarget[] = targetsQuery.data ?? [];
  const supported = config?.supportedResourceTypes ?? Object.keys(RESOURCE_TYPE_LABELS);

  const [autoSync, setAutoSync] = React.useState(false);
  const [intervalHours, setIntervalHours] = React.useState(24);
  const [targetForm, setTargetForm] = React.useState<GcpDiscoveryTargetRequest>(() => emptyTargetForm(supported));
  const [editingTargetId, setEditingTargetId] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<string | null>(null);
  const [error, setError] = React.useState('');
  // Shown only after an explicit Save; Test and Run report their own outcome.
  const [saveNotice, setSaveNotice] = React.useState('');
  const [testResult, setTestResult] = React.useState<GcpConnectionTestResponse | null>(null);
  const [syncResult, setSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [grantProject, setGrantProject] = React.useState('');
  const [credentialJson, setCredentialJson] = React.useState('');

  React.useEffect(() => {
    if (!config) return;
    setAutoSync(config.autoSyncEnabled);
    setIntervalHours(Math.max(1, Math.round((config.intervalMinutes ?? 1440) / 60)));
  }, [config]);

  const run = async <T,>(key: string, action: () => Promise<T>): Promise<T | null> => {
    setBusy(key);
    setError('');
    try {
      return await action();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
      return null;
    } finally {
      setBusy(null);
    }
  };

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ['gcp-discovery-config'] });
    await queryClient.invalidateQueries({ queryKey: ['gcp-discovery-targets'] });
  };

  const saveConnector = async () => {
    setSaveNotice('');
    const saved = await run('save', () => api.saveGcpDiscoveryConfig({
      credentialJson: credentialJson.trim() ? credentialJson.trim() : undefined,
      enabled: true,
      autoSyncEnabled: autoSync,
      intervalMinutes: Math.max(1, intervalHours) * 60
    }));
    if (saved) {
      setCredentialJson('');
      setSaveNotice('Connector settings saved.');
      queryClient.setQueryData(['gcp-discovery-config'], saved);
      await refresh();
    }
  };

  const loadKeyFile = async (file: File | undefined) => {
    if (!file) return;
    setCredentialJson(await file.text());
  };

  const testConnection = async () => {
    setTestResult(null);
    const result = await run('test', () => api.testGcpDiscoveryConnection());
    if (result) {
      setTestResult(result);
      await refresh();
    }
  };

  const triggerSync = async () => {
    setSyncResult(null);
    const result = await run('sync', () => api.triggerGcpDiscoverySync());
    if (result) setSyncResult(result);
  };

  const saveTarget = async () => {
    const payload: GcpDiscoveryTargetRequest = {
      ...targetForm,
      projectId: targetForm.projectId?.trim(),
      displayName: targetForm.displayName?.trim()
    };
    const saved = await run('target-save', () => editingTargetId
      ? api.updateGcpDiscoveryTarget(editingTargetId, payload)
      : api.createGcpDiscoveryTarget(payload));
    if (saved) {
      setGrantProject(saved.projectId);
      setEditingTargetId(null);
      setTargetForm(emptyTargetForm(supported));
      await refresh();
    }
  };

  const editTarget = (target: GcpDiscoveryTarget) => {
    setEditingTargetId(target.id);
    setTargetForm({
      projectId: target.projectId,
      displayName: target.displayName ?? '',
      enabled: target.enabled,
      resourceTypes: [...target.resourceTypes]
    });
  };

  const testTarget = async (targetId: string) => {
    setTestResult(null);
    const result = await run(`test-${targetId}`, () => api.testGcpDiscoveryTarget(targetId));
    if (result) {
      setTestResult(result);
      await refresh();
    }
  };

  const syncTarget = async (targetId: string) => {
    setSyncResult(null);
    const result = await run(`sync-${targetId}`, () => api.triggerGcpDiscoveryTargetSync(targetId));
    if (result) setSyncResult(result);
  };

  const deleteTarget = async (targetId: string) => {
    if (!window.confirm('Remove this GCP project from discovery? Existing inventory is kept.')) return;
    const done = await run(`delete-${targetId}`, async () => {
      await api.deleteGcpDiscoveryTarget(targetId);
      return true;
    });
    if (done) await refresh();
  };

  const toggleType = (type: string, checked: boolean) => {
    setTargetForm((current) => {
      const selected = new Set(current.resourceTypes ?? []);
      if (checked) selected.add(type);
      else selected.delete(type);
      return { ...current, resourceTypes: supported.filter((candidate) => selected.has(candidate)) };
    });
  };

  if (configQuery.isPending && !config) {
    return <section className="panel">Loading GCP Cloud Discovery connector...</section>;
  }
  if (configQuery.isError && !configQuery.data) {
    return <ConnectorConfigLoadError connectorName="GCP Cloud Discovery" error={configQuery.error} onRetry={() => void configQuery.refetch()} retrying={configQuery.isFetching} />;
  }

  const queryError = configQuery.error instanceof Error ? configQuery.error.message : '';
  const displayError = error || queryError;
  const provisioned = Boolean(config?.hasCredential && config.serviceAccountEmail);
  const grantFor = grantProject || targets[0]?.projectId || 'YOUR_PROJECT_ID';

  return (
    <section className="panel">
      {config?.lastSyncAt && (
        <div className="sn-status-row">
          <span className="sn-status-meta">Last integration run: {formatTimestamp(config.lastSyncAt)}</span>
        </div>
      )}

      {!config?.id && (
        <div className="notice">
          Create a read-only service account in your GCP project, download its JSON key, and add it below.
          Grant the account the roles listed after saving on every project you want discovered.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}
      {saveNotice && !displayError && <div className="notice success" role="status">{saveNotice}</div>}

      <div className="form-section">
        <h4 className="form-section-title">Service Account</h4>
        <div className="form-grid">
          <label>
            <span>
              Service account key (JSON) {!config?.hasCredential && <span className="sn-required">*</span>}{' '}
              <InfoTooltip text="Stored encrypted and never shown again. Leave blank to keep the saved key; paste or upload a new key to rotate it." />
            </span>
            <textarea
              rows={5}
              value={credentialJson}
              onChange={(e) => setCredentialJson(e.target.value)}
              placeholder={config?.hasCredential ? 'Leave blank to keep the saved key' : '{ "type": "service_account", ... }'}
              aria-label="Service account key JSON"
              spellCheck={false}
            />
            <input
              type="file"
              accept="application/json,.json"
              aria-label="Upload service account key"
              onChange={(e) => void loadKeyFile(e.target.files?.[0])}
            />
            {config?.hasCredential && <span className="sn-saved-badge">✓ Key saved — leave blank to keep it</span>}
          </label>
          <label>
            <span>Service account</span>
            <input type="text" value={config?.serviceAccountEmail ?? ''} readOnly placeholder="Read from the key after saving" />
          </label>
          <label>
            <span>Key project</span>
            <input type="text" value={config?.keyProjectId ?? ''} readOnly placeholder="Read from the key after saving" />
          </label>
        </div>
        {provisioned && (
          <div style={{ marginTop: 12 }}>
            <span className="panel-caption">
              Grant these read-only roles to the service account on <strong>{grantFor}</strong> (or in the Cloud Console under IAM):
            </span>
            <pre className="code-block" aria-label="Grant commands">
              {grantCommands(config!.serviceAccountEmail!, grantFor, config!.requiredRoles)}
            </pre>
          </div>
        )}
      </div>

      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input type="checkbox" checked={autoSync} onChange={(e) => setAutoSync(e.target.checked)} />
            <span>Enable scheduled discovery</span>
            <InfoTooltip text="Discovers every enabled project on the configured interval." />
          </label>
        </div>
        {autoSync && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>Sync interval (hours)</span>
              <input
                type="number"
                min={1}
                value={intervalHours}
                onChange={(e) => setIntervalHours(Math.max(1, Number(e.target.value) || 1))}
              />
            </label>
          </div>
        )}
      </div>

      {config?.id && (
        <div className="form-section">
          <h4 className="form-section-title">GCP Projects</h4>
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Resource types</th>
                  <th>Status</th>
                  <th>Last sync</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty-state">No GCP projects added yet.</td>
                  </tr>
                )}
                {targets.map((target) => (
                  <tr key={target.id}>
                    <td>
                      <strong>{target.displayName || target.projectId}</strong>
                      <span className="panel-caption" style={{ display: 'block' }}>{target.projectId}</span>
                    </td>
                    <td><span className="panel-caption">{target.resourceTypes.map((t) => RESOURCE_TYPE_LABELS[t] ?? t).join(', ')}</span></td>
                    <td>
                      <span className={target.enabled ? 'status-pill status-success' : 'status-pill'}>
                        {target.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                      {target.lastTestStatus && <span className="panel-caption" style={{ display: 'block' }}>{target.lastTestStatus}</span>}
                      {target.lastTestMessage && <span className="panel-caption" style={{ display: 'block', marginTop: 4 }}>{target.lastTestMessage}</span>}
                    </td>
                    <td>{formatTimestamp(target.lastSyncAt)}</td>
                    <td>
                      <div className="button-row">
                        <button type="button" className="btn btn-secondary btn-inline" onClick={() => editTarget(target)} disabled={!canManage}>Edit</button>
                        <button type="button" className="btn btn-secondary btn-inline" onClick={() => setGrantProject(target.projectId)} disabled={!provisioned}>Grants</button>
                        <button type="button" className="btn btn-secondary btn-inline" onClick={() => void testTarget(target.id)} disabled={!canManage || Boolean(busy)}>Test</button>
                        <button type="button" className="btn btn-secondary btn-inline" onClick={() => void syncTarget(target.id)} disabled={!canManage || Boolean(busy)}>Sync</button>
                        <button type="button" className="btn btn-secondary btn-inline" onClick={() => void deleteTarget(target.id)} disabled={!canManage || Boolean(busy)}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="form-grid" style={{ marginTop: 16 }}>
            <label>
              <span>Project ID <span className="sn-required">*</span></span>
              <input
                type="text"
                value={targetForm.projectId ?? ''}
                onChange={(e) => setTargetForm((current) => ({ ...current, projectId: e.target.value }))}
                placeholder="my-production-project"
                readOnly={Boolean(editingTargetId)}
              />
            </label>
            <label>
              <span>Display name</span>
              <input
                type="text"
                value={targetForm.displayName ?? ''}
                onChange={(e) => setTargetForm((current) => ({ ...current, displayName: e.target.value }))}
                placeholder="Production"
              />
            </label>
          </div>
          <fieldset className="aws-region-fieldset" style={{ marginTop: 12 }}>
            <legend className="aws-region-legend">Resource types</legend>
            <div className="aws-region-grid">
              {supported.map((type) => (
                <label key={type} className="aws-region-checkbox">
                  <input
                    type="checkbox"
                    checked={(targetForm.resourceTypes ?? []).includes(type)}
                    onChange={(e) => toggleType(type, e.target.checked)}
                  />
                  <span>{RESOURCE_TYPE_LABELS[type] ?? type}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <label className="sn-toggle-row" style={{ marginTop: 8 }}>
            <input
              type="checkbox"
              checked={targetForm.enabled ?? true}
              onChange={(e) => setTargetForm((current) => ({ ...current, enabled: e.target.checked }))}
            />
            <span>Enable this project</span>
          </label>
          <div className="button-row section-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void saveTarget()}
              disabled={!canManage || Boolean(busy) || !(targetForm.projectId ?? '').trim() || (targetForm.resourceTypes ?? []).length === 0}
            >
              {busy === 'target-save' ? 'Saving...' : editingTargetId ? 'Update Project' : 'Add Project'}
            </button>
            {editingTargetId && (
              <button type="button" className="btn btn-secondary" onClick={() => { setEditingTargetId(null); setTargetForm(emptyTargetForm(supported)); }}>
                Cancel
              </button>
            )}
          </div>
        </div>
      )}

      <div className="button-row section-actions sn-action-bar">
        <button type="button" className="btn btn-primary" onClick={() => void saveConnector()} disabled={!canManage || Boolean(busy) || (!config?.hasCredential && !credentialJson.trim())}>
          {busy === 'save' ? 'Saving...' : 'Save Connector'}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => void testConnection()} disabled={!canManage || Boolean(busy) || !config?.id}>
          {busy === 'test' ? 'Testing...' : 'Test Connection'}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => void triggerSync()} disabled={!canManage || Boolean(busy) || !provisioned || targets.length === 0}>
          {busy === 'sync' ? 'Running...' : 'Run Integration Now'}
        </button>
      </div>

      {testResult && (
        <div className={`notice sn-test-result ${statusTone(testResult.status)}`}>
          <strong>{statusLabel(testResult.status)}</strong>{' — '}{testResult.message}
          {testResult.permissions.length > 0 && (
            <ul className="panel-caption" style={{ marginTop: 6 }} aria-label="Permission checks">
              {testResult.permissions.map((check) => (
                <li key={check.permission}>
                  {check.granted ? '✓' : '✗'} {check.permission}{!check.required && ' (optional)'}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {syncResult && (
        <div className="notice">
          <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
          <a href={pathForConnectView('run-history')}>Integration Run Queue</a>.
        </div>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={pathForInventoryView('cloud-resources')}>View Cloud Resources →</a>
      </div>
    </section>
  );
}
