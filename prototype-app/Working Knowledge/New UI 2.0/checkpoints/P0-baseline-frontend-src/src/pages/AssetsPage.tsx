import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { pathForConnectView, pathForInventoryView } from '../app/routes';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  ServiceNowCmdbAuthType,
  ServiceNowCmdbConfig,
  ServiceNowCmdbConfigRequest,
  ServiceNowCmdbConnectionTest,
  SyncTriggerResponse
} from '../features/connect/types';
import { useServiceNowCmdbConfigQuery } from '../features/connect/queries';

const REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';
const DEFAULT_INSTALL_FIELDS = [
  'sys_id',
  'display_name',
  'publisher',
  'version',
  'install_date',
  'last_scanned',
  'last_used',
  'active_install',
  'unlicensed_install',
  'installed_on',
  'discovery_model'
].join(',');
const DEFAULT_DISCOVERY_FIELDS = [
  'sys_id',
  'primary_key',
  'normalized_product',
  'normalized_publisher',
  'normalized_version',
  'product_hash',
  'version_hash',
  'full_version',
  'platform',
  'language',
  'normalization_status',
  'approved',
  'low_confidence'
].join(',');

function inventoryHref(view: 'hosts', reviewCategories?: string[]): string {
  const searchParams = new URLSearchParams();
  reviewCategories?.forEach((value) => searchParams.append(REVIEW_CATEGORY_QUERY_KEY, value));
  const query = searchParams.toString();
  return query ? `${pathForInventoryView(view)}?${query}` : pathForInventoryView(view);
}

function connectHref(view: 'run-history'): string {
  return pathForConnectView(view);
}

function defaultForm(): ServiceNowCmdbConfigRequest {
  return {
    baseUrl: '',
    authType: 'BASIC',
    username: '',
    credentialSecret: '',
    installTable: 'cmdb_sam_sw_install',
    discoveryModelTable: 'cmdb_sam_sw_discovery_model',
    ciTable: 'cmdb_ci',
    installQuery: '',
    discoveryQuery: '',
    installFields: DEFAULT_INSTALL_FIELDS,
    discoveryFields: DEFAULT_DISCOVERY_FIELDS,
    pageSize: 1000,
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: ServiceNowCmdbConfig | null): ServiceNowCmdbConfigRequest {
  if (!config) {
    return defaultForm();
  }
  return {
    baseUrl: config.baseUrl ?? '',
    authType: config.authType,
    username: config.username ?? '',
    credentialSecret: '',
    installTable: config.installTable ?? 'cmdb_sam_sw_install',
    discoveryModelTable: config.discoveryModelTable ?? 'cmdb_sam_sw_discovery_model',
    ciTable: config.ciTable ?? 'cmdb_ci',
    installQuery: config.installQuery ?? '',
    discoveryQuery: config.discoveryQuery ?? '',
    installFields: config.installFields ?? DEFAULT_INSTALL_FIELDS,
    discoveryFields: config.discoveryFields ?? DEFAULT_DISCOVERY_FIELDS,
    pageSize: config.pageSize ?? 1000,
    enabled: config.enabled,
    autoSyncEnabled: config.autoSyncEnabled,
    intervalMinutes: config.intervalMinutes ?? 1440
  };
}

function formatTimestamp(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function Tooltip({ text }: { text: string }) {
  return (
    <span className="sn-tooltip" title={text} aria-label={text}>
      ⓘ
    </span>
  );
}

export function AssetsPage() {
  const actor = useActor();
  const canManageConnector = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const serviceNowConfigQuery = useServiceNowCmdbConfigQuery();
  const config = serviceNowConfigQuery.data ?? null;
  const [form, setForm] = React.useState<ServiceNowCmdbConfigRequest>(defaultForm);
  const [credentialSecret, setCredentialSecret] = React.useState('');
  const [testResult, setTestResult] = React.useState<ServiceNowCmdbConnectionTest | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [syncingLive, setSyncingLive] = React.useState(false);
  const [error, setError] = React.useState('');
  const [liveSyncResult, setLiveSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [showSecret, setShowSecret] = React.useState(false);

  React.useEffect(() => {
    setForm(formFromConfig(config));
    setCredentialSecret('');
  }, [config]);

  const updateField = <K extends keyof ServiceNowCmdbConfigRequest>(key: K, value: ServiceNowCmdbConfigRequest[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  // Display interval as hours; store internally as minutes
  const intervalHours = Math.max(1, Math.round((form.intervalMinutes ?? 1440) / 60));
  const updateIntervalHours = (hours: number) => updateField('intervalMinutes', Math.max(60, hours * 60));

  const saveConnector = async (): Promise<ServiceNowCmdbConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload: ServiceNowCmdbConfigRequest = {
        ...form,
        username: form.authType === 'BASIC' ? form.username?.trim() ?? '' : '',
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        installTable: form.installTable.trim() || 'cmdb_sam_sw_install',
        discoveryModelTable: form.discoveryModelTable.trim() || 'cmdb_sam_sw_discovery_model',
        ciTable: form.ciTable.trim() || 'cmdb_ci',
        installQuery: '',
        discoveryQuery: '',
        installFields: DEFAULT_INSTALL_FIELDS,
        discoveryFields: DEFAULT_DISCOVERY_FIELDS,
        baseUrl: form.baseUrl.trim(),
        pageSize: 1000,
        enabled: true,
        intervalMinutes: Math.max(60, Number(form.intervalMinutes) || 1440)
      };
      const saved = await api.saveServiceNowCmdbConfig(payload);
      queryClient.setQueryData(['service-now-cmdb-config'], saved);
      setForm(formFromConfig(saved));
      setCredentialSecret('');
      return saved;
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
      return null;
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async (): Promise<void> => {
    setTestResult(null);
    const saved = await saveConnector();
    if (!saved) return;
    setTesting(true);
    setError('');
    try {
      const response = await api.testServiceNowCmdbConnection();
      setTestResult(response);
      const refreshed = await api.getServiceNowCmdbConfig();
      queryClient.setQueryData(['service-now-cmdb-config'], refreshed);
      setForm(formFromConfig(refreshed));
      setCredentialSecret('');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setTesting(false);
    }
  };

  const queueLiveSync = async (): Promise<void> => {
    setSyncingLive(true);
    setError('');
    setLiveSyncResult(null);
    try {
      const saved = await saveConnector();
      if (!saved) return;
      const result = await api.triggerServiceNowCmdbSync();
      setLiveSyncResult(result);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setSyncingLive(false);
    }
  };

  const queryError = serviceNowConfigQuery.error instanceof Error ? serviceNowConfigQuery.error.message : '';
  const displayError = error || queryError;
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    serviceNowConfigQuery.dataUpdatedAt,
    config?.lastSyncAt
  ]), [
    config?.lastSyncAt,
    serviceNowConfigQuery.dataUpdatedAt
  ]);

  if (serviceNowConfigQuery.isPending && !config) {
    return <section className="panel">Loading ServiceNow CMDB connector...</section>;
  }

  return (
    <section className="panel">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={serviceNowConfigQuery.isFetching && !!config}
        refreshLabel="Refreshing ServiceNow CMDB connector details…"
      />

      {!config?.configured && (
        <div className="notice">
          This connector is not yet configured. Fill in the Connection section below to enable live ServiceNow API pulls.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}

      {/* Connection status summary */}
      {config?.configured && (
        <div className="sn-status-row">
          {config.lastSyncAt ? (
            <span className="sn-status-meta">Last integration run: {formatTimestamp(config.lastSyncAt)}</span>
          ) : (
            <span className="sn-status-meta">No integration run yet</span>
          )}
        </div>
      )}

      {/* ── SECTION 1: Connection ── */}
      <div className="form-section">
        <h4 className="form-section-title">Connection</h4>
        <div className="form-grid">
          <label id="sn-base-url">
            <span>
              ServiceNow Base URL <span className="sn-required">*</span>{' '}
              <Tooltip text="Use the root instance URL. The app will call the Table API under this host." />
            </span>
            <input
              type="url"
              value={form.baseUrl}
              onChange={(event) => updateField('baseUrl', event.target.value)}
              placeholder="https://your-instance.service-now.com"
            />
          </label>

          <label>
            <span>
              Auth Method <span className="sn-required">*</span>{' '}
              <Tooltip text="Basic Auth uses username + password. Bearer mode uses a token in the Authorization header." />
            </span>
            <select value={form.authType} onChange={(event) => updateField('authType', event.target.value as ServiceNowCmdbAuthType)}>
              <option value="BASIC">Basic Auth</option>
              <option value="BEARER">Bearer Token</option>
            </select>
          </label>

          <label>
            <span>
              Integration Username{form.authType === 'BASIC' ? <> <span className="sn-required">*</span></> : ' (Optional)'}{' '}
              <Tooltip text={form.authType === 'BASIC' ? 'Use a dedicated read-only ServiceNow integration account.' : 'Optional in Bearer mode. Leave blank if the token is sufficient.'} />
            </span>
            <input
              type="text"
              value={form.username ?? ''}
              onChange={(event) => updateField('username', event.target.value)}
              placeholder={form.authType === 'BEARER' ? 'Optional for audit context' : 'svc-noscan-servicenow'}
            />
          </label>

          <label id="sn-credential">
            <span>
              {form.authType === 'BEARER' ? 'Bearer Token' : 'Password'} <span className="sn-required">*</span>{' '}
              <Tooltip text={config?.hasCredentialSecret ? 'A secret is already saved. Enter a new value only to rotate it.' : 'Required before live pulls can work.'} />
            </span>
            <div className="secure-input-row">
              <input
                type={showSecret ? 'text' : 'password'}
                value={credentialSecret}
                onChange={(event) => setCredentialSecret(event.target.value)}
                placeholder={config?.hasCredentialSecret ? 'Leave blank to keep saved secret' : 'Enter secret'}
              />
              <button
                type="button"
                className="btn btn-secondary btn-inline"
                onClick={() => setShowSecret((v) => !v)}
                aria-label={showSecret ? 'Hide secret' : 'Show secret'}
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
            {config?.hasCredentialSecret && (
              <span className="sn-saved-badge">✓ Secret saved — leave blank to keep it</span>
            )}
          </label>
        </div>
      </div>

      {/* ── SECTION 2: Table Configuration ── */}
      <div className="form-section">
        <h4 className="form-section-title">Table Configuration</h4>
        <div className="form-grid">
          <label>
            <span>
              Install Table <span className="sn-required">*</span>{' '}
              <Tooltip text="ServiceNow table containing installed software rows per host." />
            </span>
            <input
              type="text"
              value={form.installTable}
              onChange={(event) => updateField('installTable', event.target.value)}
              placeholder="cmdb_sam_sw_install"
            />
          </label>

          <label>
            <span>
              Discovery Model Table <span className="sn-required">*</span>{' '}
              <Tooltip text="Provides normalized discovery-model metadata for software records." />
            </span>
            <input
              type="text"
              value={form.discoveryModelTable}
              onChange={(event) => updateField('discoveryModelTable', event.target.value)}
              placeholder="cmdb_sam_sw_discovery_model"
            />
          </label>

          <label>
            <span>
              CI Lookup Table <span className="sn-required">*</span>{' '}
              <Tooltip text="Used for host lookup and CI resolution." />
            </span>
            <input
              type="text"
              value={form.ciTable}
              onChange={(event) => updateField('ciTable', event.target.value)}
              placeholder="cmdb_ci"
            />
          </label>
        </div>
      </div>

      {/* ── SECTION 3: Sync Settings ── */}
      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input
              type="checkbox"
              checked={form.autoSyncEnabled}
              onChange={(event) => updateField('autoSyncEnabled', event.target.checked)}
            />
            <span>Enable scheduled live sync</span>
            <Tooltip text="Automatically pulls data from ServiceNow on the configured interval." />
          </label>
        </div>
        {form.autoSyncEnabled && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>
                Sync Interval (hours){' '}
                <Tooltip text="How often the scheduled sync runs. Minimum 1 hour." />
              </span>
              <input
                type="number"
                min={1}
                value={intervalHours}
                onChange={(event) => updateIntervalHours(Number(event.target.value))}
              />
            </label>
          </div>
        )}
      </div>

      {/* ── Action bar ── */}
      <div className="button-row section-actions sn-action-bar">
        <button type="button" className="btn btn-primary" onClick={() => void saveConnector()} disabled={!canManageConnector || saving || testing}>
          {saving ? 'Saving...' : 'Save Connector'}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => void testConnection()} disabled={!canManageConnector || testing || saving}>
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void queueLiveSync()}
          disabled={!canManageConnector || syncingLive || saving || testing || serviceNowConfigQuery.isFetching}
        >
          {syncingLive ? 'Running...' : 'Run Integration now'}
        </button>
      </div>

      {testResult && (
        <div className={`notice sn-test-result ${testResult.status === 'SUCCESS' ? 'success' : 'error'}`}>
          <strong>{testResult.status === 'SUCCESS' ? '✓ Connection successful' : '✗ Connection failed'}</strong>
          {' — '}{testResult.message}
          <span className="sn-table-checks">
            <span className={testResult.ciTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              CI {testResult.ciTableReachable ? '✓' : '✗'}
            </span>
            <span className={testResult.installTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              Install {testResult.installTableReachable ? '✓' : '✗'}
            </span>
            <span className={testResult.discoveryTableReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              Discovery {testResult.discoveryTableReachable ? '✓' : '✗'}
            </span>
          </span>
        </div>
      )}

      {liveSyncResult && (
        <div className="notice">
          <strong>Integration queued.</strong> {liveSyncResult.message}. Track progress in{' '}
          <a href={connectHref('run-history')}>Integration Run Queue</a>.
        </div>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={inventoryHref('hosts')}>View Inventory Hosts →</a>
        <a className="btn-link" href={inventoryHref('hosts', ['NEEDS_REVIEW'])}>View Hosts Needing Review →</a>
      </div>
    </section>
  );
}
