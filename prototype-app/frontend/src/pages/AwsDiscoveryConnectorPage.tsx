import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { pathForConnectView, pathForInventoryView } from '../app/routes';
import { InfoTooltip } from '../components/InfoTooltip';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  AwsAuthType,
  AwsDiscoveryConfig,
  AwsDiscoveryConfigRequest,
  AwsDiscoveryTarget,
  AwsDiscoveryTargetRequest,
  AwsConnectionTestResponse,
  SyncTriggerResponse
} from '../features/connect/types';
import { useAwsDiscoveryConfigQuery, useAwsDiscoveryTargetsQuery } from '../features/connect/queries';
import { ConnectorConfigLoadError } from '../features/connect/ConnectorConfigLoadError';
import { formatTimestamp } from '../lib/time';

// ── Region constants ─────────────────────────────────────────────────────────

const AWS_REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1'
];

function parseRegions(json?: string): string[] {
  if (!json) return ['us-east-1'];
  try { return JSON.parse(json) as string[]; } catch { return ['us-east-1']; }
}

function isWarningStatus(status?: string): boolean {
  return status?.trim().toUpperCase() === 'SUCCESS_WITH_WARNINGS';
}

function isFailedStatus(status?: string): boolean {
  return status?.trim().toUpperCase() === 'FAILED';
}

function testResultTone(status?: string): 'success' | 'warning' | 'error' {
  if (isFailedStatus(status)) return 'error';
  if (isWarningStatus(status)) return 'warning';
  return 'success';
}

function testResultLabel(status?: string): string {
  if (isFailedStatus(status)) return 'Connection failed';
  if (isWarningStatus(status)) return 'Connection succeeded with warnings';
  return 'Connection successful';
}

// ── Default form ──────────────────────────────────────────────────────────────

function defaultForm(): AwsDiscoveryConfigRequest {
  return {
    authType: 'CROSS_ACCOUNT_ROLE',
    accessKeyId: '',
    credentialSecret: '',
    crossAccountRoleArn: '',
    externalId: '',
    regionsJson: '["us-east-1"]',
    resourceTypesJson: '["EC2"]',
    enabled: true,
    autoSyncEnabled: false,
    intervalMinutes: 1440
  };
}

function formFromConfig(config: AwsDiscoveryConfig | null): AwsDiscoveryConfigRequest {
  if (!config) return defaultForm();
  return {
    authType: 'CROSS_ACCOUNT_ROLE',
    accessKeyId: config.accessKeyId ?? '',
    credentialSecret: '',
    crossAccountRoleArn: config.crossAccountRoleArn ?? '',
    externalId: config.externalId ?? '',
    regionsJson: config.regionsJson ?? '["us-east-1"]',
    resourceTypesJson: '["EC2"]',
    enabled: config.enabled,
    autoSyncEnabled: config.autoSyncEnabled,
    intervalMinutes: config.intervalMinutes ?? 1440
  };
}

function defaultTargetForm(config: AwsDiscoveryConfig | null): AwsDiscoveryTargetRequest {
  return {
    accountId: '',
    accountName: '',
    roleArn: config?.crossAccountRoleArn ?? '',
    externalId: '',
    enabled: true,
    regionsJson: config?.regionsJson ?? '["us-east-1"]',
    resourceTypesJson: '["EC2"]'
  };
}

function targetToForm(target: AwsDiscoveryTarget): AwsDiscoveryTargetRequest {
  return {
    accountId: target.accountId ?? '',
    accountName: target.accountName ?? '',
    roleArn: target.roleArn ?? '',
    externalId: target.externalId ?? '',
    enabled: target.enabled,
    regionsJson: target.regionsJson,
    resourceTypesJson: '["EC2"]'
  };
}

// ── Component ─────────────────────────────────────────────────────────────────

export function AwsDiscoveryConnectorPage() {
  const actor = useActor();
  const canManageConnector = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const configQuery = useAwsDiscoveryConfigQuery();
  const config = configQuery.data ?? null;
  const targetsQuery = useAwsDiscoveryTargetsQuery(Boolean(config?.configured));
  const targets = targetsQuery.data ?? [];

  const [activeTab, setActiveTab] = React.useState<'connection' | 'accounts'>('connection');
  const [form, setForm] = React.useState<AwsDiscoveryConfigRequest>(defaultForm);
  const [selectedRegions, setSelectedRegions] = React.useState<string[]>(['us-east-1']);
  const [showSecret, setShowSecret] = React.useState(false);
  const [testResult, setTestResult] = React.useState<AwsConnectionTestResponse | null>(null);
  const [syncResult, setSyncResult] = React.useState<SyncTriggerResponse | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [syncing, setSyncing] = React.useState(false);
  const [error, setError] = React.useState('');
  // Shown only after an explicit Save; Test and Run report their own outcome.
  const [saveNotice, setSaveNotice] = React.useState('');
  const [editingTargetId, setEditingTargetId] = React.useState<string | null>(null);
  const [targetForm, setTargetForm] = React.useState<AwsDiscoveryTargetRequest>(defaultTargetForm(null));
  const [targetBusy, setTargetBusy] = React.useState('');

  React.useEffect(() => {
    const f = formFromConfig(config);
    setForm(f);
    setSelectedRegions(parseRegions(f.regionsJson));
  }, [config]);

  React.useEffect(() => {
    if (!editingTargetId) {
      setTargetForm(defaultTargetForm(config));
    }
  }, [config, editingTargetId]);

  const updateField = <K extends keyof AwsDiscoveryConfigRequest>(key: K, value: AwsDiscoveryConfigRequest[K]) => {
    setForm((cur) => ({ ...cur, [key]: value }));
  };

  // ── Build payload ───────────────────────────────────────────────────────────
  const buildPayload = (): AwsDiscoveryConfigRequest => {
    return {
      ...form,
      regionsJson: JSON.stringify(selectedRegions),
      resourceTypesJson: '["EC2"]'
    };
  };

  // ── Actions ─────────────────────────────────────────────────────────────────
  const saveConnector = async (): Promise<AwsDiscoveryConfig | null> => {
    setSaving(true);
    setError('');
    setSaveNotice('');
    try {
      const payload = buildPayload();
      const saved = await api.saveAwsDiscoveryConfig(payload);
      queryClient.setQueryData(['aws-discovery-config'], saved);
      setForm(formFromConfig(saved));
      return saved;
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
      const result = await api.testAwsDiscoveryConnection();
      setTestResult(result);
      const refreshed = await api.getAwsDiscoveryConfig();
      queryClient.setQueryData(['aws-discovery-config'], refreshed);
      setForm(formFromConfig(refreshed));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTesting(false);
    }
  };

  const triggerSync = async (): Promise<void> => {
    setSyncing(true);
    setError('');
    setSyncResult(null);
    try {
      const saved = await saveConnector();
      if (!saved) return;
      const result = await api.triggerAwsDiscoverySync();
      setSyncResult(result);
      await queryClient.invalidateQueries({ queryKey: ['sync-runs'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSyncing(false);
    }
  };

  const refreshTargets = async () => {
    await queryClient.invalidateQueries({ queryKey: ['aws-discovery-targets'] });
  };

  const editTarget = (target: AwsDiscoveryTarget) => {
    setEditingTargetId(target.id);
    setTargetForm(targetToForm(target));
    setError('');
  };

  const resetTargetForm = () => {
    setEditingTargetId(null);
    setTargetForm(defaultTargetForm(config));
  };

  const saveTarget = async (): Promise<void> => {
    setTargetBusy('save');
    setError('');
    try {
      const savedConfig = await saveConnector();
      if (!savedConfig) return;
      if (editingTargetId) {
        await api.updateAwsDiscoveryTarget(editingTargetId, targetForm);
      } else {
        await api.createAwsDiscoveryTarget(targetForm);
      }
      resetTargetForm();
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const deleteTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      await api.deleteAwsDiscoveryTarget(targetId);
      if (editingTargetId === targetId) resetTargetForm();
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const testTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      const result = await api.testAwsDiscoveryTarget(targetId);
      setTestResult(result);
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const syncTarget = async (targetId: string): Promise<void> => {
    setTargetBusy(targetId);
    setError('');
    try {
      const result = await api.triggerAwsDiscoveryTargetSync(targetId);
      setSyncResult(result);
      await queryClient.invalidateQueries({ queryKey: ['sync-runs'] });
      await refreshTargets();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setTargetBusy('');
    }
  };

  const queryError = configQuery.error instanceof Error ? configQuery.error.message
    : targetsQuery.error instanceof Error ? targetsQuery.error.message : '';
  const displayError = error || queryError;

  if (configQuery.isPending && !config) {
    return <section className="panel">Loading AWS Cloud Discovery connector...</section>;
  }
  if (configQuery.isError && !configQuery.data) {
    return <ConnectorConfigLoadError connectorName="AWS Cloud Discovery" error={configQuery.error} onRetry={() => void configQuery.refetch()} retrying={configQuery.isFetching} />;
  }

  const intervalOptions = [
    { label: 'Hourly', minutes: 60 },
    { label: 'Every 6 hours', minutes: 360 },
    { label: 'Every 12 hours', minutes: 720 },
    { label: 'Daily', minutes: 1440 },
    { label: 'Weekly', minutes: 10080 }
  ];
  const roleConfigured = form.authType === 'CROSS_ACCOUNT_ROLE' || Boolean(form.crossAccountRoleArn?.trim());
  const targetRoleConfigured = Boolean(targetForm.roleArn?.trim());
  const showExternalIdWarning = roleConfigured && !form.externalId?.trim();
  const showTargetExternalIdWarning = targetRoleConfigured && !targetForm.externalId?.trim();

  return (
    <section className="panel">
      {/* Status row */}
      {config?.configured && (
        <div className="sn-status-row">
          {config.lastSyncAt ? (
            <span className="sn-status-meta">
              Last integration run: {formatTimestamp(config.lastSyncAt)}
              {config.awsAccountId && (
                <span className="sn-saved-badge" style={{ marginLeft: 12 }}>
                  Account: {config.awsAccountId}
                </span>
              )}
            </span>
          ) : (
            <span className="sn-status-meta">
              No integration run yet
              {config.awsAccountId && ` · Account: ${config.awsAccountId}`}
            </span>
          )}
        </div>
      )}

      {config?.lastTestStatus && (
        <div className={`notice ${testResultTone(config.lastTestStatus)}`}>
          <strong>Last AWS test: {config.lastTestStatus}</strong>
          {config.lastTestedAt && ` · ${formatTimestamp(config.lastTestedAt)}`}
          {config.lastTestMessage && (
            <div className="panel-caption" style={{ marginTop: 6, color: 'inherit' }}>
              {config.lastTestMessage}
            </div>
          )}
        </div>
      )}

      {!config?.configured && (
        <div className="notice">
          This connector is not yet configured. Select an authentication method and save.
        </div>
      )}

      {displayError && <div className="notice error">{displayError}</div>}
      {saveNotice && !displayError && <div className="notice success" role="status">{saveNotice}</div>}

      {/* ── Tab navigation ── */}
      <div className="connector-tab-bar">
        <button
          type="button"
          className={`connector-tab-btn${activeTab === 'connection' ? ' connector-tab-btn--active' : ''}`}
          onClick={() => setActiveTab('connection')}
        >
          Connection
        </button>
        <button
          type="button"
          className={`connector-tab-btn${activeTab === 'accounts' ? ' connector-tab-btn--active' : ''}`}
          onClick={() => setActiveTab('accounts')}
        >
          Multi-Account
        </button>
      </div>

      {/* ── Tab 1: Connection ── */}
      {activeTab === 'connection' && (
        <>
          {/* Authentication */}
          <div className="form-section">
            <h4 className="form-section-title">Authentication</h4>
            <div className="form-grid">
              <label>
                <span>
                  Auth Method <span className="sn-required">*</span>{' '}
                  <InfoTooltip text="Customer discovery assumes the configured IAM role using its server-generated External ID." />
                </span>
                <select
                  value={form.authType}
                  onChange={(e) => updateField('authType', e.target.value as AwsAuthType)}
                >
                  <option value="CROSS_ACCOUNT_ROLE">Cross-Account IAM Role</option>
                </select>
              </label>

              {form.authType === 'CROSS_ACCOUNT_ROLE' && (
                <>
                  <label>
                    <span>
                      Optional STS source Access Key ID
                    </span>
                    <input
                      type="text"
                      value={form.accessKeyId ?? ''}
                      onChange={(e) => updateField('accessKeyId', e.target.value)}
                      placeholder="Enter AWS access key ID"
                    />
                  </label>
                  <label>
                    <span>
                      Optional STS source Secret Access Key{' '}
                      <InfoTooltip text={config?.hasCredential ? 'A secret is saved. Enter a new value only to rotate it.' : 'Optional explicit credentials for assuming the customer role. Otherwise the configured runtime identity is used only for STS.'} />
                    </span>
                    <div className="secure-input-row">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={form.credentialSecret ?? ''}
                        onChange={(e) => updateField('credentialSecret', e.target.value)}
                        placeholder={config?.hasCredential ? 'Leave blank to keep saved secret' : 'Enter secret access key'}
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
                    {config?.hasCredential && (
                      <span className="sn-saved-badge">✓ Secret saved — leave blank to keep it</span>
                    )}
                  </label>
                </>
              )}

              {form.authType === 'CROSS_ACCOUNT_ROLE' && (
                <>
                  <label>
                    <span>
                      Cross-Account Role ARN <span className="sn-required">*</span>{' '}
                      <InfoTooltip text="The ARN of the IAM role in the target AWS account that VulnWatch should assume." />
                    </span>
                    <input
                      type="text"
                      value={form.crossAccountRoleArn ?? ''}
                      onChange={(e) => updateField('crossAccountRoleArn', e.target.value)}
                      placeholder="arn:aws:iam::123456789012:role/VulnWatchDiscoveryRole"
                    />
                  </label>
                  <label>
                    <span>
                      External ID{' '}
                      <InfoTooltip text="Generated by the server after saving. Add this value to the customer role trust policy before discovery." />
                    </span>
                    <input
                      type="text"
                      value={form.externalId ?? ''}
                      readOnly
                      placeholder="Save the connection to generate its External ID"
                    />
                  </label>
                </>
              )}

              {config?.awsAccountId && (
                <label>
                  <span>Bound AWS Account ID <InfoTooltip text="Bound to the configured customer role ARN." /></span>
                  <input type="text" value={config.awsAccountId} readOnly />
                </label>
              )}
            </div>
            {showExternalIdWarning && (
              <div className="notice warning" style={{ marginTop: 12 }}>
                <strong>Save to generate an External ID.</strong> Add the generated value to the customer role trust policy before testing or running discovery.
              </div>
            )}
          </div>

          {/* Regions */}
          <div className="form-section">
            <h4 className="form-section-title">Regions</h4>
            <fieldset className="aws-region-fieldset">
              <legend className="aws-region-legend">
                AWS Regions <span className="sn-required">*</span>{' '}
                <InfoTooltip text="Select one or more AWS regions to discover resources in." />
              </legend>
              <div className="aws-region-actions">
                <button type="button" className="btn btn-secondary btn-inline" onClick={() => setSelectedRegions([...AWS_REGIONS])}>Select all</button>
                <button type="button" className="btn btn-secondary btn-inline" onClick={() => setSelectedRegions([AWS_REGIONS[0]])}>Clear</button>
              </div>
              <div className="aws-region-grid">
                {AWS_REGIONS.map((region) => (
                  <label key={region} className="aws-region-checkbox">
                    <input
                      type="checkbox"
                      checked={selectedRegions.includes(region)}
                      onChange={(e) => {
                        setSelectedRegions((prev) => {
                          if (e.target.checked) return [...prev, region];
                          const next = prev.filter((r) => r !== region);
                          return next.length > 0 ? next : prev;
                        });
                      }}
                    />
                    <span>{region}</span>
                  </label>
                ))}
              </div>
              <span className="panel-caption" style={{ marginTop: 4, display: 'block' }}>
                Selected: {selectedRegions.join(', ') || '—'}
              </span>
            </fieldset>
          </div>

          {/* Sync Settings */}
          <div className="form-section">
            <h4 className="form-section-title">Sync Settings</h4>
            <div className="sn-toggle-group">
              <label className="sn-toggle-row">
                <input
                  type="checkbox"
                  checked={form.autoSyncEnabled ?? false}
                  onChange={(e) => updateField('autoSyncEnabled', e.target.checked)}
                />
                <span>Enable scheduled sync</span>
                <InfoTooltip text="Automatically discovers AWS resources on the configured interval." />
              </label>
            </div>
            {form.autoSyncEnabled && (
              <div className="form-grid sn-sync-interval-grid" style={{ marginTop: 8 }}>
                <label>
                  <span>Sync Interval <InfoTooltip text="How frequently the scheduled sync runs." /></span>
                  <select
                    value={form.intervalMinutes ?? 1440}
                    onChange={(e) => updateField('intervalMinutes', Number(e.target.value))}
                  >
                    {intervalOptions.map(({ label, minutes }) => (
                      <option key={minutes} value={minutes}>{label}</option>
                    ))}
                  </select>
                </label>
              </div>
            )}
          </div>

          {/* Connection tab action bar */}
          <div className="button-row section-actions sn-action-bar">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void saveConnector().then((saved) => { if (saved) setSaveNotice('Connector settings saved.'); })}
              disabled={!canManageConnector || saving || testing || syncing}
            >
              {saving ? 'Saving...' : 'Save Connector'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void testConnection()}
              disabled={!canManageConnector || testing || saving || syncing}
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void triggerSync()}
              disabled={!canManageConnector || syncing || saving || testing}
            >
              {syncing ? 'Running...' : 'Run Integration Now'}
            </button>
          </div>

          {testResult && (
            <div className={`notice sn-test-result ${testResultTone(testResult.status)}`}>
              <strong>{testResultLabel(testResult.status)}</strong>
              {' — '}{testResult.message}
              {!isFailedStatus(testResult.status) && testResult.reachableRegions.length > 0 && (
                <span className="sn-table-checks">
                  Reachable regions: {testResult.reachableRegions.join(', ')}
                </span>
              )}
              {testResult.warnings.length > 0 && (
                <div className="panel-caption" style={{ marginTop: 6 }}>
                  Warnings: {testResult.warnings.join(' | ')}
                </div>
              )}
            </div>
          )}

          {syncResult && (
            <div className="notice">
              <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
              <a href={pathForConnectView('run-history')}>Integration Run Queue</a>.
            </div>
          )}
        </>
      )}

      {/* ── Tab 2: Multi-Account ── */}
      {activeTab === 'accounts' && (
        <>
          <div className="form-section">
            <h4 className="form-section-title">AWS Account Targets</h4>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Account</th>
                    <th>Role</th>
                    <th>Regions</th>
                    <th>Status</th>
                    <th>SSM Coverage</th>
                    <th>Last Sync</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.length === 0 && (
                    <tr>
                      <td colSpan={7} className="empty-state">No AWS accounts configured yet.</td>
                    </tr>
                  )}
                  {targets.map((target) => (
                    <tr key={target.id}>
                      <td>
                        <strong>{target.accountName || target.accountId || 'AWS Account'}</strong>
                        <span className="panel-caption" style={{ display: 'block' }}>{target.accountId || 'Account ID unresolved'}</span>
                      </td>
                      <td><span className="panel-caption">{target.roleArn || 'Connector credentials'}</span></td>
                      <td><span className="panel-caption">{parseRegions(target.regionsJson).join(', ')}</span></td>
                      <td>
                        <span className={target.enabled ? 'status-pill status-success' : 'status-pill'}>
                          {target.enabled ? 'Enabled' : 'Disabled'}
                        </span>
                        {target.lastTestStatus && <span className="panel-caption" style={{ display: 'block' }}>{target.lastTestStatus}</span>}
                        {target.lastTestMessage && <span className="panel-caption" style={{ display: 'block', marginTop: 4 }}>{target.lastTestMessage}</span>}
                      </td>
                      <td>
                        <span>{target.softwareInventoryHostCount}/{target.hostCount} with inventory</span>
                        <span className="panel-caption" style={{ display: 'block' }}>
                          SSM {target.ssmManagedHostCount}, missing IAM {target.missingIamInstanceProfileCount}
                        </span>
                      </td>
                      <td>{formatTimestamp(target.lastSyncAt)}</td>
                      <td>
                        <div className="button-row">
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => editTarget(target)} disabled={!canManageConnector}>Edit</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void testTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Test</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void syncTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Sync</button>
                          <button type="button" className="btn btn-secondary btn-inline" onClick={() => void deleteTarget(target.id)} disabled={!canManageConnector || Boolean(targetBusy)}>Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="form-grid" style={{ marginTop: 16 }}>
              <label>
                <span>Account name</span>
                <input
                  type="text"
                  value={targetForm.accountName ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, accountName: e.target.value }))}
                  placeholder="Production shared services"
                />
              </label>
              <label>
                <span>Account ID</span>
                <input
                  type="text"
                  value={targetForm.accountId ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, accountId: e.target.value }))}
                  placeholder="123456789012"
                />
              </label>
              <label>
                <span>Role ARN</span>
                <input
                  type="text"
                  value={targetForm.roleArn ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, roleArn: e.target.value }))}
                  placeholder="arn:aws:iam::123456789012:role/ScoutDiscoveryReadOnlyRole"
                />
              </label>
              <label>
                <span>External ID</span>
                <input
                  type="text"
                  value={targetForm.externalId ?? ''}
                  readOnly
                  placeholder="optional-external-id"
                />
              </label>
              <label>
                <span>Regions JSON</span>
                <input
                  type="text"
                  value={targetForm.regionsJson ?? ''}
                  onChange={(e) => setTargetForm((cur) => ({ ...cur, regionsJson: e.target.value }))}
                  placeholder='["us-east-1"]'
                />
              </label>
            </div>
            {showTargetExternalIdWarning && (
              <div className="notice warning" style={{ marginTop: 12 }}>
                <strong>Save to generate an External ID.</strong> Add the generated value to this customer role trust policy before discovery.
              </div>
            )}
            <label className="sn-toggle-row" style={{ marginTop: 8 }}>
              <input
                type="checkbox"
                checked={targetForm.enabled ?? true}
                onChange={(e) => setTargetForm((cur) => ({ ...cur, enabled: e.target.checked }))}
              />
              <span>Enable this account target</span>
            </label>
            <div className="button-row section-actions">
              <button type="button" className="btn btn-primary" onClick={() => void saveTarget()} disabled={Boolean(targetBusy) || saving}>
                {targetBusy === 'save' ? 'Saving...' : editingTargetId ? 'Update Account' : 'Add Account'}
              </button>
              {editingTargetId && (
                <button type="button" className="btn btn-secondary" onClick={resetTargetForm} disabled={Boolean(targetBusy)}>
                  Cancel
                </button>
              )}
            </div>
          </div>

          {/* Accounts tab action bar */}
          <div className="button-row section-actions sn-action-bar">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void saveConnector().then((saved) => { if (saved) setSaveNotice('Connector settings saved.'); })}
              disabled={!canManageConnector || saving || testing || syncing}
            >
              {saving ? 'Saving...' : 'Save Connector'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void testConnection()}
              disabled={!canManageConnector || testing || saving || syncing}
            >
              {testing ? 'Testing...' : 'Test Connection'}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void triggerSync()}
              disabled={!canManageConnector || syncing || saving || testing}
            >
              {syncing ? 'Running...' : 'Run Integration Now'}
            </button>
          </div>

          {testResult && (
            <div className={`notice sn-test-result ${testResultTone(testResult.status)}`}>
              <strong>{testResultLabel(testResult.status)}</strong>
              {' — '}{testResult.message}
              {!isFailedStatus(testResult.status) && testResult.reachableRegions.length > 0 && (
                <span className="sn-table-checks">
                  Reachable regions: {testResult.reachableRegions.join(', ')}
                </span>
              )}
              {testResult.warnings.length > 0 && (
                <div className="panel-caption" style={{ marginTop: 6 }}>
                  Warnings: {testResult.warnings.join(' | ')}
                </div>
              )}
            </div>
          )}

          {syncResult && (
            <div className="notice">
              <strong>Integration queued.</strong> {syncResult.message}. Track progress in{' '}
              <a href={pathForConnectView('run-history')}>Integration Run Queue</a>.
            </div>
          )}
        </>
      )}

      <div className="button-row section-actions">
        <a className="btn-link" href={pathForInventoryView('hosts')}>
          View Host Inventory →
        </a>
      </div>
    </section>
  );
}
