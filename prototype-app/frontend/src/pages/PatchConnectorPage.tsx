import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { InfoTooltip } from '../components/InfoTooltip';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import { fixIntelligenceApi } from '../features/fix-intelligence/api';
import type { PatchConnectionTest, PatchConnectorConfigRequest, PatchProvider } from '../features/fix-intelligence/types';
import { formatTimestamp } from '../lib/time';

type ProviderCopy = {
  intro: string;
  baseUrl?: { label: string; placeholder: string; hint: string };
  directory?: boolean;
  username?: boolean;
  secret?: { label: string; hint: string };
};

const PROVIDER_COPY: Record<PatchProvider, ProviderCopy> = {
  sccm: {
    intro: 'Reads software updates, compliance state and deployments from the SCCM/MECM site database, '
      + 'using the SQL connection already configured on the SCCM/MECM inventory connector.'
  },
  intune: {
    intro: 'Reads managed devices, Windows update status and quality update profiles through Microsoft Graph. '
      + 'Register an Entra application with DeviceManagementManagedDevices.Read.All and '
      + 'DeviceManagementConfiguration.Read.All (application permissions, admin consent).',
    directory: true,
    secret: { label: 'Client secret', hint: 'Stored encrypted and never shown again. Leave blank to keep the saved secret.' }
  },
  bigfix: {
    intro: 'Reads computers, Fixlets and actions from the BigFix REST API with a read-only operator. '
      + 'The server host must be on the operator-approved BigFix host list.',
    baseUrl: { label: 'BigFix server URL', placeholder: 'https://bigfix.corp.example.com:52311', hint: 'HTTPS only. The host must be listed in BIGFIX_ALLOWED_HOSTS on the Scout backend.' },
    username: true,
    secret: { label: 'Password', hint: 'Stored encrypted and never shown again. Leave blank to keep the saved password.' }
  },
  tanium: {
    intro: 'Reads endpoints and patch status from the Tanium Cloud Gateway API with a read-only API token.',
    baseUrl: { label: 'Tanium Cloud API URL', placeholder: 'https://acme-api.cloud.tanium.com', hint: 'Must be your *.cloud.tanium.com API host.' },
    secret: { label: 'API token', hint: 'Stored encrypted and never shown again. Leave blank to keep the saved token.' }
  }
};

export function PatchConnectorPage({ provider }: { provider: PatchProvider }): React.ReactElement {
  const actor = useActor();
  const canManage = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const copy = PROVIDER_COPY[provider];
  const configQuery = useQuery({
    queryKey: ['patch-connector', provider],
    queryFn: () => fixIntelligenceApi.getPatchConnector(provider)
  });
  const config = configQuery.data;

  const [baseUrl, setBaseUrl] = React.useState('');
  const [directoryId, setDirectoryId] = React.useState('');
  const [clientId, setClientId] = React.useState('');
  const [username, setUsername] = React.useState('');
  const [secret, setSecret] = React.useState('');
  const [enabled, setEnabled] = React.useState(true);
  const [autoSync, setAutoSync] = React.useState(false);
  const [intervalHours, setIntervalHours] = React.useState(24);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [testResult, setTestResult] = React.useState<PatchConnectionTest | null>(null);

  React.useEffect(() => {
    if (!config) return;
    setBaseUrl(config.baseUrl ?? '');
    setDirectoryId(config.directoryId ?? '');
    setClientId(config.clientId ?? '');
    setUsername(config.username ?? '');
    setEnabled(config.enabled);
    setAutoSync(config.autoSyncEnabled);
    setIntervalHours(Math.max(1, Math.round(config.intervalMinutes / 60)));
  }, [config]);

  const onFailure = (failure: Error) => { setNotice(null); setError(failure.message); };
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['patch-connector', provider] });

  const save = useMutation({
    mutationFn: () => {
      const payload: PatchConnectorConfigRequest = {
        baseUrl: copy.baseUrl ? baseUrl.trim() || null : null,
        directoryId: copy.directory ? directoryId.trim() || null : null,
        clientId: copy.directory ? clientId.trim() || null : null,
        username: copy.username ? username.trim() || null : null,
        enabled,
        autoSyncEnabled: autoSync,
        intervalMinutes: intervalHours * 60
      };
      // Write-only: only send a secret the user actually typed.
      if (secret) payload.secret = secret;
      return fixIntelligenceApi.savePatchConnector(provider, payload);
    },
    onSuccess: () => { setSecret(''); setError(null); setNotice('Configuration saved.'); void refresh(); },
    onError: onFailure
  });
  const test = useMutation({
    mutationFn: () => fixIntelligenceApi.testPatchConnector(provider),
    onSuccess: (result) => { setTestResult(result); setError(null); setNotice(null); void refresh(); },
    onError: onFailure
  });
  const sync = useMutation({
    mutationFn: () => fixIntelligenceApi.syncPatchConnector(provider),
    onSuccess: () => { setError(null); setNotice('Patch sync queued. Results appear in Fix Intelligence → Patches.'); },
    onError: onFailure
  });

  if (configQuery.isPending) return <section className="panel">Loading {provider.toUpperCase()} patch connector...</section>;
  if (configQuery.isError) return <section className="panel"><div className="notice error">{configQuery.error.message}</div></section>;

  const busy = save.isPending || test.isPending || sync.isPending;

  return (
    <section className="panel" aria-label={`${config?.displayName ?? provider} patch connector`}>
      {config?.lastSyncAt && (
        <div className="sn-status-row">
          <span className="sn-status-meta">Last patch sync: {formatTimestamp(config.lastSyncAt)}</span>
        </div>
      )}
      <div className="notice">{copy.intro}</div>
      {error && <div className="notice error" role="alert">{error}</div>}
      {notice && <div className="notice">{notice}</div>}

      {(copy.baseUrl || copy.directory || copy.username || copy.secret) && (
        <div className="form-section">
          <h4 className="form-section-title">Connection</h4>
          <div className="form-grid">
            {copy.baseUrl && (
              <label>
                <span>{copy.baseUrl.label} <InfoTooltip text={copy.baseUrl.hint} /></span>
                <input type="url" value={baseUrl} placeholder={copy.baseUrl.placeholder} disabled={!canManage}
                       onChange={(event) => setBaseUrl(event.target.value)} />
              </label>
            )}
            {copy.directory && (
              <>
                <label>
                  <span>Directory (tenant) ID</span>
                  <input type="text" value={directoryId} placeholder="00000000-0000-0000-0000-000000000000" disabled={!canManage}
                         onChange={(event) => setDirectoryId(event.target.value)} />
                </label>
                <label>
                  <span>Application (client) ID</span>
                  <input type="text" value={clientId} placeholder="00000000-0000-0000-0000-000000000000" disabled={!canManage}
                         onChange={(event) => setClientId(event.target.value)} />
                </label>
              </>
            )}
            {copy.username && (
              <label>
                <span>Username</span>
                <input type="text" value={username} autoComplete="off" disabled={!canManage}
                       onChange={(event) => setUsername(event.target.value)} />
              </label>
            )}
            {copy.secret && (
              <label>
                <span>{copy.secret.label} <InfoTooltip text={copy.secret.hint} /></span>
                <input type="password" value={secret} autoComplete="new-password" disabled={!canManage}
                       placeholder={config?.hasSecret ? 'Leave blank to keep the saved value' : ''}
                       onChange={(event) => setSecret(event.target.value)} />
                {config?.hasSecret && <span className="sn-saved-badge">✓ Saved — leave blank to keep it</span>}
              </label>
            )}
          </div>
        </div>
      )}

      <div className="form-section">
        <h4 className="form-section-title">Sync Settings</h4>
        <div className="sn-toggle-group">
          <label className="sn-toggle-row">
            <input type="checkbox" checked={enabled} disabled={!canManage} onChange={(event) => setEnabled(event.target.checked)} />
            <span>Connector enabled</span>
          </label>
          <label className="sn-toggle-row">
            <input type="checkbox" checked={autoSync} disabled={!canManage} onChange={(event) => setAutoSync(event.target.checked)} />
            <span>Enable scheduled patch sync</span>
          </label>
        </div>
        {autoSync && (
          <div className="form-grid sn-sync-interval-grid">
            <label>
              <span>Sync interval (hours)</span>
              <input type="number" min={1} value={intervalHours} disabled={!canManage}
                     onChange={(event) => setIntervalHours(Math.max(1, Number(event.target.value) || 1))} />
            </label>
          </div>
        )}
      </div>

      {testResult && (
        <div className="form-section" aria-label="Connection test result">
          <h4 className="form-section-title">Connection test · {testResult.status.replace(/_/g, ' ').toLowerCase()}</h4>
          <p className="panel-caption">{testResult.message}</p>
          <ul>
            {testResult.checks.map((check) => (
              <li key={check.name}>
                {check.passed ? '✓' : '✗'} {check.name}{!check.required && ' (optional)'}
                {check.detail && <span className="panel-caption"> — {check.detail}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {!testResult && config?.lastTestStatus && (
        <p className="panel-caption">
          Last test {config.lastTestStatus.replace(/_/g, ' ').toLowerCase()} · {formatTimestamp(config.lastTestedAt)}
          {config.lastTestMessage && ` — ${config.lastTestMessage}`}
        </p>
      )}

      {canManage ? (
        <div className="button-row section-actions sn-action-bar">
          <button type="button" className="btn btn-primary" disabled={busy} onClick={() => save.mutate()}>Save Configuration</button>
          <button type="button" className="btn btn-secondary" disabled={busy || !config?.configured} onClick={() => test.mutate()}>
            Test Connection
          </button>
          <button type="button" className="btn btn-secondary" disabled={busy || !config?.configured || !config.enabled}
                  onClick={() => sync.mutate()}>
            Sync Now
          </button>
        </div>
      ) : (
        <p className="panel-caption">Only tenant or inventory administrators can change this connector.</p>
      )}
    </section>
  );
}
