import React from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { InfoTooltip } from '../components/InfoTooltip';
import { useActor } from '../features/auth/context';
import { canManageInventorySources } from '../features/auth/roles';
import type {
  JiraAuthType,
  JiraConnectionTest,
  JiraTicketingConfig,
  JiraTicketingConfigRequest
} from '../features/connect/types';
import { useJiraTicketingConfigQuery, useTicketingProviderStatusQuery } from '../features/connect/queries';
import { formatTimestamp } from '../lib/time';

function defaultForm(): JiraTicketingConfigRequest {
  return {
    baseUrl: '',
    authType: 'BASIC',
    username: '',
    projectKey: '',
    issueTypeId: '',
    issueTypeName: 'Task',
    defaultLabels: '',
    includePriority: true,
    enabled: true
  };
}

function formFromConfig(config: JiraTicketingConfig | null): JiraTicketingConfigRequest {
  if (!config) return defaultForm();
  return {
    baseUrl: config.baseUrl ?? '',
    authType: config.authType ?? 'BASIC',
    username: config.username ?? '',
    projectKey: config.projectKey ?? '',
    issueTypeId: config.issueTypeId ?? '',
    issueTypeName: config.issueTypeName ?? 'Task',
    defaultLabels: config.defaultLabels ?? '',
    includePriority: config.includePriority,
    enabled: config.enabled
  };
}

export function JiraTicketingConnectorPage() {
  const actor = useActor();
  const canManageConnector = canManageInventorySources(actor);
  const queryClient = useQueryClient();
  const jiraConfigQuery = useJiraTicketingConfigQuery();
  const ticketingStatusQuery = useTicketingProviderStatusQuery();
  const config = jiraConfigQuery.data ?? null;
  const ticketingStatus = ticketingStatusQuery.data ?? null;

  const [form, setForm] = React.useState<JiraTicketingConfigRequest>(defaultForm);
  const [credentialSecret, setCredentialSecret] = React.useState('');
  const [testResult, setTestResult] = React.useState<JiraConnectionTest | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);
  const [error, setError] = React.useState('');
  const [showSecret, setShowSecret] = React.useState(false);

  React.useEffect(() => {
    setForm(formFromConfig(config));
    setCredentialSecret('');
  }, [config]);

  const updateField = <K extends keyof JiraTicketingConfigRequest>(
    key: K,
    value: JiraTicketingConfigRequest[K]
  ) => {
    setForm((current) => ({ ...current, [key]: value }));
  };

  const saveConnector = async (): Promise<JiraTicketingConfig | null> => {
    setSaving(true);
    setError('');
    try {
      const payload: JiraTicketingConfigRequest = {
        ...form,
        baseUrl: form.baseUrl?.trim() ?? '',
        username: form.authType === 'BASIC' ? form.username?.trim() ?? '' : '',
        // Omitted rather than blank, so the backend keeps the stored token.
        credentialSecret: credentialSecret.trim().length > 0 ? credentialSecret.trim() : undefined,
        projectKey: form.projectKey?.trim().toUpperCase() ?? '',
        issueTypeId: form.issueTypeId?.trim() ?? '',
        issueTypeName: form.issueTypeName?.trim() || 'Task',
        defaultLabels: form.defaultLabels?.trim() ?? ''
      };
      const saved = await api.saveJiraTicketingConfig(payload);
      queryClient.setQueryData(['jira-ticketing-config'], saved);
      // Saving or disabling Jira changes which system owns new tickets.
      void queryClient.invalidateQueries({ queryKey: ['ticketing-provider-status'] });
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
    setTesting(true);
    setError('');
    setTestResult(null);
    try {
      // Test against what is on screen, not what was last saved.
      const saved = await saveConnector();
      if (!saved) return;
      setTestResult(await api.testJiraTicketingConnection());
      void queryClient.invalidateQueries({ queryKey: ['jira-ticketing-config'] });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : String(requestError));
    } finally {
      setTesting(false);
    }
  };

  if (jiraConfigQuery.isLoading) {
    return <section className="panel">Loading Jira connector...</section>;
  }

  const jiraIsActive = ticketingStatus?.activeProvider === 'jira';
  const overridesServiceNow = jiraIsActive && (ticketingStatus?.overridden ?? []).includes('servicenow');

  return (
    <section className="panel">
      {config?.configured && config.lastTestedAt && (
        <div className="sn-status-row">
          <span className="sn-status-meta">Last connection test: {formatTimestamp(config.lastTestedAt)}</span>
        </div>
      )}

      {!config?.configured && (
        <div className="notice">
          This connector is not yet configured. Fill in the Connection section below. Once Jira is
          enabled it takes over ticketing from ServiceNow for all new findings.
        </div>
      )}

      {overridesServiceNow && (
        <div className="notice">
          <strong>Jira is the active ticketing system.</strong> New finding tickets are raised in
          Jira instead of ServiceNow. Tickets already raised in ServiceNow keep their incident
          numbers and continue to sync from ServiceNow.
        </div>
      )}

      {config?.configured && !config.enabled && (
        <div className="notice">
          This connector is saved but disabled, so ticketing falls back to ServiceNow. Re-enable it
          below to route new tickets to Jira.
        </div>
      )}

      {error && <div className="notice error">{error}</div>}

      <div className="form-section">
        <h4 className="form-section-title">Connection</h4>
        <div className="form-grid">
          <label>
            <span>
              Base URL <span className="sn-required">*</span>{' '}
              <InfoTooltip text="Your Jira site URL, with no trailing path. The host must also be present in the 'jira=' entry of HTTP_OUTBOUND_ALLOWED_HOSTS." />
            </span>
            <input
              type="text"
              value={form.baseUrl ?? ''}
              onChange={(e) => updateField('baseUrl', e.target.value)}
              placeholder="https://your-org.atlassian.net"
            />
          </label>

          <label>
            <span>
              Auth Method <span className="sn-required">*</span>{' '}
              <InfoTooltip text="Basic is Jira Cloud: an account email plus an API token. Bearer is a Jira Data Center personal access token." />
            </span>
            <select
              value={form.authType}
              onChange={(e) => updateField('authType', e.target.value as JiraAuthType)}
            >
              <option value="BASIC">Email + API token (Jira Cloud)</option>
              <option value="BEARER">Personal access token (Data Center)</option>
            </select>
          </label>

          {form.authType === 'BASIC' && (
            <label>
              <span>
                Account Email <span className="sn-required">*</span>{' '}
                <InfoTooltip text="The Atlassian account that owns the API token. It needs Create Issues on the target project." />
              </span>
              <input
                type="text"
                value={form.username ?? ''}
                onChange={(e) => updateField('username', e.target.value)}
                placeholder="svc-scout@your-org.com"
              />
            </label>
          )}

          <label>
            <span>
              {form.authType === 'BASIC' ? 'API Token' : 'Personal Access Token'}{' '}
              <span className="sn-required">*</span>{' '}
              <InfoTooltip
                text={config?.hasCredentialSecret
                  ? 'A token is already saved. Enter a new value only to rotate it.'
                  : 'Required before tickets can be raised.'}
              />
            </span>
            <div className="secure-input-row">
              <input
                type={showSecret ? 'text' : 'password'}
                value={credentialSecret}
                onChange={(e) => setCredentialSecret(e.target.value)}
                placeholder={config?.hasCredentialSecret ? 'Leave blank to keep saved token' : 'Enter API token'}
              />
              <button
                type="button"
                className="btn btn-secondary btn-inline"
                onClick={() => setShowSecret((v) => !v)}
                aria-label={showSecret ? 'Hide token' : 'Show token'}
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
            {config?.hasCredentialSecret && (
              <span className="sn-saved-badge">✓ Token saved — leave blank to keep it</span>
            )}
          </label>
        </div>
      </div>

      <div className="form-section">
        <h4 className="form-section-title">Issue Mapping</h4>
        <div className="form-grid">
          <label>
            <span>
              Project Key <span className="sn-required">*</span>{' '}
              <InfoTooltip text="The Jira project that receives remediation tickets, e.g. SEC." />
            </span>
            <input
              type="text"
              value={form.projectKey ?? ''}
              onChange={(e) => updateField('projectKey', e.target.value)}
              placeholder="SEC"
              maxLength={64}
            />
          </label>

          <label>
            <span>
              Issue Type Name{' '}
              <InfoTooltip text="Used when no issue type id is set. Must match an issue type available on the project's create screen." />
            </span>
            <input
              type="text"
              value={form.issueTypeName ?? ''}
              onChange={(e) => updateField('issueTypeName', e.target.value)}
              placeholder="Task"
            />
          </label>

          <label>
            <span>
              Issue Type ID{' '}
              <InfoTooltip text="Optional but more reliable than the name, which is not unique across issue type schemes. Takes precedence when set." />
            </span>
            <input
              type="text"
              value={form.issueTypeId ?? ''}
              onChange={(e) => updateField('issueTypeId', e.target.value)}
              placeholder="10004"
            />
          </label>

          <label>
            <span>
              Default Labels{' '}
              <InfoTooltip text="Comma-separated labels added to every ticket, alongside the automatic 'scout' label and the finding id. Spaces become hyphens." />
            </span>
            <input
              type="text"
              value={form.defaultLabels ?? ''}
              onChange={(e) => updateField('defaultLabels', e.target.value)}
              placeholder="security, vulnerability-management"
            />
          </label>
        </div>
      </div>

      <div className="form-section">
        <h4 className="form-section-title">Behaviour</h4>
        <div className="form-grid">
          <label>
            <span>
              Send Priority{' '}
              <InfoTooltip text="Maps finding severity onto Jira's default priority names. Turn this off if your project has removed Priority from its create screen, which makes Jira reject the field." />
            </span>
            <select
              value={form.includePriority ? 'yes' : 'no'}
              onChange={(e) => updateField('includePriority', e.target.value === 'yes')}
            >
              <option value="yes">Map severity to Jira priority</option>
              <option value="no">Do not send a priority</option>
            </select>
          </label>

          <label>
            <span>
              Connector Enabled{' '}
              <InfoTooltip text="While enabled, Jira overrides ServiceNow for new finding tickets. Disable it to hand ticketing back to ServiceNow." />
            </span>
            <select
              value={form.enabled ? 'yes' : 'no'}
              onChange={(e) => updateField('enabled', e.target.value === 'yes')}
            >
              <option value="yes">Enabled — Jira receives new tickets</option>
              <option value="no">Disabled — fall back to ServiceNow</option>
            </select>
          </label>
        </div>
      </div>

      <div className="button-row section-actions sn-action-bar">
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => void saveConnector()}
          disabled={!canManageConnector || saving || testing}
        >
          {saving ? 'Saving...' : 'Save Connector'}
        </button>
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => void testConnection()}
          disabled={!canManageConnector || testing || saving}
        >
          {testing ? 'Testing...' : 'Test Connection'}
        </button>
      </div>

      {!canManageConnector && (
        <div className="notice">
          You need the Tenant Admin or Inventory Admin role to change this connector.
        </div>
      )}

      {testResult && (
        <div className={`notice sn-test-result ${testResult.status === 'SUCCESS' ? 'success' : 'error'}`}>
          <strong>{testResult.status === 'SUCCESS' ? '✓ Connection successful' : '✗ Connection failed'}</strong>
          {' — '}{testResult.message}
          <span className="sn-table-checks">
            <span className={testResult.credentialsValid ? 'sn-check-ok' : 'sn-check-fail'}>
              Credentials {testResult.credentialsValid ? '✓' : '✗'}
            </span>
            <span className={testResult.projectReachable ? 'sn-check-ok' : 'sn-check-fail'}>
              Project {testResult.projectReachable ? '✓' : '✗'}
            </span>
          </span>
        </div>
      )}
    </section>
  );
}
