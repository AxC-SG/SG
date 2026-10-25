import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../api/client';
import type { AiSecurityAzureConnectionTest } from '../features/ai-security/types';

export function AiSecurityAzureConnectorPage() {
  const queryClient = useQueryClient();
  const configQuery = useQuery({
    queryKey: ['ai-security-azure-foundry-config'],
    queryFn: api.getAiSecurityAzureFoundryConfig,
  });
  const flagsQuery = useQuery({
    queryKey: ['ai-security-feature-flags'],
    queryFn: api.listAiSecurityConnectorFeatureFlags,
  });
  const updateFlag = useMutation({
    mutationFn: ({ featureKey, enabled }: { featureKey: string; enabled: boolean }) =>
      api.updateAiSecurityConnectorFeatureFlag(featureKey, { enabled, killSwitch: false }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-feature-flags'] }),
  });
  const runsQuery = useQuery({
    queryKey: ['ai-security-runs', 'AZURE'],
    queryFn: () => api.listAiSecurityRuns('AZURE'),
    refetchInterval: 3000,
  });
  const latestRunId = runsQuery.data?.[0]?.id;
  const latestSuccessfulRun = runsQuery.data?.find((run) => run.status === 'COMPLETED');
  const scopesQuery = useQuery({
    queryKey: ['ai-security-run-scopes', latestRunId],
    queryFn: () => api.listAiSecurityRunScopes(latestRunId as string),
    enabled: latestRunId != null,
  });

  const [foundryEndpointUrl, setFoundryEndpointUrl] = React.useState('');
  const [azureTenantId, setAzureTenantId] = React.useState('');
  const [clientId, setClientId] = React.useState('');
  const [clientSecret, setClientSecret] = React.useState('');
  const [subscriptionIds, setSubscriptionIds] = React.useState('');
  const [region, setRegion] = React.useState('eastus2');
  const [testResult, setTestResult] = React.useState<AiSecurityAzureConnectionTest | null>(null);
  const [runMessage, setRunMessage] = React.useState<string | null>(null);

  React.useEffect(() => {
    const config = configQuery.data;
    if (!config) return;
    setFoundryEndpointUrl(config.foundryEndpointUrl ?? '');
    setAzureTenantId(config.azureTenantId ?? '');
    setClientId(config.clientId ?? '');
    setSubscriptionIds(config.subscriptionIds.join(', '));
    if (config.regions.length > 0) setRegion(config.regions.join(', '));
  }, [configQuery.data]);

  const configured = configQuery.data?.configured ?? false;

  const saveMutation = useMutation({
    mutationFn: () => api.saveAiSecurityAzureFoundryConfig({
      foundryEndpointUrl: foundryEndpointUrl || undefined,
      azureTenantId,
      clientId,
      clientSecret: clientSecret || undefined,
      subscriptionIds,
      region: region || undefined,
    }),
    onSuccess: () => {
      setClientSecret('');
      void queryClient.invalidateQueries({ queryKey: ['ai-security-azure-foundry-config'] });
    },
  });
  const testMutation = useMutation({
    mutationFn: api.testAiSecurityAzureFoundryConfig,
    onSuccess: setTestResult,
  });
  const runMutation = useMutation({
    mutationFn: api.runAiSecurityAzureFoundryConfig,
    onSuccess: (result: { jobId: string; status: string; message: string }) => {
      setRunMessage(`${result.message} Status: ${result.status}.`);
      void queryClient.invalidateQueries({ queryKey: ['ingestion-jobs'] });
      void queryClient.invalidateQueries({ queryKey: ['sync-runs'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-security-runs', 'AZURE'] });
    },
    onError: (error: Error) => setRunMessage(`Execution failed: ${error.message}`),
  });

  const error = saveMutation.error ?? testMutation.error ?? runMutation.error;

  return (
    <div className="ai-connector-layout">
      <section className="ai-security-hero connector">
        <div>
          <span className="ai-security-kicker">Inventory · AI · Azure</span>
          <h2>Azure Foundry configuration</h2>
          <p>Enter connection details, test backend reachability, then start ingestion.</p>
        </div>
        <span className={`status-pill ${configured ? 'success' : 'muted'}`}>
          {configQuery.isLoading ? 'Loading' : configured ? 'Success' : 'Not configured'}
        </span>
      </section>

      <div className="ai-connector-columns">
        <section className="panel ai-connector-form">
          <div className="panel-header">
            <div>
              <h3>Connection</h3>
              <span className="panel-caption">One form configures Azure Cloud Discovery and AI Security together.</span>
            </div>
          </div>
          <fieldset disabled={flagsQuery.isLoading || updateFlag.isPending}>
            <legend>Agent discovery</legend>
            <p>Enable the agent types to include in discovery, then execute the connector.</p>
            {[
              ['AZURE_NEW_FOUNDRY', 'Foundry agents'],
              ['AZURE_CLASSIC_FOUNDRY', 'Classic Foundry agents'],
            ].map(([featureKey, label]) => {
              const flag = flagsQuery.data?.find(item => item.featureKey === featureKey);
              return <label key={featureKey}>
                <input type="checkbox" checked={flag?.enabled === true && !flag.killSwitch}
                  disabled={flag?.killSwitch === true}
                  onChange={event => updateFlag.mutate({ featureKey, enabled: event.target.checked })} />
                {label}{flag?.killSwitch && ' (paused by emergency stop)'}
              </label>;
            })}
            {flagsQuery.data && !flagsQuery.data.some(flag =>
              ['AZURE_NEW_FOUNDRY', 'AZURE_CLASSIC_FOUNDRY'].includes(flag.featureKey) && flag.enabled && !flag.killSwitch)
              && <div className="notice">Agent discovery is disabled. Runs will collect supporting Azure resources but no agents.</div>}
            {(flagsQuery.error || updateFlag.error) && <div className="notice error">Unable to update agent discovery settings.</div>}
          </fieldset>
          <label>
            Foundry endpoint URL
            <input
              value={foundryEndpointUrl}
              onChange={(event) => setFoundryEndpointUrl(event.target.value)}
              placeholder="https://<resource>.services.ai.azure.com"
            />
          </label>
          <label>Tenant ID<input value={azureTenantId} onChange={(event) => setAzureTenantId(event.target.value)} /></label>
          <label>Client ID<input value={clientId} onChange={(event) => setClientId(event.target.value)} /></label>
          <label>
            Client secret
            <input
              type="password"
              autoComplete="new-password"
              value={clientSecret}
              onChange={(event) => setClientSecret(event.target.value)}
              placeholder={configured ? 'Leave blank to keep the current secret' : 'Required'}
            />
          </label>
          <label>Subscription IDs<input value={subscriptionIds} onChange={(event) => setSubscriptionIds(event.target.value)} placeholder="sub-id-1, sub-id-2" /></label>
          <label>Region<input value={region} onChange={(event) => setRegion(event.target.value)} placeholder="eastus2" /></label>
          {error && <div className="notice error">{error instanceof Error ? error.message : String(error)}</div>}
          {latestSuccessfulRun && (
            <div className="notice success">
              Last run completed with {latestSuccessfulRun.recordsFetched.toLocaleString()} artifact{latestSuccessfulRun.recordsFetched === 1 ? '' : 's'} discovered.
            </div>
          )}
          {testResult && (
            <div className={`notice ${testResult.success ? 'success' : 'error'}`}>
              <strong>{testResult.message}</strong>
              {!testResult.success && testResult.code && <small>Code: {testResult.code}</small>}
            </div>
          )}
          {runMessage && <div className={`notice ${runMessage.startsWith('Execution failed') ? 'error' : 'success'}`}>{runMessage}</div>}
          <div className="ai-connector-actions">
            <button
              className="btn btn-secondary"
              type="button"
              onClick={() => saveMutation.mutate()}
              disabled={!azureTenantId || !clientId || !subscriptionIds || (!configured && !clientSecret) || saveMutation.isPending}
            >
              {saveMutation.isPending ? 'Saving…' : 'Save configuration'}
            </button>
            <button className="btn btn-secondary" type="button" onClick={() => testMutation.mutate()} disabled={!configured || testMutation.isPending}>
              {testMutation.isPending ? 'Testing…' : 'Test connection'}
            </button>
            <button className="btn btn-primary" type="button" onClick={() => runMutation.mutate()} disabled={!configured || runMutation.isPending}>
              {runMutation.isPending ? 'Queuing…' : 'Execute now'}
            </button>
          </div>
        </section>

        <section className="panel ai-connector-runs">
          <div className="panel-header"><div><h3>Recent runs</h3><span className="panel-caption">Scope failures retain prior inventory and findings.</span></div></div>
          {(runsQuery.data ?? []).length === 0 ? (
            <div className="empty-state"><p>No Azure AI Security discovery runs yet.</p></div>
          ) : (
            <div className="ai-run-list">
              {(runsQuery.data ?? []).slice(0, 10).map((run) => (
                <article key={run.id}>
                  <div><strong>{run.status.replace(/_/g, ' ')}</strong><span>{new Date(run.startedAt).toLocaleString()}</span></div>
                  <div><span>{run.recordsFetched} observations</span><span>{run.recordsFailed} incomplete scopes</span></div>
                  {run.errorMessage && <p>{run.errorMessage}</p>}
                </article>
              ))}
            </div>
          )}
          {(scopesQuery.data ?? []).length > 0 && (
            <>
              <div className="panel-header ai-scope-header">
                <div><h3>Latest scope completeness</h3><span className="panel-caption">Only COMPLETE scopes can deactivate inventory or resolve findings.</span></div>
              </div>
              <div className="ai-scope-list">
                {(scopesQuery.data ?? []).map((scope) => {
                  const diagnostic = scope.diagnostics.items?.[0];
                  return (
                    <article key={scope.id}>
                      <div>
                        <strong>{scope.resourceFamily.replace(/_/g, ' ')}</strong>
                        <span className={`status-pill ${scope.status.toLowerCase()}`}>{scope.status}</span>
                      </div>
                      <p>{scope.accountId} · {scope.region}</p>
                      {diagnostic && (
                        <div className="ai-scope-diagnostic">
                          <strong>{diagnostic.code}</strong>
                          <span>{diagnostic.message}</span>
                          {diagnostic.missingPermissions.length > 0 && (
                            <small>Missing: {diagnostic.missingPermissions.join(', ')}</small>
                          )}
                          <small>
                            {diagnostic.retryable ? 'Retryable' : 'User action required'}
                            {' · '}Correlation {diagnostic.correlationId}
                          </small>
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
