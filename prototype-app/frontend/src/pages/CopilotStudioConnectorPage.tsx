import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import { AsyncSection, type AsyncSectionState } from '../components/AsyncSection';

export function CopilotStudioConnectorPage() {
  const client = useQueryClient(); const configs = useQuery({ queryKey: ['copilot-studio-connectors'], queryFn: api.listCopilotStudioConnectors });
  const featureFlags = useQuery({ queryKey: ['ai-security-feature-flags'], queryFn: api.listAiSecurityConnectorFeatureFlags });
  const [organizationUrl, setOrganizationUrl] = React.useState(''); const [credentialProfileId, setCredentialProfileId] = React.useState('');
  const [discoveryEnabled, setDiscoveryEnabled] = React.useState(false); const [killSwitch, setKillSwitch] = React.useState(false);
  const [scheduleCron, setScheduleCron] = React.useState('0 0 * * * *'); const [allowedHosts, setAllowedHosts] = React.useState('');
  const save = useMutation({ mutationFn: api.saveCopilotStudioConnector, onSuccess: () => void client.invalidateQueries({ queryKey: ['copilot-studio-connectors'] }) });
  const test = useMutation({ mutationFn: api.testCopilotStudioConnector });
  const discover = useMutation({
    mutationFn: api.runCopilotStudioDiscovery,
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ['ingestion-jobs'] });
      void client.invalidateQueries({ queryKey: ['sync-runs'] });
      void client.invalidateQueries({ queryKey: ['ai-security-runs', 'MICROSOFT_COPILOT'] });
    },
  });
  const updateFlag = useMutation({ mutationFn: ({ featureKey, enabled, killSwitch: flagKillSwitch }: { featureKey: string; enabled: boolean; killSwitch: boolean }) => api.updateAiSecurityConnectorFeatureFlag(featureKey, { enabled, killSwitch: flagKillSwitch }), onSuccess: () => void client.invalidateQueries({ queryKey: ['ai-security-feature-flags'] }) });
  const [saveNotice, setSaveNotice] = React.useState('');
  const errorText = (error: unknown, fallback: string) => (error instanceof Error ? error.message : fallback);
  const configsState: AsyncSectionState = configs.isPending
    ? 'pending'
    : configs.isError && !configs.data ? 'error' : (configs.data ?? []).length === 0 ? 'empty' : 'ready';
  const discoveryFlags = featureFlags.data?.filter(flag => flag.featureKey === 'COPILOT_DISCOVERY') ?? [];
  const flagsState: AsyncSectionState = featureFlags.isPending
    ? 'pending'
    : featureFlags.isError && !featureFlags.data ? 'error' : discoveryFlags.length === 0 ? 'empty' : 'ready';
  const submit = () => {
    setSaveNotice('');
    save.mutate(
      { organizationUrl, credentialProfileId, discoveryEnabled, executionEnabled: false, killSwitch, scheduleCron, allowedDataverseHosts: allowedHosts.split(',').map(value => value.trim()).filter(Boolean) },
      { onSuccess: () => setSaveNotice('Connector saved.') }
    );
  };
  return <section className="page ai-security-page ui2-connect-family"><header><h2>Copilot Studio</h2><p>Dataverse definition and configuration discovery.</p></header>
    <section className="panel">
      <div className="panel-header"><div><h3>Connection</h3><span className="panel-caption">Discovery reads bot and component definitions only; runtime metadata is not collected.</span></div></div>
      <div className="form-grid">
        <label>Organization URL<input value={organizationUrl} onChange={e => setOrganizationUrl(e.target.value)} placeholder="https://org.crm.dynamics.com" /></label>
        <label>Azure credential profile ID<input value={credentialProfileId} onChange={e => setCredentialProfileId(e.target.value)} aria-describedby="copilot-profile-help" /></label>
        <span id="copilot-profile-help" className="field-hint">The saved Azure credential profile that signs in to Dataverse. Its secret is stored with that profile, not here.</span>
        <label>Schedule (six-field cron)<input value={scheduleCron} onChange={e => setScheduleCron(e.target.value)} aria-describedby="copilot-cron-help" /></label>
        <span id="copilot-cron-help" className="field-hint">Seconds, minutes, hours, day of month, month, day of week. The default runs hourly.</span>
        <label>Allowed Dataverse hosts<input value={allowedHosts} onChange={e => setAllowedHosts(e.target.value)} placeholder="org.crm.dynamics.com" aria-describedby="copilot-hosts-help" /></label>
        <span id="copilot-hosts-help" className="field-hint">Comma-separated. Discovery connects only to these hosts.</span>
      </div>
      <div className="sn-toggle-group">
        <label className="sn-toggle-row"><input type="checkbox" checked={discoveryEnabled} onChange={e => setDiscoveryEnabled(e.target.checked)} /> Enable discovery</label>
        <label className="sn-toggle-row"><input type="checkbox" checked={killSwitch} onChange={e => setKillSwitch(e.target.checked)} /> Kill switch (stop discovery for this organization)</label>
      </div>
      <div className="button-row section-actions">
        <button type="button" className="btn btn-primary" onClick={submit} disabled={save.isPending}>{save.isPending ? 'Saving…' : 'Save connector'}</button>
      </div>
      {save.isError && <p className="notice error" role="alert">{errorText(save.error, 'Unable to save connector')}</p>}
      {saveNotice && !save.isError && <p className="notice success" role="status">{saveNotice}</p>}
    </section>
    <section className="panel"><h2>Tenant rollout controls</h2>
      <AsyncSection
        state={flagsState}
        loadingLabel="Loading rollout controls…"
        emptyMessage="No Copilot discovery rollout control is available for this tenant."
        errorMessage={`Rollout controls could not be loaded: ${errorText(featureFlags.error, 'Unknown error')}.`}
        onRetry={() => void featureFlags.refetch()}
        retrying={featureFlags.isFetching}
      >
        {discoveryFlags.map(flag => <div key={flag.featureKey}>
          <strong>Discovery</strong>{' '}
          <label><input type="checkbox" checked={flag.enabled} disabled={updateFlag.isPending} onChange={event => updateFlag.mutate({ featureKey: flag.featureKey, enabled: event.target.checked, killSwitch: flag.killSwitch })} /> Tenant enabled</label>{' '}
          <label><input type="checkbox" checked={flag.killSwitch} disabled={updateFlag.isPending} onChange={event => updateFlag.mutate({ featureKey: flag.featureKey, enabled: flag.enabled, killSwitch: event.target.checked })} /> Emergency stop</label>
        </div>)}
        {updateFlag.isError && <p className="notice error" role="alert">{errorText(updateFlag.error, 'The rollout control could not be updated')}</p>}
      </AsyncSection>
    </section>
    <section className="panel"><h2>Configured organizations</h2>
      <AsyncSection
        state={configsState}
        loadingLabel="Loading configured organizations…"
        emptyMessage="No Copilot Studio organization is configured yet. Save a connection above to add one."
        errorMessage={`Configured organizations could not be loaded: ${errorText(configs.error, 'Unknown error')}.`}
        onRetry={() => void configs.refetch()}
        retrying={configs.isFetching}
      >
        {configs.data?.map(item => <div key={item.id}><strong>{item.organizationUrl}</strong> — discovery {item.discoveryEnabled ? 'enabled' : 'disabled'}{item.killSwitch ? ' (stopped by kill switch)' : ''}, schedule <code>{item.scheduleCron}</code>{' '}
          <span className="button-row">
            <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setOrganizationUrl(item.organizationUrl); setCredentialProfileId(item.credentialProfileId); setDiscoveryEnabled(item.discoveryEnabled); setKillSwitch(item.killSwitch); setScheduleCron(item.scheduleCron); setAllowedHosts(item.allowedDataverseHosts.join(', ')); }}>Edit</button>
            <button type="button" className="btn btn-secondary btn-sm" disabled={test.isPending} onClick={() => test.mutate(item.id)}>Test permissions</button>
            <button type="button" className="btn btn-primary btn-sm" disabled={discover.isPending} onClick={() => discover.mutate(item.id)}>Run discovery</button>
          </span>
        </div>)}
      </AsyncSection>
      {test.data && <p>Discovery — bots: {test.data.bots.state}; components: {test.data.components.state}.</p>}
      {test.isError && <p className="notice error" role="alert">{errorText(test.error, 'The permission test could not be run')}</p>}
      {discover.data && <p role="status">Discovery {discover.data.existingJob ? 'already queued' : 'queued'} (job {discover.data.jobId}). Track progress in the ingestion run queue.</p>}
      {discover.isError && <p role="alert">{errorText(discover.error, 'Copilot discovery could not be queued')}</p>}
    </section>
  </section>;
}
