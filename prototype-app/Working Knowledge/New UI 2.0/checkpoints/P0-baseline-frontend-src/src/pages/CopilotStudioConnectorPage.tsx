import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';

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
  return <main className="page ai-security-page"><header><h1>Copilot Studio</h1><p>Dataverse definition and configuration discovery.</p></header>
    <section className="panel"><label>Organization URL<input value={organizationUrl} onChange={e => setOrganizationUrl(e.target.value)} placeholder="https://org.crm.dynamics.com" /></label>
      <label>Azure credential profile ID<input value={credentialProfileId} onChange={e => setCredentialProfileId(e.target.value)} /></label>
      <label><input type="checkbox" checked={discoveryEnabled} onChange={e => setDiscoveryEnabled(e.target.checked)} /> Enable discovery</label>
      <label><input type="checkbox" checked={killSwitch} onChange={e => setKillSwitch(e.target.checked)} /> Kill switch</label>
      <label>Schedule (six-field cron)<input value={scheduleCron} onChange={e => setScheduleCron(e.target.value)} /></label>
      <label>Allowed Dataverse hosts<input value={allowedHosts} onChange={e => setAllowedHosts(e.target.value)} placeholder="org.crm.dynamics.com" /></label>
      <button type="button" onClick={() => save.mutate({ organizationUrl, credentialProfileId, discoveryEnabled, executionEnabled: false, killSwitch, scheduleCron, allowedDataverseHosts: allowedHosts.split(',').map(value => value.trim()).filter(Boolean) })} disabled={save.isPending}>Save connector</button>
      {save.isError && <p role="alert">{save.error instanceof Error ? save.error.message : 'Unable to save connector'}</p>}
    </section>
    <section className="panel"><h2>Tenant rollout controls</h2>{featureFlags.data?.filter(flag => flag.featureKey === 'COPILOT_DISCOVERY').map(flag => <div key={flag.featureKey}>
      <strong>{flag.featureKey === 'COPILOT_DISCOVERY' ? 'Discovery' : 'Runtime'}</strong>{' '}
      <label><input type="checkbox" checked={flag.enabled} onChange={event => updateFlag.mutate({ featureKey: flag.featureKey, enabled: event.target.checked, killSwitch: flag.killSwitch })} /> Tenant enabled</label>{' '}
      <label><input type="checkbox" checked={flag.killSwitch} onChange={event => updateFlag.mutate({ featureKey: flag.featureKey, enabled: flag.enabled, killSwitch: event.target.checked })} /> Emergency stop</label>
    </div>)}</section>
    <section className="panel"><h2>Configured organizations</h2>{configs.data?.map(item => <div key={item.id}><strong>{item.organizationUrl}</strong> — discovery {item.discoveryEnabled ? 'enabled' : 'disabled'}, schedule <code>{item.scheduleCron}</code> <button type="button" onClick={() => { setOrganizationUrl(item.organizationUrl); setCredentialProfileId(item.credentialProfileId); setDiscoveryEnabled(item.discoveryEnabled); setKillSwitch(item.killSwitch); setScheduleCron(item.scheduleCron); setAllowedHosts(item.allowedDataverseHosts.join(', ')); }}>Edit</button> <button type="button" onClick={() => test.mutate(item.id)}>Test permissions</button><button type="button" onClick={() => discover.mutate(item.id)}>Run discovery</button></div>) ?? <p>Loading…</p>}{test.data && <p>Discovery — bots: {test.data.bots.state}; components: {test.data.components.state}.</p>}{discover.data && <p role="status">Discovery {discover.data.existingJob ? 'already queued' : 'queued'} (job {discover.data.jobId}). Track progress in the ingestion run queue.</p>}{discover.isError && <p role="alert">{discover.error instanceof Error ? discover.error.message : 'Copilot discovery could not be queued'}</p>}</section>
  </main>;
}
