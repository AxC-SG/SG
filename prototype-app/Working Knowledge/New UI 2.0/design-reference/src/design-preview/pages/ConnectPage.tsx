import { useCapabilities, usePreview } from '../previewContext';
import { useMockAction } from '../components/useMockAction';
import React from 'react';
import { ArrowLeft, Play, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { CONNECTOR_SECTIONS, RUN_HISTORY, type ConnectorHealth } from '../data';
import { Badge, Card, PageHeader } from '../components/primitives';
import { Alert, ProgressBar, Spinner, useToast } from '../components/feedback';
import { Accordion, Tabs } from '../components/disclosure';
import { Field, PasswordInput, RadioCards, Select, Switch, TextInput } from '../components/forms';

// Reference for ConnectPage (/connect/sources, /connect/run-history) and the per-connector
// config pages (AwsDiscoveryConnectorPage etc.). Sections, card ids and the status-dot
// title/aria-label health convention follow root CLAUDE.md "Connect Page Architecture".

function VendorMark({ mark }: { mark: string }) {
  switch (mark) {
    case 'microsoft': return (
      <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="2" width="9.5" height="9.5" fill="#f25022" /><rect x="12.5" y="2" width="9.5" height="9.5" fill="#7fba00" /><rect x="2" y="12.5" width="9.5" height="9.5" fill="#00a4ef" /><rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#ffb900" /></svg>
    );
    case 'aws': return <svg viewBox="0 0 40 24" aria-hidden="true"><text x="20" y="15" textAnchor="middle" fontSize="13" fontWeight="700" fontFamily="Arial, sans-serif" fill="currentColor">aws</text><path d="M8 18c7 4 17 4 24 0" stroke="#ff9900" strokeWidth="2" fill="none" strokeLinecap="round" /></svg>;
    case 'azure': return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 3h5L7 21H2z" fill="#0078d4" /><path d="M13 9l9 12h-12l5-3z" fill="#50a0e6" /></svg>;
    case 'servicenow': return <svg viewBox="0 0 32 24" aria-hidden="true"><rect x="1" y="3" width="30" height="18" rx="5" fill="#032d42" /><text x="16" y="16" textAnchor="middle" fontSize="9" fontWeight="700" fontFamily="Arial, sans-serif" fill="#62d84e">NOW</text></svg>;
    case 'bigfix': return <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2" y="2" width="20" height="20" rx="5" fill="#4a5f7a" /><text x="12" y="17" textAnchor="middle" fontSize="13" fontWeight="700" fontFamily="Arial, sans-serif" fill="#fff">b</text></svg>;
    case 'tanium': return <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10" fill="#e0262c" /><text x="12" y="16.5" textAnchor="middle" fontSize="12" fontWeight="700" fontFamily="Arial, sans-serif" fill="#fff">T</text></svg>;
    default: return <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="3" fill="none" stroke="currentColor" strokeWidth="1.6" /><path d="M7 9h10M7 13h6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" /></svg>;
  }
}

const HEALTH_LABEL: Record<ConnectorHealth, string> = { healthy: 'Healthy', failing: 'Failing', idle: 'Not configured', disabled: 'Disabled' };

function StatusDot({ health, detail }: { health: ConnectorHealth; detail: string }) {
  return <span className={`dp-status-dot dp-status-dot--${health}`} title={`${HEALTH_LABEL[health]} · ${detail}`} aria-label={`${HEALTH_LABEL[health]} · ${detail}`} role="img" />;
}

function RunStatus({ status }: { status: string }) {
  if (status === 'RUNNING') return <Badge tone="accent"><Spinner size={11} /> Running</Badge>;
  if (status === 'SUCCEEDED') return <Badge tone="success" dot>Succeeded</Badge>;
  if (status === 'FAILED') return <Badge tone="critical" dot>Failed</Badge>;
  return <Badge dot>Queued</Badge>;
}

function RunHistory() {
  return (
    <div className="dp-table-card">
      <div className="dp-toolbar">
        <strong>Inventory Integration Run History</strong>
        <span className="dp-muted">Live queue · refreshes every 5s</span>
        <div className="dp-toolbar-right"><button type="button" className="dp-btn dp-btn--sm"><RefreshCw size={13} /> Refresh</button></div>
      </div>
      <div className="dp-table-scroll">
        <table className="dp-table">
          <thead><tr><th>Run</th><th>Source</th><th>Trigger</th><th>Status</th><th style={{ width: 180 }}>Progress</th><th>Records</th><th>Started</th><th>Duration</th></tr></thead>
          <tbody>
            {RUN_HISTORY.map((run) => (
              <tr key={run.id} className="static">
                <td className="dp-mono dp-muted">{run.id}</td>
                <td>{run.source}</td>
                <td className="dp-muted">{run.trigger}</td>
                <td><RunStatus status={run.status} /></td>
                <td><div className="dp-progress-cell"><ProgressBar value={run.progress} tone={run.status === 'FAILED' ? 'critical' : run.status === 'SUCCEEDED' ? 'success' : 'accent'} label={`${run.source} progress`} /><span className="dp-num dp-muted">{run.progress}%</span></div></td>
                <td className="dp-num">{run.records}</td>
                <td className="dp-num dp-muted">{run.started}</td>
                <td className="dp-num dp-muted">{run.duration}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ConnectorDetail({ id, onBack }: { id: string; onBack: () => void }) {
  const toast = useToast();
  const { canInventory } = useCapabilities();
  const { scenario } = usePreview();
  const saving = useMockAction();
  const match = CONNECTOR_SECTIONS.flatMap((s) => s.items).find((c) => c.id === id);
  const connector = match ?? { id, name: 'Connector unavailable', vendor: 'Unavailable', mark: 'generic', health: 'disabled' as const, status: 'This connector is not in the supported catalog.', mockOnly: false };
  const [auth, setAuth] = React.useState<'ROLE' | 'KEYS'>('ROLE');
  const [scheduled, setScheduled] = React.useState(true);
  const [testing, setTesting] = React.useState<'idle' | 'running' | 'ok'>('idle');
  const [targets, setTargets] = React.useState([{ account: '412938471023', region: 'us-east-1' }, { account: '998102334871', region: 'eu-west-1' }]);

  const test = () => { setTesting('running'); window.setTimeout(() => setTesting('ok'), 900); };

  if (connector.health === 'disabled') return <div className="dp-page"><button type="button" className="dp-link" onClick={onBack}>All connectors</button><PageHeader title={connector.name} description={connector.status} /><Alert tone="warning" title="Connector unavailable">This connector is read-only in the current product scope. Existing inventory is retained. Configuration, testing, and sync actions are unavailable.</Alert></div>;
  return (
    <div className="dp-page">
      <button type="button" className="dp-btn dp-btn--ghost dp-btn--sm dp-self-start" onClick={onBack}><ArrowLeft size={14} /> All connectors</button>
      <div className="dp-connector-hero">
        <span className="dp-vendor-mark dp-vendor-mark--lg"><VendorMark mark={connector.mark} /></span>
        <div>
          <h1>{connector.name}</h1>
          <p className="dp-muted">{connector.vendor} · {connector.status}</p>
        </div>
        <StatusDot health={connector.health} detail={connector.status} />
        <div className="dp-page-actions dp-ml-auto">
          <button type="button" className="dp-btn" disabled={!canInventory} onClick={() => toast('info', 'Sample sync queued; no provider contacted.')}><Play size={14} /> Run sync now</button>
        </div>
      </div>
      {connector.mockOnly ? <Alert tone="warning" title="UI-only connector">Test Connection and Save Configuration are not wired to a backend yet (see Known Limitations).</Alert> : null}
      {connector.health === 'failing' ? <Alert tone="danger" title="Last sync failed" action={<button type="button" className="dp-link">View run</button>}>The source rejected the configured credentials. Review the last run before retrying.</Alert> : null}

      {!canInventory ? <Alert title="Read-only connector access">This role cannot change source settings or run syncs.</Alert> : null}
      {saving.error ? <Alert tone="danger">{saving.error}</Alert> : saving.message ? <Alert tone="success">{saving.message}</Alert> : null}
      <fieldset disabled={!canInventory || saving.pending} className="dp-form-boundary"><div className="dp-settings-grid">
        <div className="dp-settings-main">
          <Card title="Connection" subtitle="Where ScoutGrid connects and how it identifies this source.">
            <div className="dp-form dp-form--2col">
              <Field label="Display name" htmlFor="c-name" required><TextInput id="c-name" defaultValue={connector.name} /></Field>
              <Field label="Default region" htmlFor="c-region"><Select id="c-region" defaultValue="us-east-1"><option>us-east-1</option><option>us-west-2</option><option>eu-west-1</option></Select></Field>
            </div>
          </Card>
          <Card title="Authentication">
            <div className="dp-form">
              <RadioCards
                name="auth"
                value={auth}
                onChange={setAuth}
                options={[
                  { value: 'ROLE', label: 'Cross-account role', description: 'Assume an IAM role with an external ID. Recommended.' },
                  { value: 'KEYS', label: 'Access keys', description: 'Long-lived IAM user keys. Rotate every 90 days.' },
                ]}
              />
              {auth === 'ROLE' ? (
                <div className="dp-form dp-form--2col">
                  <Field label="Role ARN" htmlFor="c-arn" required><TextInput id="c-arn" className="dp-mono" defaultValue="arn:aws:iam::412938471023:role/ScoutGridDiscovery" /></Field>
                  <Field label="External ID" htmlFor="c-ext" hint="Shown once. Stored encrypted."><PasswordInput id="c-ext" defaultValue="sg-ext-7f3a9c" /></Field>
                </div>
              ) : (
                <div className="dp-form dp-form--2col">
                  <Field label="Access key ID" htmlFor="c-key" required><TextInput id="c-key" className="dp-mono" placeholder="AKIA…" /></Field>
                  <Field label="Secret access key" htmlFor="c-secret" required error="Secret is required when using access keys."><PasswordInput id="c-secret" /></Field>
                </div>
              )}
              <div className="dp-row-gap">
                <button type="button" className="dp-btn" onClick={test} disabled={testing === 'running'}>{testing === 'running' ? <Spinner label="Testing…" /> : 'Test Connection'}</button>
                {testing === 'ok' ? <Alert tone={scenario === 'partial-error' ? 'danger' : 'success'} role={scenario === 'partial-error' ? 'alert' : 'status'}>{scenario === 'partial-error' ? 'Connection test failed. Your configuration is retained; retry after checking permissions.' : 'Connection verified · 2 accounts reachable · SSM inventory enabled.'}</Alert> : null}
              </div>
            </div>
          </Card>
          <Card title="Discovery targets" subtitle="aws_discovery_targets — one row per account/region." actions={<button type="button" className="dp-btn dp-btn--sm" onClick={() => setTargets([...targets, { account: '', region: 'us-east-1' }])}><Plus size={13} /> Add target</button>}>
            <div className="dp-rule-rows">
              {targets.map((t, i) => (
                <div key={i} className="dp-rule-row">
                  <TextInput aria-label={`Account ID ${i + 1}`} className="dp-mono" value={t.account} placeholder="Account ID" onChange={(e) => setTargets(targets.map((x, j) => (j === i ? { ...x, account: e.target.value } : x)))} />
                  <Select aria-label={`Region ${i + 1}`} value={t.region} onChange={(e) => setTargets(targets.map((x, j) => (j === i ? { ...x, region: e.target.value } : x)))}><option>us-east-1</option><option>us-west-2</option><option>eu-west-1</option></Select>
                  <button type="button" className="dp-icon-btn sm" aria-label={`Remove target ${i + 1}`} onClick={() => setTargets(targets.filter((_, j) => j !== i))}><Trash2 size={13} /></button>
                </div>
              ))}
            </div>
          </Card>
          <Card title="Sync schedule">
            <div className="dp-form">
              <Switch checked={scheduled} onChange={setScheduled} label="Scheduled sync" description="Runs on the 5-minute scheduler when due." />
              <Field label="Interval" htmlFor="c-int"><Select id="c-int" disabled={!scheduled} defaultValue="6h"><option value="1h">Every hour</option><option value="6h">Every 6 hours</option><option value="24h">Daily</option></Select></Field>
            </div>
          </Card>
          <div className="dp-form-actions">
            <button type="button" className="dp-btn" onClick={onBack}>Cancel</button>
            <button type="button" className="dp-btn dp-btn--primary" onClick={() => saving.run('Configuration saved in the mock. No source credentials were transmitted.')} disabled={saving.pending}>{saving.pending ? 'Saving…' : 'Save Configuration'}</button>
          </div>
        </div>
        <aside className="dp-settings-aside">
          <Card title="Recent runs">
            <div className="dp-list">
              {RUN_HISTORY.slice(0, 4).map((run) => (
                <div key={run.id} className="dp-list-row static">
                  <span className="dp-list-main"><span>{run.source}</span><span className="dp-muted dp-num">{run.started} · {run.duration}</span></span>
                  <RunStatus status={run.status} />
                </div>
              ))}
            </div>
          </Card>
        </aside>
      </div></fieldset>
    </div>
  );
}

export function ConnectPage({ route, onNavigate }: { route: string; onNavigate: (route: string) => void }) {
  const segment = route.split('/')[2] ?? 'sources';
  if (segment !== 'sources' && segment !== 'run-history') {
    return <ConnectorDetail id={segment} onBack={() => onNavigate('/connect')} />;
  }
  return (
    <div className="dp-page">
      <PageHeader title="Connectors" description="Connect supported inventory, BOM and static AI sources. Status dots expose last sync on hover." />
      <Tabs
        label="Connect views"
        value={segment}
        onChange={(v) => onNavigate(v === 'sources' ? '/connect' : '/connect/run-history')}
        tabs={[{ value: 'sources', label: 'Sources' }, { value: 'run-history', label: 'Run History' }]}
      />
      {segment === 'run-history' ? <RunHistory /> : (
        <>
          {CONNECTOR_SECTIONS.map((section) => (
            <section key={section.title} className="dp-section">
              <div className="dp-section-head">
                <h2>{section.title}</h2>
                <p>{section.description}</p>
              </div>
              <div className="dp-connector-grid">
                {section.items.map((c) => (
                  <button key={c.id} type="button" className="dp-connector-card" onClick={() => onNavigate(`/connect/${c.id}`)}>
                    <span className="dp-connector-top">
                      <span className="dp-vendor-mark"><VendorMark mark={c.mark} /></span>
                      <StatusDot health={c.health} detail={c.status} />
                    </span>
                    <strong>{c.name}</strong>
                    <span className="dp-muted">{c.vendor}</span>
                    {c.entitlement ? <Badge tone="accent">AI Security</Badge> : null}
                  </button>
                ))}
              </div>
            </section>
          ))}
          <Accordion title="Vulnerability Intelligence" meta="Per-tenant feed filter rules">
            <p className="dp-muted">VulnerabilitySourcesSection renders here unchanged, gated by canManageSourceFilters(actor).</p>
          </Accordion>
        </>
      )}
    </div>
  );
}
