import React from 'react';
import { ArrowLeft, ArrowRight, CheckCircle2, FlaskConical, Send, ShieldCheck } from 'lucide-react';
import { Badge, Card, PageHeader } from '../components/primitives';
import { Alert, Spinner } from '../components/feedback';
import { CodeBlock, PropertyList, Timeline } from '../components/disclosure';
import { Field, Select, Textarea } from '../components/forms';
import { Modal } from '../components/overlays';
import { useMockAction } from '../components/useMockAction';
import { useCapabilities, usePreview } from '../previewContext';

const POLICIES = [
  { id: 'tool-access', name: 'Unrestricted tool permissions', severity: 'Critical', mapping: 'OWASP Agentic · ASI03', provider: 'AWS Bedrock', version: '1.3.0', description: 'Identify tool definitions that grant broad capabilities without a constrained action scope.' },
  { id: 'sensitive-access', name: 'Sensitive data access scope', severity: 'High', mapping: 'OWASP Agentic · ASI02', provider: 'AWS Bedrock', version: '1.1.0', description: 'Review static data-source references and configured access boundaries.' },
  { id: 'identity', name: 'Agent identity configured', severity: 'Medium', mapping: 'Identity & access', provider: 'Azure AI Foundry', version: '2.0.1', description: 'Check that a configured agent has an explicit identity reference.' },
];
const TENANT_OPTIONS = [{ id: 'acme', name: 'Acme Corporation', active: true }, { id: 'initech-demo', name: 'Initech Demo', active: true }, { id: 'globex', name: 'Globex Industries — suspended', active: false }];
type Phase = 'DRAFT' | 'DEV_VALIDATED' | 'APPROVED' | 'PUBLISHED';

export function PolicyDistributionPage({ route, onNavigate }: { route: string; onNavigate: (route: string) => void }) {
  const policyId = route.split('/')[3];
  if (!policyId) return <PolicyCatalog onNavigate={onNavigate} />;
  return <PolicyDetail key={policyId} policyId={policyId} onNavigate={onNavigate} />;
}

function PolicyCatalog({ onNavigate }: { onNavigate: (route: string) => void }) {
  const [search, setSearch] = React.useState('');
  return <div className="dp-page"><PageHeader eyebrow="Platform / AI Policies" title="Policy Distribution" description="A governed catalog with explicit lifecycle, tenant defaults, and rollout scope." actions={<Badge tone="accent">Platform-owned</Badge>} /><div className="dp-summary-strip dp-card"><div><span>Catalog packages</span><strong>3</strong></div><div><span>Installed</span><strong>3</strong></div><div><span>Ready for review</span><strong>3</strong></div><div><span>Scope</span><strong className="dp-summary-word">Static assessment</strong></div></div><Card title="Policy catalog" subtitle="Open a policy to inspect its evidence and follow the dev/test → approval → publish flow."><div className="dp-form" style={{ marginBottom: 16 }}><Field label="Find policy"><input className="dp-input" value={search} onChange={e => setSearch(e.target.value)} placeholder="Name, provider, or framework mapping" /></Field></div><div className="dp-table-scroll"><table className="dp-table"><thead><tr><th>Policy / version</th><th>Provider</th><th>Framework mapping</th><th>Severity</th><th>Lifecycle</th><th>Actions</th></tr></thead><tbody>{POLICIES.filter(p => `${p.name} ${p.provider} ${p.mapping}`.toLowerCase().includes(search.toLowerCase())).map(p => <tr className="static" key={p.id}><td><button type="button" className="dp-link" onClick={() => onNavigate(`/platform/ai-policies/${p.id}`)}>{p.name}</button><span className="dp-table-sub dp-mono">{p.id} · v{p.version}</span></td><td>{p.provider}</td><td className="dp-muted">{p.mapping}</td><td><Badge tone={p.severity === 'Critical' ? 'critical' : p.severity === 'High' ? 'high' : 'medium'}>{p.severity}</Badge></td><td><Badge>Draft</Badge></td><td><button type="button" className="dp-btn dp-btn--sm" onClick={() => onNavigate(`/platform/ai-policies/${p.id}`)}>Manage <ArrowRight size={12} /></button></td></tr>)}</tbody></table></div></Card><Alert title="Sample policy catalog">All deployments, approvals, and rollout outcomes in this reference are browser-only simulations.</Alert></div>;
}

function PolicyDetail({ policyId, onNavigate }: { policyId: string; onNavigate: (route: string) => void }) {
  const policy = POLICIES.find(p => p.id === policyId) ?? POLICIES[0];
  const [phase, setPhase] = React.useState<Phase>('DRAFT');
  const [cohort, setCohort] = React.useState<string[]>(['acme']);
  const [scope, setScope] = React.useState<'SELECTED' | 'ALL'>('SELECTED');
  const [note, setNote] = React.useState('');
  const [confirm, setConfirm] = React.useState(false);
  const [jobs, setJobs] = React.useState<Array<{ tenant: string; status: 'SUCCEEDED' | 'FAILED' }>>([]);
  const [history, setHistory] = React.useState<Array<{ title: string; meta: string; body?: string }>>([{ title: 'Catalog version installed', meta: `v${policy.version}`, body: 'Awaiting dev/test validation.' }]);
  const action = useMockAction();
  const { canPublish } = useCapabilities();
  const { scenario } = usePreview();
  const activeIds = TENANT_OPTIONS.filter(t => t.active).map(t => t.id);
  const targetIds = scope === 'ALL' ? activeIds : cohort.filter(id => activeIds.includes(id));
  const event = (title: string, body: string) => setHistory(current => [...current, { title, body, meta: 'Just now · sample' }]);
  const publish = () => {
    setConfirm(false);
    action.run('Policy published to the sample tenant cohort.', () => {
      setPhase('PUBLISHED');
      setJobs(targetIds.map((tenant, i) => ({ tenant, status: scenario === 'partial-error' && i === 0 ? 'FAILED' : 'SUCCEEDED' })));
      event('Publication requested', `${targetIds.length} active tenant workspace(s).`);
    });
  };
  const canApprove = canPublish && phase === 'DEV_VALIDATED' && note.trim().length > 0;
  return <div className="dp-page"><button type="button" className="dp-link dp-back-link" onClick={() => onNavigate('/platform/ai-policies')}><ArrowLeft size={13} /> Back to policy catalog</button><PageHeader eyebrow={`Policy Distribution / ${policy.id}`} title={policy.name} description={`Version ${policy.version} · ${policy.provider} · ${policy.mapping}`} actions={<Badge tone={phase === 'PUBLISHED' ? 'success' : 'accent'}>{phase.replace('_', ' ')}</Badge>} />
    {!canPublish ? <Alert tone="warning" title="Platform Owner required">Policy distribution actions are read-only in Tenant scope. Switch workspace scope in Reference controls.</Alert> : null}
    {action.error ? <Alert tone="danger" title="Policy change could not be saved">{action.error}</Alert> : action.message ? <Alert tone="success">{action.message}</Alert> : null}
    <div className="dp-grid-3-2"><div className="dp-stack"><Card title="Policy intent"><p className="dp-body-copy">{policy.description}</p><PropertyList items={[[ 'Assessment scope', 'Static configuration facts'], ['Governance owner', 'Platform Security'], ['Tenant configuration', 'Platform controlled'], ['Default selection', 'Opt in'], ['Framework mapping', policy.mapping]]} /><details className="dp-accordion"><summary>Inspect package metadata</summary><CodeBlock language="json" code={JSON.stringify({ policyId: policy.id, version: policy.version, provider: policy.provider, assessmentScope: 'STATIC', mapping: policy.mapping }, null, 2)} /></details></Card>
      <Card title="Dev/test & publication scope" subtitle="Use the native multi-select to choose a cohort. Suspended tenants are excluded."><div className="dp-form"><Field label="Dev/test tenants" hint="Use Cmd/Ctrl to select more than one tenant. Keep the native selection behavior."><Select multiple size={3} aria-label="Dev/test tenants" value={cohort} disabled={!canPublish || action.pending || phase === 'PUBLISHED'} onChange={e => setCohort(Array.from(e.target.selectedOptions, option => option.value))}>{TENANT_OPTIONS.map(t => <option key={t.id} value={t.id} disabled={!t.active}>{t.name}</option>)}</Select></Field><div className="dp-row-between dp-wrap"><span className="dp-muted">{cohort.length} tenant(s) selected for dev/test</span><button type="button" className="dp-btn" disabled={!canPublish || !cohort.length || action.pending || phase !== 'DRAFT'} onClick={() => action.run('Dev/test validation completed in the mock.', () => { setPhase('DEV_VALIDATED'); event('Dev/test validation completed', `${cohort.length} tenant(s) · sample evidence recorded.`); })}><FlaskConical size={14} />{action.pending && phase === 'DRAFT' ? 'Validating…' : 'Deploy to dev/test'}</button></div>
      <Field label="Approval evidence note" hint="Required before approval. Retained if saving fails."><Textarea value={note} rows={3} disabled={!canPublish || phase === 'PUBLISHED'} onChange={e => setNote(e.target.value)} placeholder="Describe validation results and link the supporting evidence…" /></Field><button type="button" className="dp-btn" disabled={!canApprove || action.pending} onClick={() => action.run('Policy approval recorded in the mock.', () => { setPhase('APPROVED'); event('Policy approved', note); })}><CheckCircle2 size={14} /> Approve with evidence</button>
      <fieldset className="dp-publication-scope" disabled={!canPublish || action.pending || phase === 'PUBLISHED'}><legend>Publication scope</legend><label className="dp-choice"><input type="radio" name="publish-scope" checked={scope === 'SELECTED'} onChange={() => setScope('SELECTED')} /><span>Selected active tenants</span></label><label className="dp-choice"><input type="radio" name="publish-scope" checked={scope === 'ALL'} onChange={() => setScope('ALL')} /><span>All active tenants</span></label></fieldset><Alert title="Publication summary">{targetIds.length} active tenant(s) · {scope === 'ALL' ? 'All active tenants' : 'Selected cohort'} · Suspended tenants are excluded.</Alert><button type="button" className="dp-btn dp-btn--primary" disabled={!canPublish || phase !== 'APPROVED' || action.pending || !targetIds.length} onClick={() => setConfirm(true)}>{action.pending && phase === 'APPROVED' ? <Spinner label="Publishing…" /> : <><Send size={14} />Publish policy</>}</button></div></Card>
    </div><aside className="dp-stack"><Card title="Shipping readiness"><div className="dp-gate-list">{[{ label: 'Package installed', ready: true }, { label: 'Dev/test validated', ready: phase !== 'DRAFT' }, { label: 'Approval recorded', ready: ['APPROVED', 'PUBLISHED'].includes(phase) }, { label: 'Publication requested', ready: phase === 'PUBLISHED' }].map(gate => <div className="dp-row-between" key={gate.label}><span>{gate.label}</span><Badge tone={gate.ready ? 'success' : 'neutral'}>{gate.ready ? 'Ready' : 'Pending'}</Badge></div>)}</div></Card><Card title="Lifecycle history"><Timeline items={history} /></Card></aside></div>
    {jobs.length ? <Card title="Tenant rollout jobs" subtitle="Select Partial data failure before publishing to review a failed tenant job."><div className="dp-table-scroll"><table className="dp-table"><thead><tr><th>Tenant</th><th>Version</th><th>Status</th><th>Action</th></tr></thead><tbody>{jobs.map(job => <tr key={job.tenant} className="static"><td>{TENANT_OPTIONS.find(t => t.id === job.tenant)?.name}</td><td className="dp-mono">{policy.version}</td><td><Badge tone={job.status === 'SUCCEEDED' ? 'success' : 'critical'}>{job.status}</Badge>{job.status === 'FAILED' ? <small className="dp-table-sub">Sample tenant job failed. Other results are retained.</small> : null}</td><td>{job.status === 'FAILED' ? <button type="button" className="dp-btn dp-btn--sm" disabled={!canPublish || action.pending} onClick={() => action.run('Failed tenant rollout retried in the mock.', () => setJobs(current => current.map(j => j.tenant === job.tenant ? { ...j, status: 'SUCCEEDED' } : j)))}>Retry rollout</button> : '—'}</td></tr>)}</tbody></table></div></Card> : null}
    <Modal open={confirm} onClose={() => setConfirm(false)} title={scope === 'ALL' ? 'Publish to all active tenants?' : 'Publish to selected tenants?'} description={`Policy ${policy.id} · Version ${policy.version}`} footer={<><button type="button" className="dp-btn" onClick={() => setConfirm(false)}>Cancel</button><button type="button" className="dp-btn dp-btn--primary" onClick={publish}>Confirm publication</button></>}><div className="dp-stack"><p>{targetIds.length} active workspace(s) will receive this sample policy version.</p>{targetIds.map(id => <div className="dp-row-gap" key={id}><ShieldCheck size={14} />{TENANT_OPTIONS.find(t => t.id === id)?.name}</div>)}<Alert title="Local simulation">No policy package or tenant configuration will be changed outside this mock.</Alert></div></Modal>
  </div>;
}
