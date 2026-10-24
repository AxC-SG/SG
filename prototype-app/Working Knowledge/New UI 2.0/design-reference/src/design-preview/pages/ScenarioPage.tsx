import { ArrowRight, ShieldCheck } from 'lucide-react';
import { Badge, Card, PageHeader } from '../components/primitives';
import { Alert } from '../components/feedback';
import { Field, Select, Switch } from '../components/forms';
import { SCENARIOS } from '../components/ScenarioFrame';
import { DEFAULT_PREVIEW, type PreviewState } from '../previewContext';

export const ROLES = [['TENANT_ADMIN', 'Tenant admin'], ['SECURITY_ANALYST', 'Security analyst'], ['INVENTORY_ADMIN', 'Inventory admin'], ['READ_ONLY_AUDITOR', 'Read-only auditor']] as const;

export function ScenarioPage({ state, onChange, onNavigate }: { state: PreviewState; onChange: (patch: Partial<PreviewState>) => void; onNavigate: (route: string) => void }) {
  return <div className="dp-page">
    <PageHeader eyebrow="Reference tools · Not product UI" title="States & permissions" description="Use deterministic fixtures to review the interface beyond the happy path." actions={<button className="dp-btn" type="button" onClick={() => onChange(DEFAULT_PREVIEW)}>Reset all fixtures</button>} />
    <div className="dp-grid-3-2">
      <Card title="Build a review scenario" subtitle="These choices persist as you move between mock pages."><div className="dp-form">
        <Field label="Workspace scope" htmlFor="scenario-scope"><Select id="scenario-scope" value={state.scope} onChange={e => onChange({ scope: e.target.value as PreviewState['scope'] })}><option value="tenant">Tenant workspace</option><option value="platform">Platform owner</option></Select></Field>
        <Field label="Tenant role" htmlFor="scenario-role" hint="Platform scope uses the Platform Owner fixture."><Select id="scenario-role" value={state.role} disabled={state.scope === 'platform'} onChange={e => onChange({ role: e.target.value as PreviewState['role'] })}>{ROLES.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select></Field>
        <Field label="Data & lifecycle state" htmlFor="scenario-state"><Select id="scenario-state" value={state.scenario} onChange={e => onChange({ scenario: e.target.value as PreviewState['scenario'] })}>{SCENARIOS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</Select></Field>
        <Switch checked={state.aiEntitled} onChange={aiEntitled => onChange({ aiEntitled })} label="AI Security entitlement" description="Hide AI navigation and prevent AI detail content when unavailable." />
        <Switch checked={state.enhancements} onChange={enhancements => onChange({ enhancements })} label="Optional UI enhancements" description="Enable command search and desktop sidebar collapse. Off in the baseline." />
      </div></Card>
      <Card title="Open this scenario" subtitle="Try the same fixture across different screen families."><div className="dp-stack"><div className="dp-row-gap"><Badge tone="accent">{state.scope === 'platform' ? 'Platform owner' : ROLES.find(([role]) => role === state.role)?.[1]}</Badge><Badge>{SCENARIOS.find(([key]) => key === state.scenario)?.[1]}</Badge></div>{[['Inventory & lifecycle', '/inventory/overview'], ['CVE workbench', '/vuln-repo/org-cves/CVE-2026-31337'], ['AI asset detail', '/inventory/ai/support-agent'], ['Findings', '/findings']].map(([title, route]) => <button type="button" className="dp-scenario-link" key={route} onClick={() => onNavigate(route)}>{title}<ArrowRight size={14} /></button>)}<Alert title="Local simulation">Save-failure fixtures retain edits. No configuration is written outside this browser session.</Alert></div></Card>
    </div>
    <Card title="Permission contract" subtitle="The mock changes available navigation and mutation controls, rather than only changing the persona label."><div className="dp-table-scroll"><table className="dp-table"><thead><tr><th>Tenant role</th><th>Read evidence</th><th>Triage findings</th><th>Manage inventory</th><th>Configure policy</th></tr></thead><tbody>{ROLES.map(([role, label]) => <tr className={`static${state.role === role ? ' selected' : ''}`} key={role}><td>{label}</td>{[true, ['TENANT_ADMIN', 'SECURITY_ANALYST'].includes(role), ['TENANT_ADMIN', 'INVENTORY_ADMIN'].includes(role), role === 'TENANT_ADMIN'].map((allowed, i) => <td key={i}><span className={allowed ? 'dp-text-success' : 'dp-muted'}>{allowed ? 'Allowed' : 'Read only'}</span></td>)}</tr>)}</tbody></table></div></Card>
    <div className="dp-review-intro"><ShieldCheck size={20} /><div><strong>Review the behavior as well as the surface.</strong><p>Open a dialog and cycle Tab / Shift+Tab. Test the rightmost table filter, a failed save, a long identifier, and a graph with no relationships. Use the theme button to repeat in light and dark.</p></div></div>
  </div>;
}
