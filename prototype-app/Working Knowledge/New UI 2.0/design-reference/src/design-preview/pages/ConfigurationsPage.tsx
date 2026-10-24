import { useCapabilities } from '../previewContext';
import React from 'react';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { Badge, Card, PageHeader } from '../components/primitives';
import { Alert } from '../components/feedback';
import { Field, RadioCards, Select, Slider, Switch, TextInput, Textarea } from '../components/forms';
import { ConfirmDialog } from '../components/overlays';

// Reference for ConfigurationsPage. Section switching stays in the primary nav (as today);
// each section keeps its own "Save" row with validation errors + status message (renderSaveRow).

type Section = 'sla' | 'triage' | 'automation' | 'ownership' | 'findings-score' | 'suppress' | 'auto-findings';
const SECTIONS: Record<Section, { title: string; description: string }> = {
  sla: { title: 'SLA & Remediation', description: 'Risk score thresholds, remediation deadlines per severity, and asset criticality multipliers.' },
  triage: { title: 'S.AI Prioritization', description: 'Weight the urgency signals that drive S.AI Priority across findings and CVEs.' },
  automation: { title: 'Workflow Automation', description: 'Auto-close rules and finding generation mode.' },
  ownership: { title: 'Ownership', description: 'Rule-based user and group assignment for findings.' },
  'findings-score': { title: 'Findings Score', description: 'Custom attribute-based scoring rules evaluated at query time.' },
  suppress: { title: 'Suppression Rules', description: 'Define rules that suppress CVE or finding records when matching conditions are met.' },
  'auto-findings': { title: 'Auto Investigation & Findings', description: 'Automatically create findings based on CVE, software, and asset criteria.' },
};

function SaveBar({ errors, message, onSave, saving }: { errors: string[]; message: string; onSave: () => void; saving: boolean }) {
  return (
    <div className="dp-save-bar">
      {errors.length ? (
        <div className="dp-save-errors" role="alert"><ul>{errors.map((e) => <li key={e}>{e}</li>)}</ul></div>
      ) : message ? <span className="dp-save-msg" role="status">{message}</span> : <span className="dp-muted">Changes apply to the tenant risk policy.</span>}
      <button type="button" className="dp-btn dp-btn--primary dp-ml-auto" onClick={onSave} disabled={saving || errors.length > 0}>{saving ? 'Saving…' : 'Save'}</button>
    </div>
  );
}

const TRIAGE = [
  ['Exploitability weight', 1.2], ['Blast radius weight', 1.0], ['EOL risk weight', 0.8],
  ['SLA breach weight', 1.1], ['Missing owner boost', 0.5], ['Patch gap boost', 0.7],
] as const;

const SCORE_TABLES = ['findings', 'vulnerabilities', 'assets'];
const SCORE_COLUMNS: Record<string, string[]> = { findings: ['severity', 'status', 'due_at'], vulnerabilities: ['cvss_score', 'epss_score', 'in_kev'], assets: ['criticality', 'environment', 'internet_facing'] };

export function ConfigurationsPage({ route }: { route: string; onNavigate: (route: string) => void }) {
  const { canConfigure } = useCapabilities();
  const section = (route.split('/')[2] as Section) in SECTIONS ? (route.split('/')[2] as Section) : 'sla';
  const [message, setMessage] = React.useState('');
  const [saving, setSaving] = React.useState(false);
  const [weights, setWeights] = React.useState<number[]>(TRIAGE.map(([, w]) => w));
  const [critThreshold, setCritThreshold] = React.useState('9.0');
  const [autoClose, setAutoClose] = React.useState(true);
  const [mode, setMode] = React.useState<'AUTO' | 'MANUAL'>('AUTO');
  const [rules, setRules] = React.useState([
    { table: 'vulnerabilities', column: 'in_kev', op: '=', value: 'true', weight: '0.4' },
    { table: 'vulnerabilities', column: 'epss_score', op: '>=', value: '0.5', weight: '0.35' },
    { table: 'assets', column: 'internet_facing', op: '=', value: 'true', weight: '0.25' },
  ]);
  const [deleting, setDeleting] = React.useState<string | null>(null);

  React.useEffect(() => { setMessage(''); }, [section]);
  const save = () => { setSaving(true); window.setTimeout(() => { setSaving(false); setMessage('Risk policy saved.'); }, 600); };

  const errors: string[] = [];
  if (section === 'sla' && (critThreshold.trim() === '' || Number.isNaN(Number(critThreshold)) || Number(critThreshold) < 0 || Number(critThreshold) > 10)) errors.push('Critical threshold must be a number between 0 and 10.');
  const weightSum = rules.reduce((s, r) => s + Number(r.weight || 0), 0);
  if (section === 'findings-score' && Math.abs(weightSum - 1) > 0.001) errors.push(`Weights must sum to 1.0 (currently ${weightSum.toFixed(2)}).`);

  const sim = Math.min(10, 5.1 * weights[0] * 0.4 + 3 * weights[1] * 0.25 + 2 * weights[3] * 0.2 + weights[4] + weights[5] * 0.6);

  return (
    <div className="dp-page dp-page--narrow">
      <PageHeader eyebrow="Configurations" title={SECTIONS[section].title} description={SECTIONS[section].description} />

      {!canConfigure ? <Alert title="Read-only policy access">A tenant administrator is required to change policy settings.</Alert> : null}
      <fieldset className="dp-form-boundary" disabled={!canConfigure}>
      {section === 'sla' ? (
        <>
          <Card title="Risk score thresholds">
            <div className="dp-form dp-form--2col">
              <Field label="Critical at or above" htmlFor="t-crit" error={errors[0]}><TextInput id="t-crit" inputMode="decimal" value={critThreshold} onChange={(e) => setCritThreshold(e.target.value)} suffix="/ 10" /></Field>
              <Field label="High at or above" htmlFor="t-high"><TextInput id="t-high" inputMode="decimal" defaultValue="7.0" suffix="/ 10" /></Field>
            </div>
          </Card>
          <Card title="Remediation deadlines" subtitle="Days from first observation until a finding breaches SLA.">
            <table className="dp-table dp-table--form">
              <thead><tr><th>Severity</th><th>Deadline</th><th>Notify before</th></tr></thead>
              <tbody>
                {[['critical', 7, 2], ['high', 30, 5], ['medium', 90, 14], ['low', 180, 30]].map(([sev, d, n]) => (
                  <tr key={sev} className="static">
                    <td><Badge tone={sev as 'critical'} dot>{String(sev)[0].toUpperCase() + String(sev).slice(1)}</Badge></td>
                    <td><TextInput aria-label={`${sev} deadline`} type="number" defaultValue={d} suffix="days" /></td>
                    <td><TextInput aria-label={`${sev} notify`} type="number" defaultValue={n} suffix="days" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <Card title="Asset criticality SLA multipliers">
            <div className="dp-form dp-form--3col">
              {[['Tier 0 — crown jewels', '0.5'], ['Tier 1 — production', '0.75'], ['Tier 2 — internal', '1.0']].map(([l, v]) => (
                <Field key={l} label={l} htmlFor={`m-${l}`}><TextInput id={`m-${l}`} defaultValue={v} prefix="×" /></Field>
              ))}
            </div>
          </Card>
        </>
      ) : null}

      {section === 'triage' ? (
        <div className="dp-grid-3-2">
          <Card title="Urgency signal weights" subtitle="Client-side only until backend columns exist (see Verified gap).">
            <div className="dp-form">
              {TRIAGE.map(([label], i) => (
                <Slider key={label} label={label} min={0} max={2} step={0.1} value={weights[i]} onChange={(v) => setWeights(weights.map((w, j) => (j === i ? v : w)))} />
              ))}
            </div>
          </Card>
          <Card title="Triage Score Simulator" subtitle="CVE-2026-31337 on prod-api-gw-01">
            <div className="dp-sim">
              <div className="dp-score-ring dp-score-ring--lg" style={{ '--dp-score': `${sim * 10}%` } as React.CSSProperties}><span>{sim.toFixed(1)}</span></div>
              <div className="dp-sim-factors">
                {TRIAGE.map(([label], i) => (
                  <div key={label} className="dp-row-between"><span className="dp-muted">{label}</span><strong className="dp-num">×{weights[i].toFixed(1)}</strong></div>
                ))}
              </div>
            </div>
          </Card>
        </div>
      ) : null}

      {section === 'automation' ? (
        <>
          <Card title="Auto-close">
            <div className="dp-form">
              <Switch checked={autoClose} onChange={setAutoClose} label="Auto-close resolved findings" description="Runs hourly. Closes findings whose component is no longer observed." />
              <Field label="Close after" htmlFor="ac-days"><TextInput id="ac-days" type="number" defaultValue={14} disabled={!autoClose} suffix="days" /></Field>
            </div>
          </Card>
          <Card title="Finding generation mode">
            <RadioCards name="mode" value={mode} onChange={setMode} options={[
              { value: 'AUTO', label: 'Automatic', description: 'Create findings as soon as correlation confirms applicability.' },
              { value: 'MANUAL', label: 'Manual', description: 'Analysts promote CVEs to findings from the workbench.' },
            ]} />
          </Card>
        </>
      ) : null}

      {section === 'findings-score' ? (
        <Card title="Scoring rules" subtitle={`${rules.length} / 10 columns · weights sum ${weightSum.toFixed(2)}`} actions={<button type="button" className="dp-btn dp-btn--sm" disabled={rules.length >= 10} onClick={() => setRules([...rules, { table: 'findings', column: 'severity', op: '=', value: '', weight: '0' }])}><Plus size={13} /> Add column</button>}>
          <div className="dp-rule-rows dp-rule-rows--score">
            <div className="dp-rule-head"><span>Table</span><span>Column</span><span>Operator</span><span>Value</span><span>Weight</span><span /></div>
            {rules.map((r, i) => {
              const set = (patch: Partial<typeof r>) => setRules(rules.map((x, j) => (j === i ? { ...x, ...patch } : x)));
              return (
                <div key={i} className="dp-rule-row">
                  <Select aria-label={`Table ${i + 1}`} value={r.table} onChange={(e) => set({ table: e.target.value, column: SCORE_COLUMNS[e.target.value][0] })}>{SCORE_TABLES.map((t) => <option key={t}>{t}</option>)}</Select>
                  <Select aria-label={`Column ${i + 1}`} value={r.column} onChange={(e) => set({ column: e.target.value })}>{SCORE_COLUMNS[r.table].map((c) => <option key={c}>{c}</option>)}</Select>
                  <Select aria-label={`Operator ${i + 1}`} value={r.op} onChange={(e) => set({ op: e.target.value })}>{['=', '!=', '>=', '<=', 'contains'].map((o) => <option key={o}>{o}</option>)}</Select>
                  <span className="dp-mobile-field" data-label="Value"><TextInput aria-label={`Value ${i + 1}`} value={r.value} onChange={(e) => set({ value: e.target.value })} /></span>
                  <span className="dp-mobile-field" data-label="Weight"><TextInput aria-label={`Weight ${i + 1}`} value={r.weight} inputMode="decimal" onChange={(e) => set({ weight: e.target.value })} /></span>
                  <button type="button" className="dp-icon-btn sm" aria-label={`Remove rule ${i + 1}`} onClick={() => setRules(rules.filter((_, j) => j !== i))}><Trash2 size={13} /></button>
                </div>
              );
            })}
          </div>
        </Card>
      ) : null}

      {section === 'suppress' || section === 'ownership' || section === 'auto-findings' ? (
        <>
          <div className="dp-table-card">
            <div className="dp-toolbar"><strong>{SECTIONS[section].title}</strong><div className="dp-toolbar-right"><button type="button" className="dp-btn dp-btn--primary dp-btn--sm"><Plus size={13} /> New rule</button></div></div>
            <table className="dp-table">
              <thead><tr><th>Name</th><th>State</th><th>Record type</th><th>Valid</th><th>Order</th><th /></tr></thead>
              <tbody>
                {[['Dev assets — 30d', 'APPROVED', 'FINDING', 'Oct 1 → Oct 31', 1], ['Vendor-disputed CVEs', 'IN_REVIEW', 'CVE', 'Oct 12 → —', 2], ['Legacy SCCM noise', 'DRAFT', 'FINDING', '—', 3], ['Q3 exception', 'EXPIRED', 'CVE', 'Jul 1 → Sep 30', 4]].map(([name, state, type, valid, order]) => (
                  <tr key={String(name)} className="static">
                    <td><strong>{name}</strong></td>
                    <td><Badge tone={state === 'APPROVED' ? 'success' : state === 'IN_REVIEW' ? 'warning' : state === 'EXPIRED' ? 'neutral' : 'accent'} dot>{String(state).replace('_', ' ')}</Badge></td>
                    <td className="dp-mono dp-muted">{type}</td>
                    <td className="dp-muted dp-num">{valid}</td>
                    <td className="dp-num">{order}</td>
                    <td className="dp-cell-actions">
                      <button type="button" className="dp-btn dp-btn--ghost dp-btn--sm"><Pencil size={12} /> Edit</button>
                      <button type="button" className="dp-btn dp-btn--ghost dp-btn--sm dp-text-critical" onClick={() => setDeleting(String(name))}><Trash2 size={12} /> Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Card title="Rule form" subtitle="Inline create/edit form — stays inline, as today.">
            <div className="dp-form dp-form--2col">
              <Field label="Name" htmlFor="r-name" required><TextInput id="r-name" placeholder="e.g. Dev assets — 30d" /></Field>
              <Field label="State" htmlFor="r-state"><Select id="r-state"><option>DRAFT</option><option>IN_REVIEW</option><option>APPROVED</option></Select></Field>
              <Field label="Valid from" htmlFor="r-from"><TextInput id="r-from" type="datetime-local" /></Field>
              <Field label="Valid to" htmlFor="r-to"><TextInput id="r-to" type="datetime-local" /></Field>
            </div>
            <div className="dp-form" style={{ marginTop: 12 }}><Field label="Reason" htmlFor="r-reason"><Textarea id="r-reason" rows={2} /></Field></div>
          </Card>
          <Alert tone="info">Rule lists save per-rule (Close / Save in the form). The section-level Save row below only appears on policy-backed sections.</Alert>
        </>
      ) : null}

      {['sla', 'triage', 'automation', 'findings-score'].includes(section) ? <SaveBar errors={errors} message={message} onSave={save} saving={saving} /> : null}

      </fieldset>
      <ConfirmDialog open={deleting !== null} onCancel={() => setDeleting(null)} onConfirm={() => setDeleting(null)} title="Delete rule?" confirmLabel="Delete" body={<>Delete <strong>{deleting}</strong>? Records it suppressed reopen on the next sweep.</>} />
    </div>
  );
}
