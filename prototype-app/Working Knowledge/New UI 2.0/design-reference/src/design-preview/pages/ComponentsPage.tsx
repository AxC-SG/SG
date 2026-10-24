import React from 'react';
import { Background, Controls, Handle, Position, ReactFlow, ReactFlowProvider, type Edge, type Node, type NodeProps } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Bot, Database, Inbox, KeyRound, Server, ServerCrash, Wrench } from 'lucide-react';
import { Avatar, Badge, Card, Meter, PageHeader, Popover, Segmented, SeverityBadge, Sparkline, StatTile, StatusBadge, Drawer } from '../components/primitives';
import { Alert, EmptyState, FreshnessStatus, ProgressBar, Skeleton, Spinner, useToast } from '../components/feedback';
import { Checkbox, Field, FileDropzone, PasswordInput, RadioCards, Select, Slider, Switch, TextInput, Textarea } from '../components/forms';
import { ConfirmDialog, Menu, Modal, Tooltip } from '../components/overlays';
import { Accordion, CodeBlock, Collapsible, PropertyList, Stepper, Tabs, Timeline } from '../components/disclosure';

// Component inventory for the phase-2 migration. Every section maps to a legacy
// class family (see README "Component mapping"). Section ids are linkable: #/components#forms.

const SECTIONS = [
  ['tokens', 'Tokens'], ['buttons', 'Buttons'], ['forms', 'Forms'], ['status', 'Badges & status'], ['feedback', 'Feedback'],
  ['loading', 'Loading'], ['navigation', 'Tabs & disclosure'], ['overlays', 'Overlays'], ['data', 'Data display'], ['graph', 'Graph'],
] as const;

const SWATCHES = ['bg', 'surface', 'surface-2', 'hover', 'border', 'border-strong', 'text', 'text-2', 'text-3', 'accent', 'critical', 'high', 'medium', 'low', 'success', 'warning'];

type GraphData = { label: string; kind: string; tone: 'accent' | 'critical' | 'neutral' | 'success'; icon: React.ReactNode };
function GraphNode({ data }: NodeProps<Node<GraphData>>) {
  return (
    <div className={`dp-graph-node dp-graph-node--${data.tone}`}>
      <Handle type="target" position={Position.Left} />
      <span className="dp-graph-icon">{data.icon}</span>
      <span className="dp-graph-copy"><strong>{data.label}</strong><small>{data.kind}</small></span>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
const NODE_TYPES = { dp: GraphNode };
const NODES: Node<GraphData>[] = [
  { id: 'agent', type: 'dp', position: { x: 0, y: 90 }, data: { label: 'support-agent', kind: 'Bedrock agent', tone: 'accent', icon: <Bot size={14} /> } },
  { id: 'model', type: 'dp', position: { x: 260, y: 0 }, data: { label: 'claude-sonnet', kind: 'Model', tone: 'neutral', icon: <Server size={14} /> } },
  { id: 'tool', type: 'dp', position: { x: 260, y: 90 }, data: { label: 'refund-tool', kind: 'Action group', tone: 'critical', icon: <Wrench size={14} /> } },
  { id: 'kb', type: 'dp', position: { x: 260, y: 180 }, data: { label: 'kb-tickets', kind: 'Knowledge base', tone: 'neutral', icon: <Database size={14} /> } },
  { id: 'secret', type: 'dp', position: { x: 520, y: 90 }, data: { label: 'payments-api-key', kind: 'Secret', tone: 'critical', icon: <KeyRound size={14} /> } },
];
const EDGES: Edge[] = [
  { id: 'e1', source: 'agent', target: 'model' },
  { id: 'e2', source: 'agent', target: 'tool', animated: true, className: 'dp-edge--critical' },
  { id: 'e3', source: 'agent', target: 'kb' },
  { id: 'e4', source: 'tool', target: 'secret', animated: true, className: 'dp-edge--critical', label: 'exposure path' },
];

function RiskPhases() {
  const phases = [
    ['CVE Published', 'CVSS 9.8 · EPSS 94%', 6.1], ['In CISA KEV', 'Added Oct 22', 7.4], ['Org Exposure', '148 assets', 8.6],
    ['EOL Risk', '0 EOL components', 8.6], ['No Patch', 'Fix available', 8.2], ['Applicability', 'Confirmed affected', 9.1], ['Findings Created', '148 findings', 9.4],
  ] as const;
  return (
    <ol className="dp-phases">
      {phases.map(([name, detail, score], i) => (
        <li key={name} className={i === phases.length - 1 ? 'current' : ''}>
          <span className="dp-phase-dot" />
          <strong>{name}</strong>
          <span className="dp-muted">{detail}</span>
          <span className="dp-phase-score dp-num">{score.toFixed(1)}</span>
        </li>
      ))}
    </ol>
  );
}

export function ComponentsPage() {
  const toast = useToast();
  const [seg, setSeg] = React.useState<'a' | 'b' | 'c'>('a');
  const [tab, setTab] = React.useState<'one' | 'two' | 'three'>('one');
  const [sw, setSw] = React.useState(true);
  const [slider, setSlider] = React.useState(1.2);
  const [radio, setRadio] = React.useState<'x' | 'y'>('x');
  const [modal, setModal] = React.useState(false);
  const [confirm, setConfirm] = React.useState(false);
  const [drawer, setDrawer] = React.useState(false);

  // Scroll the shell's content pane, not the document, so the sidebar never shifts.
  const jump = (id: string, smooth = true) => {
    const target = document.getElementById(id);
    const pane = target?.closest('.dp-content');
    if (target && pane) pane.scrollTo({ top: target.offsetTop - 8, behavior: smooth ? 'smooth' : 'auto' });
  };
  React.useEffect(() => {
    const id = window.location.hash.split('#')[2];
    if (id) jump(id, false);
  }, []);

  return (
    <div className="dp-page dp-gallery">
      <PageHeader eyebrow="Design reference" title="Component Library" description="Every primitive and state the app needs. Use these, and only these, when restyling a page." />
      <nav className="dp-gallery-toc" aria-label="Sections">
        {SECTIONS.map(([id, label]) => <a key={id} href={`#/components#${id}`} onClick={(e) => { e.preventDefault(); jump(id); }}>{label}</a>)}
      </nav>

      <section id="tokens" className="dp-gallery-section">
        <h2>Tokens</h2>
        <div className="dp-swatches">
          {SWATCHES.map((s) => <div key={s} className="dp-swatch-tile"><span style={{ background: `var(--dp-${s})` }} /><code>--dp-{s}</code></div>)}
        </div>
        <div className="dp-type-scale">
          <span style={{ fontSize: 'var(--dp-text-3xl)', fontWeight: 600, letterSpacing: '-0.02em' }}>Display 28</span>
          <span style={{ fontSize: 'var(--dp-text-2xl)', fontWeight: 600, letterSpacing: '-0.02em' }}>Page title 22</span>
          <span style={{ fontSize: 'var(--dp-text-xl)', fontWeight: 600 }}>Section 16</span>
          <span style={{ fontSize: 'var(--dp-text-lg)', fontWeight: 600 }}>Card title 14</span>
          <span>Body 13 — the default for tables, forms and copy.</span>
          <span className="dp-muted" style={{ fontSize: 'var(--dp-text-sm)' }}>Caption 12 · secondary text</span>
          <span className="dp-mono">CVE-2026-31337 · mono 12 for identifiers</span>
        </div>
      </section>

      <section id="buttons" className="dp-gallery-section">
        <h2>Buttons</h2>
        <div className="dp-demo-row">
          <button type="button" className="dp-btn dp-btn--primary">Primary</button>
          <button type="button" className="dp-btn">Secondary</button>
          <button type="button" className="dp-btn dp-btn--ghost">Ghost</button>
          <button type="button" className="dp-btn dp-btn--danger">Danger</button>
          <button type="button" className="dp-btn dp-btn--danger-ghost">Danger ghost</button>
          <button type="button" className="dp-btn" disabled>Disabled</button>
          <button type="button" className="dp-btn dp-btn--primary" disabled><Spinner /> Saving…</button>
          <button type="button" className="dp-link">Link button</button>
        </div>
        <div className="dp-demo-row">
          <button type="button" className="dp-btn dp-btn--primary dp-btn--sm">Small</button>
          <button type="button" className="dp-btn dp-btn--sm">Small</button>
          <button type="button" className="dp-icon-btn" aria-label="Icon button"><Wrench size={16} /></button>
          <Segmented value={seg} onChange={setSeg} options={[{ value: 'a', label: '7D' }, { value: 'b', label: '30D' }, { value: 'c', label: '90D' }]} />
        </div>
      </section>

      <section id="forms" className="dp-gallery-section">
        <h2>Forms</h2>
        <div className="dp-grid-2">
          <Card title="Text inputs">
            <div className="dp-form">
              <Field label="Name" htmlFor="g-name" required hint="Shown in the tenant switcher."><TextInput id="g-name" placeholder="Acme Corporation" /></Field>
              <Field label="Slug" htmlFor="g-slug" error="Slug already in use."><TextInput id="g-slug" defaultValue="acme" className="dp-mono" /></Field>
              <Field label="Threshold" htmlFor="g-thr"><TextInput id="g-thr" defaultValue="9.0" suffix="/ 10" /></Field>
              <Field label="Secret" htmlFor="g-sec"><PasswordInput id="g-sec" defaultValue="s3cr3t-value" /></Field>
              <Field label="Disabled" htmlFor="g-dis"><TextInput id="g-dis" disabled defaultValue="Read only" /></Field>
              <Field label="Notes" htmlFor="g-notes"><Textarea id="g-notes" rows={3} placeholder="Optional" /></Field>
            </div>
          </Card>
          <Card title="Selection">
            <div className="dp-form">
              <Field label="Region" htmlFor="g-region"><Select id="g-region"><option>us-east-1</option><option>eu-west-1</option></Select></Field>
              <Field label="Valid from" htmlFor="g-date"><TextInput id="g-date" type="datetime-local" /></Field>
              <Checkbox label="Add demo data" description="Seeds a realistic dataset once the tenant is ACTIVE." defaultChecked />
              <Switch checked={sw} onChange={setSw} label="Scheduled sync" description="Runs every 5 minutes when due." />
              <Slider label="Exploitability weight" min={0} max={2} step={0.1} value={slider} onChange={setSlider} />
              <RadioCards name="g-radio" value={radio} onChange={setRadio} options={[{ value: 'x', label: 'Automatic', description: 'Create on correlation.' }, { value: 'y', label: 'Manual', description: 'Analyst promotes.' }]} />
              <FileDropzone accept=".json,.xml,.spdx" />
            </div>
          </Card>
        </div>
      </section>

      <section id="status" className="dp-gallery-section">
        <h2>Badges &amp; status</h2>
        <div className="dp-demo-row">
          {(['critical', 'high', 'medium', 'low'] as const).map((s) => <SeverityBadge key={s} severity={s} />)}
          {(['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'] as const).map((s) => <StatusBadge key={s} status={s} />)}
          <Badge tone="critical">KEV</Badge><Badge tone="warning">Exploit</Badge><Badge tone="accent">AI Security</Badge><Badge>NOT_REQUESTED</Badge>
        </div>
        <div className="dp-demo-row">
          {(['healthy', 'failing', 'idle', 'disabled'] as const).map((h) => <span key={h} className="dp-cell-title"><span className={`dp-status-dot dp-status-dot--${h}`} role="img" aria-label={h} />{h}</span>)}
          <Avatar name="Priya Raman" /><Avatar name="Marcus Lee" /><Meter value={9.4} /><Meter value={6.2} /><Meter value={2.1} />
        </div>
      </section>

      <section id="feedback" className="dp-gallery-section">
        <h2>Feedback</h2>
        <div className="dp-stack">
          <Alert tone="info" title="Notice">Replaces <code>.notice</code>. Keep <code>role="status"</code>.</Alert>
          <Alert tone="success">Password created successfully.</Alert>
          <Alert tone="warning" title="UI-only connector">Not wired to a backend yet.</Alert>
          <Alert tone="danger" title="Last sync failed" action={<button type="button" className="dp-link">Retry</button>}>Replaces <code>.notice.error</code>. Keep <code>role="alert"</code>.</Alert>
          <div className="dp-demo-row">
            <button type="button" className="dp-btn" onClick={() => toast('success', 'Configuration saved')}>Show toast</button>
            <span className="dp-muted">Toasts are for transient confirmations only — never replace an inline notice with one.</span>
          </div>
          <FreshnessStatus updatedAt="Oct 24, 2026, 10:46 AM" />
          <FreshnessStatus updatedAt="" isRefreshing refreshLabel="Refreshing findings while keeping current results visible…" />
        </div>
      </section>

      <section id="loading" className="dp-gallery-section">
        <h2>Loading, empty &amp; error</h2>
        <div className="dp-grid-3">
          <Card title="Skeleton"><div className="dp-stack"><Skeleton width="40%" /><Skeleton /><Skeleton width="80%" /><Skeleton height={60} radius={8} /></div></Card>
          <Card title="Progress"><div className="dp-stack"><Spinner label="Loading findings…" /><ProgressBar value={62} label="Sync progress" /><ProgressBar value={100} tone="success" label="Done" /><ProgressBar value={37} tone="critical" label="Failed" /></div></Card>
          <Card title="Empty / error">
            <EmptyState icon={<Inbox size={18} />} title="No findings yet" action={<button type="button" className="dp-btn dp-btn--sm">Configure Sources</button>}>Findings appear once vulnerabilities correlate with inventory.</EmptyState>
            <EmptyState icon={<ServerCrash size={18} />} title="Couldn't load this view" action={<button type="button" className="dp-btn dp-btn--sm">Retry</button>}>Request failed with 503.</EmptyState>
          </Card>
        </div>
      </section>

      <section id="navigation" className="dp-gallery-section">
        <h2>Tabs &amp; disclosure</h2>
        <Tabs label="Demo tabs" value={tab} onChange={setTab} tabs={[{ value: 'one', label: 'Overview' }, { value: 'two', label: 'Affected Assets', count: 12 }, { value: 'three', label: 'History' }]} />
        <div className="dp-grid-2" style={{ marginTop: 16 }}>
          <div className="dp-stack">
            <Accordion title="Vulnerability Intelligence" meta="7 sources" defaultOpen>Native &lt;details&gt; — open state, keyboard and tests unchanged.</Accordion>
            <Accordion title="Advanced settings">Collapsed by default.</Accordion>
            <Collapsible label="Show raw evidence"><CodeBlock language="json" code={'{\n  "cpe": "cpe:2.3:a:apache:log4j:2.14.1",\n  "decision": "AFFECTED"\n}'} /></Collapsible>
          </div>
          <Card title="Stepper & timeline">
            <Stepper steps={['Connect', 'Authenticate', 'Scope', 'Schedule']} current={2} />
            <Timeline items={[
              { title: 'Correlated via CPE match', meta: 'Oct 12' },
              { title: 'Added to CISA KEV', meta: 'Oct 22', tone: 'critical' },
              { title: 'Resolved', meta: 'Oct 24', tone: 'success', body: 'Upgraded to 2.25.3' },
            ]} />
          </Card>
        </div>
      </section>

      <section id="overlays" className="dp-gallery-section">
        <h2>Overlays</h2>
        <div className="dp-demo-row">
          <button type="button" className="dp-btn" onClick={() => setModal(true)}>Modal</button>
          <button type="button" className="dp-btn dp-btn--danger" onClick={() => setConfirm(true)}>Confirm (type-to-confirm)</button>
          <button type="button" className="dp-btn" onClick={() => setDrawer(true)}>Drawer</button>
          <Popover trigger={({ toggle }) => <button type="button" className="dp-btn" onClick={toggle}>Menu</button>}>
            {(close) => <Menu items={[{ label: 'Edit', onSelect: close }, { label: 'Duplicate', onSelect: close }, 'separator', { label: 'Delete', danger: true, onSelect: close }, { label: 'Disabled item', disabled: true, onSelect: close }]} />}
          </Popover>
          <Tooltip content="Scout AI-computed priority score (0–10)"><button type="button" className="dp-btn">Hover for tooltip</button></Tooltip>
        </div>
        <Modal open={modal} onClose={() => setModal(false)} title="Create Incident" description="2 selected findings" footer={<><button type="button" className="dp-btn" onClick={() => setModal(false)}>Cancel</button><button type="button" className="dp-btn dp-btn--primary" onClick={() => setModal(false)}>Confirm</button></>}>
          <div className="dp-form"><Field label="Assigned To" htmlFor="m-a"><TextInput id="m-a" /></Field><Field label="Notes" htmlFor="m-n"><Textarea id="m-n" rows={3} /></Field></div>
        </Modal>
        <ConfirmDialog open={confirm} onCancel={() => setConfirm(false)} onConfirm={() => setConfirm(false)} title="Delete tenant?" confirmLabel="Delete tenant" requireText="acme" body="This removes the tenant schema and all its data." />
        <Drawer open={drawer} onClose={() => setDrawer(false)} title="EOL detail" eyebrow="Drawer — replaces EolDetailDrawer / SoftwareIdentityDetailDrawer visuals">
          <PropertyList items={[['Product', 'nginx'], ['Cycle', '1.24'], ['EOL date', '2026-11-30'], ['Status', <Badge key="b" tone="warning" dot>Nearing EOL</Badge>]]} />
        </Drawer>
      </section>

      <section id="data" className="dp-gallery-section">
        <h2>Data display</h2>
        <div className="dp-kpi-grid dp-kpi-grid--4">
          <StatTile label="Critical Findings" value="84" sub="Active open findings" tone="critical" onClick={() => undefined} />
          <StatTile label="Open Findings" value="1,223" sub="All severities" tone="warning" onClick={() => undefined} />
          <StatTile label="Static tile" value="42" sub="Not clickable" />
          <StatTile label="With series" value="37" sub="Only when data exists" tone="high" spark={[3, 5, 4, 8, 6, 9, 12]} />
        </div>
        <div className="dp-grid-2" style={{ marginTop: 16 }}>
          <Card title="CVE risk score phases" subtitle="CveRiskScorePanel — horizontal phase timeline"><RiskPhases /></Card>
          <Card title="Properties & code">
            <PropertyList items={[['CVE ID', <span key="c" className="dp-mono">CVE-2026-31337</span>], ['EPSS', '94.3%'], ['Package', <span key="p" className="dp-mono">log4j-core@2.14.1</span>], ['Trend', <Sparkline key="s" values={[2, 3, 3, 5, 8, 9]} tone="critical" />]]} />
            <CodeBlock language="shell" code="mvn versions:use-dep-version -Dincludes=*:log4j-core -DdepVersion=2.25.3" />
          </Card>
        </div>
      </section>

      <section id="graph" className="dp-gallery-section">
        <h2>Graph</h2>
        <p className="dp-muted">AiDependencyGraph / exposure paths. React Flow stays; only node, edge and canvas styling move to tokens.</p>
        <div className="dp-graph">
          <ReactFlowProvider>
            <ReactFlow nodes={NODES} edges={EDGES} nodeTypes={NODE_TYPES} fitView nodesDraggable={false}>
              <Background gap={16} size={1} />
              <Controls showInteractive={false} />
            </ReactFlow>
          </ReactFlowProvider>
        </div>
      </section>
    </div>
  );
}
