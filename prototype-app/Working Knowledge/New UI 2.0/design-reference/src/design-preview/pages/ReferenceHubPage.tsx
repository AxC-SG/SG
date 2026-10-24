import { ArrowRight, Bot, Boxes, GitPullRequestArrow, Layers, Microscope, ShieldCheck } from 'lucide-react';
import { Badge, Card, PageHeader } from '../components/primitives';

const EXAMPLES = [
  { title: 'Findings experience parity', route: '/findings/ai', label: 'Tenant · Findings', icon: <ShieldCheck size={21} />, text: 'Compare AI and vulnerability findings with shared table, toolbar, state, and evidence patterns.', tags: ['Domain filters', 'Detail navigation', 'Shared presentation'] },
  { title: 'CVE assessment workbench', route: '/vuln-repo/org-cves/CVE-2026-31337', label: 'Tenant · Investigation', icon: <Microscope size={21} />, text: 'Follow evidence into applicability decisions, bulk review, and finding creation.', tags: ['Evidence expansion', 'Bulk decisions', 'Save / retry'] },
  { title: 'AI asset detail', route: '/inventory/ai/support-agent', label: 'Tenant · AI Security', icon: <Bot size={21} />, text: 'Inspect policy results, static discovery evidence, and connected resources in context.', tags: ['Relationship graph', 'Provenance', 'Evidence drawer'] },
  { title: 'Policy distribution', route: '/platform/ai-policies', label: 'Platform · Governance', icon: <GitPullRequestArrow size={21} />, text: 'Choose a tenant cohort, validate in dev/test, approve, and review a rollout.', tags: ['Native multi-select', 'Lifecycle gates', 'Failed jobs'] },
  { title: 'Inventory & lifecycle', route: '/inventory/overview', label: 'Tenant · Inventory', icon: <Boxes size={21} />, text: 'Stress-test dense records, long identifiers, expandable versions, and EOL detail.', tags: ['Nested records', 'Column filters', 'Lifecycle drawer'] },
  { title: 'States & permissions', route: '/reference/scenarios', label: 'Reference · Scenario fixtures', icon: <ShieldCheck size={21} />, text: 'Explore actual role restrictions, entitlement gaps, refresh, failure, and blocked states.', tags: ['Role matrix', 'Retained edits', 'Lifecycle fixtures'] },
  { title: 'Component library', route: '/components', label: 'Reference · Shared system', icon: <Layers size={21} />, text: 'Review the shared forms, overlays, disclosure patterns, status treatments, and tokens.', tags: ['Light & dark', 'Keyboard access', 'Native controls'] },
];

export function ReferenceHubPage({ onNavigate }: { onNavigate: (route: string) => void }) {
  return <div className="dp-page dp-review-hub">
    <div className="dp-fixture-label">UI 2.0 · Interactive design reference · Sample data only</div>
    <PageHeader eyebrow="ScoutGrid / Design review" title="A clearer view of complex security work." description="Explore the interface where it matters most: evidence, decisions, and the next action." actions={<Badge tone="accent">Enriched reference</Badge>} />
    <div className="dp-review-intro"><div><strong>One system. Two workspaces.</strong><p>Every example shares the same tokens and component vocabulary. Changes are local to this mock; no API, provider, or tenant is contacted.</p></div><div className="dp-review-checks"><span>Tenant + Platform</span><span>Light + dark</span><span>Keyboard + responsive</span></div></div>
    <div className="dp-review-grid">{EXAMPLES.map(example => <button key={example.route} type="button" className="dp-review-card" onClick={() => onNavigate(example.route)}><span className="dp-review-card-top"><span className="dp-review-icon">{example.icon}</span><ArrowRight size={17} /></span><span className="dp-fixture-label">{example.label}</span><strong>{example.title}</strong><span className="dp-review-card-copy">{example.text}</span><span className="dp-review-tags">{example.tags.map(tag => <span key={tag}>{tag}</span>)}</span></button>)}</div>
    <Card title="Continue through the existing patterns" subtitle="The original reference pages remain available."><div className="dp-row-gap dp-wrap">{[['Exposure Dashboard', '/exposure'], ['Findings', '/findings'], ['Finding detail', '/findings/F-10420'], ['Connectors', '/connect'], ['Configurations', '/configurations/sla'], ['Tenant Management', '/platform/tenants'], ['Login', '/login']].map(([label, route]) => <button key={route} type="button" className="dp-btn dp-btn--sm" onClick={() => onNavigate(route)}>{label}<ArrowRight size={12} /></button>)}</div></Card>
  </div>;
}
