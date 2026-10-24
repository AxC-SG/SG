import { useCapabilities } from '../previewContext';
import React from 'react';
import { FindingsFamilyNav } from '../components/FindingsFamilyNav';
import { CheckCircle2, ChevronDown, Columns3, Filter, Info, Inbox, Lock } from 'lucide-react';
import { FINDINGS, STATUS_LABEL, type FindingStatus, type MockFinding, type Severity } from '../data';
import { Badge, Meter, PageHeader, Popover, SeverityBadge, StatusBadge } from '../components/primitives';
import { Alert, EmptyState, FreshnessStatus, Skeleton } from '../components/feedback';
import { Field, Select, TextInput, Textarea } from '../components/forms';
import { Menu, Modal, Tooltip } from '../components/overlays';
import { usePreview } from '../previewContext';

// Visual reference for pages/FindingsPage.tsx; live hooks remain the behavior authority. Summary widgets,
// GROUP BY, header column filters, Resolve + "More actions", column settings,
// queue actions, action dialogs, cursor pagination, row-click selection.

type ColKey = 'findingId' | 'cveId' | 'asset' | 'owner' | 'supportGroup' | 'package' | 'severity' | 'status' | 'creationSource'
  | 'risk' | 'priority' | 'ownerGroup' | 'assignedTo' | 'dueDate' | 'incidentId' | 'incidentStatus' | 'suppressionRule' | 'firstObserved' | 'lastObserved';

const ALL_COLUMNS: Array<{ key: ColKey; label: string; alwaysVisible?: boolean; filter?: 'multi' | 'text' | 'min' | 'due' }> = [
  { key: 'findingId', label: 'Finding ID', alwaysVisible: true, filter: 'text' },
  { key: 'cveId', label: 'CVE ID', alwaysVisible: true, filter: 'text' },
  { key: 'asset', label: 'Asset', filter: 'text' },
  { key: 'owner', label: 'Owner', filter: 'text' },
  { key: 'supportGroup', label: 'Support Group', filter: 'text' },
  { key: 'package', label: 'Package', filter: 'text' },
  { key: 'severity', label: 'Severity', filter: 'multi' },
  { key: 'status', label: 'Status', filter: 'multi' },
  { key: 'creationSource', label: 'Created By', filter: 'multi' },
  { key: 'risk', label: 'Risk', filter: 'min' },
  { key: 'priority', label: 'S.AI Priority' },
  { key: 'ownerGroup', label: 'Owner Group' },
  { key: 'assignedTo', label: 'Assigned To', filter: 'text' },
  { key: 'dueDate', label: 'Due Date', filter: 'due' },
  { key: 'incidentId', label: 'Incident ID', filter: 'text' },
  { key: 'incidentStatus', label: 'Inc. Status' },
  { key: 'suppressionRule', label: 'Suppression Rule' },
  { key: 'firstObserved', label: 'First Observed' },
  { key: 'lastObserved', label: 'Last Observed' },
];
const DEFAULT_VISIBLE = new Set<ColKey>(['findingId', 'cveId', 'asset', 'owner', 'supportGroup', 'package', 'severity', 'status', 'creationSource', 'risk', 'priority', 'ownerGroup', 'assignedTo', 'dueDate', 'incidentId']);
const GROUP_OPTIONS = [
  { key: 'severity', label: 'Severity' }, { key: 'status', label: 'Status' }, { key: 'owner', label: 'Owner' },
  { key: 'asset', label: 'Asset' }, { key: 'package', label: 'Package' }, { key: 'cve', label: 'Vulnerability ID' },
] as const;
type GroupKey = typeof GROUP_OPTIONS[number]['key'];
const MULTI_VALUES: Record<'severity' | 'status' | 'creationSource', string[]> = {
  severity: ['critical', 'high', 'medium', 'low'],
  status: ['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'],
  creationSource: ['MANUAL', 'AUTOMATIC'],
};
const PAGE_SIZE = 25;
type Action = 'create-incident' | 'defer' | 'false-positive' | 'duplicate' | 'assign' | 'delete' | 'resolve';
const ACTION_TITLE: Record<Action, string> = {
  'create-incident': 'Create Incident', defer: 'Defer Findings', 'false-positive': 'Mark False Positive', duplicate: 'Mark Duplicate', assign: 'Assign Findings', delete: 'Delete Findings', resolve: 'Resolve Findings',
};

const groupValue = (f: MockFinding, key: GroupKey) => (key === 'cve' ? f.cve : key === 'owner' ? f.owner ?? 'Unassigned' : key === 'status' ? STATUS_LABEL[f.status] : String(f[key]));
const SEV_TONE: Record<Severity, string> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };

function DueCell({ days }: { days: number | null }) {
  if (days === null) return <span className="dp-muted">No SLA</span>;
  if (days < 0) return <span className="dp-sla breached">{Math.abs(days)}d overdue</span>;
  if (days <= 7) return <span className="dp-sla soon">in {days}d</span>;
  return <span className="dp-sla">in {days}d</span>;
}

function HBar({ items, onPick }: { items: Array<{ label: string; value: number; tone: string; active?: boolean }>; onPick: (label: string) => void }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="dp-hbars">
      {items.map((item) => (
        <button key={item.label} type="button" className={`dp-hbar${item.active ? ' active' : ''}`} onClick={() => onPick(item.label)}>
          <span className="dp-hbar-label" title={item.label}>{item.label}</span>
          <span className="dp-hbar-track"><span className={`dp-fill--${item.tone}`} style={{ width: `${(item.value / max) * 100}%` }} /></span>
          <span className="dp-hbar-val">{item.value}</span>
        </button>
      ))}
    </div>
  );
}

export function FindingsPage({ onNavigate }: { onNavigate: (route: string) => void }) {
  const { loading } = usePreview();
  const { canTriage } = useCapabilities();
  const [filters, setFilters] = React.useState<Record<string, string | string[]>>({});
  const [groupBy, setGroupBy] = React.useState<GroupKey | ''>('');
  const [groupFilter, setGroupFilter] = React.useState<{ field: GroupKey; value: string } | null>(null);
  const [unassignedOnly, setUnassignedOnly] = React.useState(false);
  const [incidentLinked, setIncidentLinked] = React.useState(false);
  const [dueBand, setDueBand] = React.useState<string | null>(null);
  const [visible, setVisible] = React.useState<Set<ColKey>>(() => { try { const saved = JSON.parse(localStorage.getItem('findings-col-vis-v2') ?? 'null'); return Array.isArray(saved) ? new Set([...saved, 'findingId', 'cveId']) : new Set(DEFAULT_VISIBLE); } catch { return new Set(DEFAULT_VISIBLE); } });
  React.useEffect(() => { localStorage.setItem('findings-col-vis-v2', JSON.stringify([...visible])); }, [visible]);
  const [widths, setWidths] = React.useState<Partial<Record<ColKey, number>>>({});
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [page, setPage] = React.useState(0);
  const [action, setAction] = React.useState<Action | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [queue, setQueue] = React.useState<{ title: string; isDefault: boolean } | null>(null);
  const [queueDialog, setQueueDialog] = React.useState(false);
  const [queueTitle, setQueueTitle] = React.useState('');

  const multi = (k: string) => (filters[k] as string[] | undefined) ?? [];
  const text = (k: string) => (filters[k] as string | undefined) ?? '';
  const setFilter = (k: string, v: string | string[]) => { setFilters((p) => ({ ...p, [k]: v })); setPage(0); };

  const rows = FINDINGS.filter((f) =>
    (!text('findingId') || f.id.toLowerCase().includes(text('findingId').toLowerCase()))
    && (!text('supportGroup') || (f.supportGroup ?? '').toLowerCase().includes(text('supportGroup').toLowerCase()))
    && (!text('assignedTo') || (f.assignedTo ?? '').toLowerCase().includes(text('assignedTo').toLowerCase()))
    && (!text('incidentId') || (f.incidentId ?? '').toLowerCase().includes(text('incidentId').toLowerCase()))
    && (!unassignedOnly || !f.assignedTo)
    && (!incidentLinked || !!f.incidentId)
    &&
    (multi('severity').length === 0 || multi('severity').includes(f.severity))
    && (multi('status').length === 0 || multi('status').includes(f.status))
    && (multi('creationSource').length === 0 || multi('creationSource').includes(f.creationSource))
    && (!text('cveId') || f.cve.toLowerCase().includes(text('cveId').toLowerCase()))
    && (!text('asset') || f.asset.toLowerCase().includes(text('asset').toLowerCase()))
    && (!text('package') || f.package.toLowerCase().includes(text('package').toLowerCase()))
    && (!text('owner') || (f.owner ?? '').toLowerCase().includes(text('owner').toLowerCase()))
    && (!text('risk') || f.risk >= Number(text('risk')))
    && (!groupFilter || groupValue(f, groupFilter.field) === groupFilter.value)
    && (!dueBand || (f.status === 'OPEN' && (dueBand === 'Overdue' ? (f.dueInDays ?? 1) < 0 : dueBand === 'Due in 7 days' ? f.dueInDays !== null && f.dueInDays >= 0 && f.dueInDays < 7 : dueBand === 'No SLA Set' ? f.dueInDays === null : (f.dueInDays ?? -1) >= 7))));
  const pageCount = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const cols = ALL_COLUMNS.filter((c) => visible.has(c.key));
  const hasSelection = selected.size > 0;
  const allSelected = pageRows.length > 0 && pageRows.every((r) => selected.has(r.id));

  const chips: Array<{ label: string; onRemove: () => void }> = [];
  if (groupFilter) chips.push({ label: `${GROUP_OPTIONS.find((g) => g.key === groupFilter.field)?.label}: ${groupFilter.value}`, onRemove: () => setGroupFilter(null) });
  (['severity', 'status', 'creationSource'] as const).forEach((k) => {
    if (multi(k).length) chips.push({ label: `${ALL_COLUMNS.find((c) => c.key === k)?.label}: ${multi(k).map((v) => STATUS_LABEL[v as FindingStatus] ?? v).join(', ')}`, onRemove: () => setFilter(k, []) });
  });
  (['cveId', 'asset', 'package', 'owner', 'supportGroup', 'assignedTo', 'risk'] as const).forEach((k) => {
    if (text(k)) chips.push({ label: `${k === 'cveId' ? 'CVE' : ALL_COLUMNS.find((c) => c.key === k)?.label}: ${text(k)}`, onRemove: () => setFilter(k, '') });
  });
  if (dueBand) chips.push({ label: `SLA: ${dueBand}`, onRemove: () => setDueBand(null) });
  if (unassignedOnly) chips.push({ label: 'Unassigned remediation', onRemove: () => setUnassignedOnly(false) });
  if (incidentLinked) chips.push({ label: 'Linked incident', onRemove: () => setIncidentLinked(false) });
  const clearAll = () => { setUnassignedOnly(false); setIncidentLinked(false); setFilters({}); setGroupFilter(null); setDueBand(null); setPage(0); };

  const count = (pred: (f: MockFinding) => boolean) => FINDINGS.filter(pred).length;
  const sevCounts = MULTI_VALUES.severity.map((s) => ({ label: s, value: count((f) => f.severity === s), tone: SEV_TONE[s as Severity] }));
  const sevTotal = sevCounts.reduce((a, b) => a + b.value, 0);

  const startResize = (key: ColKey, event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    const th = (event.currentTarget as HTMLElement).parentElement as HTMLElement;
    const startX = event.clientX;
    const startW = th.getBoundingClientRect().width;
    const move = (e: MouseEvent) => setWidths((w) => ({ ...w, [key]: Math.max(72, startW + e.clientX - startX) }));
    const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };

  const cell = (f: MockFinding, key: ColKey): React.ReactNode => {
    switch (key) {
      case 'findingId': return <a className="dp-id-link dp-mono" href={`#/findings/${f.id}`} onClick={(e) => e.stopPropagation()}>{f.id}</a>;
      case 'cveId': return (
        <span className="dp-cell-title">
          <button type="button" className="dp-link dp-mono" onClick={(e) => { e.stopPropagation(); onNavigate(`/vuln-repo/org-cves/${f.cve}`); }}>{f.cve}</button>
          {f.kev ? <Badge tone="critical">KEV</Badge> : null}
        </span>
      );
      case 'asset': return <span className="dp-mono">{f.asset}</span>;
      case 'owner': return f.owner ?? <span className="dp-muted">—</span>;
      case 'supportGroup': return f.supportGroup ?? <span className="dp-muted">—</span>;
      case 'package': return <span className="dp-mono">{f.package}</span>;
      case 'severity': return <SeverityBadge severity={f.severity} />;
      case 'status': return <StatusBadge status={f.status} />;
      case 'creationSource': return <span className="dp-muted">{f.creationSource === 'AUTOMATIC' ? 'Automatic' : 'Manual'}</span>;
      case 'risk': return <span className="dp-num">{f.risk.toFixed(1)}</span>;
      case 'priority': return <Meter value={f.priority} />;
      case 'ownerGroup': return f.ownerGroup ?? <span className="dp-muted">—</span>;
      case 'assignedTo': return f.assignedTo ?? <span className="dp-muted">Unassigned</span>;
      case 'dueDate': return <DueCell days={f.dueInDays} />;
      case 'incidentId': return f.incidentId ? <span className="dp-mono">{f.incidentId}</span> : <span className="dp-muted">—</span>;
      case 'incidentStatus': return f.incidentStatus ?? <span className="dp-muted">—</span>;
      case 'suppressionRule': return f.suppressionRule ?? <span className="dp-muted">—</span>;
      case 'firstObserved': return <span className="dp-muted dp-num">{f.firstObserved}</span>;
      case 'lastObserved': return <span className="dp-muted dp-num">{f.lastObserved}</span>;
    }
  };

  const groupCards = groupBy ? [{
    key: groupBy,
    label: GROUP_OPTIONS.find((g) => g.key === groupBy)?.label ?? groupBy,
    items: Object.entries(FINDINGS.reduce<Record<string, number>>((acc, f) => { const v = groupValue(f, groupBy); acc[v] = (acc[v] ?? 0) + 1; return acc; }, {}))
      .sort((a, b) => b[1] - a[1]).slice(0, 8),
  }] : [];

  const confirmAction = () => {
    setNotice(`${ACTION_TITLE[action as Action]}: ${selected.size} finding${selected.size === 1 ? '' : 's'} updated.`);
    setAction(null);
    setSelected(new Set());
  };

  return (
    <div className="dp-page">
      <FindingsFamilyNav active="vulnerability" onNavigate={onNavigate} />
      <PageHeader title="Findings" meta={<FreshnessStatus updatedAt="Oct 24, 2026, 10:46 AM" refreshLabel="Refreshing findings while keeping current results visible…" />} />
      {notice ? <Alert tone="success" role="status" action={<button type="button" className="dp-link" onClick={() => setNotice(null)}>Dismiss</button>}>{notice}</Alert> : null}

      <div className="dp-toolbar dp-toolbar--bare">
        <label className="dp-inline-select">
          <span>Group by</span>
          <Select value={groupBy} onChange={(e) => { setGroupBy(e.target.value as GroupKey | ''); setGroupFilter(null); }} aria-label="Group by">
            <option value="">None</option>
            {GROUP_OPTIONS.map((g) => <option key={g.key} value={g.key}>{g.label}</option>)}
          </Select>
        </label>
        {chips.length ? (
          <div className="dp-chip-row">
            {chips.map((chip) => (
              <span key={chip.label} className="dp-filter-chip">{chip.label}<button type="button" onClick={chip.onRemove} aria-label="Remove filter">×</button></span>
            ))}
            {chips.length > 1 ? <button type="button" className="dp-link" onClick={clearAll}>Clear all</button> : null}
          </div>
        ) : null}
        <div className="dp-toolbar-right">
          {queue ? (
            <>
              <button type="button" className="dp-btn dp-btn--sm" onClick={() => { setQueueTitle(queue.title); setQueueDialog(true); }}>Edit Queue</button>
              <button type="button" className="dp-btn dp-btn--sm" onClick={() => setNotice(`Duplicated queue "${queue.title}".`)}>Duplicate Queue</button>
              {!queue.isDefault ? <button type="button" className="dp-btn dp-btn--sm" onClick={() => setQueue({ ...queue, isDefault: true })}>Set Default</button> : null}
              <button type="button" className="dp-btn dp-btn--sm" onClick={() => setQueue(null)}>Delete Queue</button>
            </>
          ) : null}
          <button type="button" className="dp-btn dp-btn--sm" onClick={() => { setQueueTitle(''); setQueueDialog(true); }}>Save Current View</button>
        </div>
      </div>

      {loading ? (
        <div className="dp-widgets">{Array.from({ length: 5 }, (_, i) => <div key={i} className="dp-widget"><Skeleton width="50%" /><Skeleton height={90} radius={8} /></div>)}</div>
      ) : (
        <div className="dp-widgets">
          <div className={`dp-widget${multi('severity').length ? ' active' : ''}`}>
            <div className="dp-widget-title">Exposure by Severity</div>
            <div className="dp-widget-donut">
              <div className="dp-mini-donut" style={{ background: `conic-gradient(${sevCounts.reduce<{ acc: string[]; at: number }>((st, s) => { const end = st.at + (s.value / sevTotal) * 100; st.acc.push(`var(--dp-${s.tone}) ${st.at}% ${end}%`); return { acc: st.acc, at: end }; }, { acc: [], at: 0 }).acc.join(', ')})` }}><span>{sevTotal}</span></div>
              <div className="dp-legend-compact">
                {sevCounts.map((s) => (
                  <button key={s.label} type="button" className={multi('severity').includes(s.label) ? 'active' : ''} onClick={() => { setFilters(p => ({ ...p, severity: multi('severity').length === 1 && multi('severity')[0] === s.label ? [] : [s.label], status: [] })); setDueBand(null); setPage(0); }}>
                    <span className={`dp-swatch dp-swatch--${s.tone}`} />{s.label.toUpperCase()}<strong>{s.value}</strong>
                  </button>
                ))}
              </div>
            </div>
          </div>
          <div className={`dp-widget${multi('status').length ? ' active' : ''}`}>
            <div className="dp-widget-title">Findings by Status</div>
            <HBar
              items={MULTI_VALUES.status.map((s) => ({ label: STATUS_LABEL[s as FindingStatus], value: count((f) => f.status === s), tone: s === 'OPEN' ? 'accent' : s === 'RESOLVED' ? 'success' : 'neutral', active: multi('status').includes(s) }))}
              onPick={(label) => { const value = Object.entries(STATUS_LABEL).find(([, l]) => l === label)?.[0] ?? label; setFilters(p => ({ ...p, status: multi('status').length === 1 && multi('status')[0] === value ? [] : [value], severity: [] })); setDueBand(null); setPage(0); }}
            />
          </div>
          <div className={`dp-widget${text('asset') ? ' active' : ''}`}>
            <div className="dp-widget-title">Top Assets at Risk</div>
            <HBar items={['prod-api-gw-01', 'payments-svc:3.14.2', 'billing-core', 'vpn-edge-02'].map((a) => ({ label: a, value: count((f) => f.asset === a), tone: 'high', active: text('asset') === a }))} onPick={(label) => { setFilter('asset', text('asset') === label ? '' : label); setDueBand(null); }} />
          </div>
          <div className={`dp-widget${dueBand ? ' active' : ''}`}>
            <div className="dp-widget-title">SLA &amp; Due Date</div>
            <HBar
              items={[
                { label: 'Overdue', value: count((f) => (f.dueInDays ?? 1) < 0), tone: 'critical', active: dueBand === 'Overdue' },
                { label: 'Due in 7 days', value: count((f) => f.dueInDays !== null && f.dueInDays >= 0 && f.dueInDays < 7), tone: 'high', active: dueBand === 'Due in 7 days' },
                { label: 'On Track', value: count((f) => (f.dueInDays ?? -1) >= 7), tone: 'success', active: dueBand === 'On Track' },
                { label: 'No SLA Set', value: count((f) => f.dueInDays === null), tone: 'neutral', active: dueBand === 'No SLA Set' },
              ]}
              onPick={(label) => { setDueBand(current => current === label ? null : label); setPage(0); }}
            />
          </div>
          <div className="dp-widget">
            <div className="dp-widget-title">Key Indicators</div>
            <div className="dp-mini-kpis">
              {[
                { label: 'Critical Open', value: count((f) => f.severity === 'critical' && f.status === 'OPEN'), tone: 'critical', run: () => setFilters({ severity: ['critical'], status: ['OPEN'] }) },
                { label: 'Unassigned remediation', value: count((f) => !f.owner), tone: 'high', run: () => { clearAll(); setFilters({ status: ['OPEN'] }); setUnassignedOnly(true); } },
                { label: 'With Incidents', value: count((f) => !!f.incidentId), tone: 'accent', run: () => { clearAll(); setIncidentLinked(true); } },
                { label: 'Overdue', value: count((f) => (f.dueInDays ?? 1) < 0), tone: 'critical', run: () => setDueBand('Overdue') },
              ].map((k) => (
                <button key={k.label} type="button" className={`dp-mini-kpi dp-mini-kpi--${k.tone}`} onClick={k.run}>
                  <strong>{k.value}</strong><span>{k.label}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {groupCards.map((g) => (
        <div key={g.key} className="dp-group-card">
          <div className="dp-widget-title">{g.label}</div>
          <div className="dp-group-items">
            {g.items.map(([v, c]) => (
              <button key={v} type="button" className="dp-group-item" aria-pressed={groupFilter?.field === g.key && groupFilter.value === v} onClick={() => { clearAll(); setGroupFilter({ field: g.key as GroupKey, value: v }); }}>
                <span>{v}</span><strong>{c}</strong>
              </button>
            ))}
          </div>
        </div>
      ))}

      <div className="dp-table-card">
        <div className="dp-toolbar">
          <button type="button" className="dp-btn dp-btn--primary dp-btn--sm" disabled={!canTriage || !hasSelection} onClick={() => setAction('resolve')}><CheckCircle2 size={14} /> Resolve</button>
          <Popover
            width={220}
            trigger={({ open, toggle }) => (
              <button type="button" className={`dp-btn dp-btn--sm${open ? ' dp-btn--active' : ''}`} onClick={toggle} title="More actions" aria-expanded={open}>More <ChevronDown size={13} /></button>
            )}
          >
            {(close) => (
              <Menu items={[
                { label: '+ Create Incident', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('create-incident'); } },
                { label: 'Defer', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('defer'); } },
                { label: 'False Positive', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('false-positive'); } },
                { label: 'Duplicate', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('duplicate'); } },
                { label: 'Assign to…', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('assign'); } },
                'separator',
                { label: 'Re-open', disabled: !canTriage || !hasSelection, onSelect: () => { close(); setNotice(`Re-opened ${selected.size} findings.`); } },
                { label: 'Delete', danger: true, disabled: !canTriage || !hasSelection, onSelect: () => { close(); setAction('delete'); } },
              ]} />
            )}
          </Popover>
          {hasSelection ? <span className="dp-selection-count">{selected.size} selected <button type="button" className="dp-link" onClick={() => setSelected(new Set())}>Clear</button></span> : null}
          <div className="dp-toolbar-right">
            <Popover
              align="right"
              width={240}
              trigger={({ toggle }) => <button type="button" className="dp-btn dp-btn--sm" onClick={toggle} title="Column settings"><Columns3 size={14} /> Columns</button>}
            >
              {() => (
                <div>
                  <div className="dp-menu-label dp-row-between"><span>VISIBLE COLUMNS</span><button type="button" className="dp-link" onClick={() => setVisible(new Set(DEFAULT_VISIBLE))}>Reset</button></div>
                  <div className="dp-colvis-list">
                    {ALL_COLUMNS.map((c) => (
                      <label key={c.key} className={`dp-check-row${c.alwaysVisible ? ' locked' : ''}`}>
                        <input type="checkbox" disabled={c.alwaysVisible} checked={visible.has(c.key)} onChange={() => setVisible((v) => { const n = new Set(v); if (n.has(c.key)) n.delete(c.key); else n.add(c.key); return n; })} />
                        {c.label}
                        {c.alwaysVisible ? <Lock size={11} className="dp-ml-auto dp-muted" /> : null}
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </Popover>
          </div>
        </div>

        <div className="dp-table-scroll">
          <table className="dp-table dp-table--resizable">
            <thead>
              <tr>
                <th className="dp-th-check dp-sticky-col">
                  <input type="checkbox" aria-label="Select all" checked={allSelected}
                    ref={(el) => { if (el) el.indeterminate = hasSelection && !allSelected; }}
                    onChange={() => setSelected((s) => { const n = new Set(s); pageRows.forEach((r) => (allSelected ? n.delete(r.id) : n.add(r.id))); return n; })} />
                </th>
                {cols.map((c) => {
                  const active = c.filter === 'multi' ? multi(c.key).length > 0 : c.filter === 'due' ? !!dueBand : !!text(c.key);
                  return (
                    <th key={c.key} className={`${c.key === 'findingId' ? 'dp-sticky-col dp-sticky-col--2' : ''}${active ? ' filtered' : ''}`} style={widths[c.key] ? { width: widths[c.key], minWidth: widths[c.key] } : undefined}>
                      <span className="dp-th-inner">
                        {c.label}
                        {c.key === 'priority' ? (
                          <Tooltip content="Scout AI-computed priority score (0–10) based on exploitability, SLA proximity, EOL risk, and blast radius"><span className="dp-th-info" tabIndex={0}><Info size={12} /></span></Tooltip>
                        ) : null}
                        {c.filter ? (
                          <Popover
                            width={220}
                            trigger={({ toggle }) => <button type="button" className={`dp-th-filter${active ? ' active' : ''}`} onClick={toggle} title={`Filter ${c.label}`}><Filter size={11} /></button>}
                          >
                            {(close) => (
                              <div className="dp-col-filter">
                                {c.filter === 'due' ? ['Overdue', 'Due in 7 days', 'On Track', 'No SLA Set'].map(band => <label key={band} className="dp-check-row"><input type="radio" name="due-band" checked={dueBand === band} onChange={() => { setDueBand(band); setPage(0); }} />{band}</label>) : c.filter === 'multi' ? MULTI_VALUES[c.key as 'severity' | 'status' | 'creationSource'].map((v) => (
                                  <label key={v} className="dp-check-row">
                                    <input type="checkbox" checked={multi(c.key).includes(v)} onChange={() => setFilter(c.key, multi(c.key).includes(v) ? multi(c.key).filter((x) => x !== v) : [...multi(c.key), v])} />
                                    {STATUS_LABEL[v as FindingStatus] ?? v}
                                  </label>
                                )) : (
                                  <TextInput
                                    autoFocus
                                    type={c.filter === 'min' ? 'number' : 'text'}
                                    placeholder={c.filter === 'min' ? 'Min risk score' : `Search ${c.label}…`}
                                    value={text(c.key)}
                                    onChange={(e) => setFilter(c.key, e.target.value)}
                                  />
                                )}
                                <button type="button" className="dp-link" onClick={() => { if (c.filter === 'due') setDueBand(null); else setFilter(c.key, c.filter === 'multi' ? [] : ''); close(); }}>Clear filter</button>
                              </div>
                            )}
                          </Popover>
                        ) : null}
                      </span>
                      <span className="dp-resize-handle" onMouseDown={(e) => startResize(c.key, e)} aria-hidden="true" />
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {loading ? Array.from({ length: 8 }, (_, i) => (
                <tr key={i} className="dp-row-loading">{[0, ...cols].map((_, j) => <td key={j}><Skeleton width={j === 0 ? 14 : `${50 + ((i * 7 + j * 13) % 45)}%`} /></td>)}</tr>
              )) : pageRows.length === 0 ? (
                <tr><td colSpan={cols.length + 1}>
                  {chips.length === 0 ? (
                    <EmptyState icon={<Inbox size={18} />} title="No findings yet" action={<button type="button" className="dp-btn dp-btn--sm" onClick={() => onNavigate('/connect')}>Configure Sources</button>}>
                      Findings are generated when ingested vulnerabilities are correlated with your software inventory.
                    </EmptyState>
                  ) : (
                    <EmptyState icon={<Filter size={18} />} title="No findings matched the current filters." action={<button type="button" className="dp-btn dp-btn--sm" onClick={clearAll}>Clear filters</button>} />
                  )}
                </td></tr>
              ) : pageRows.map((f) => (
                <tr key={f.id} className={selected.has(f.id) ? 'selected' : ''} onClick={() => setSelected((s) => { const n = new Set(s); if (n.has(f.id)) n.delete(f.id); else n.add(f.id); return n; })}>
                  <td className="dp-th-check dp-sticky-col" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" aria-label="Select row" checked={selected.has(f.id)} onChange={() => setSelected((s) => { const n = new Set(s); if (n.has(f.id)) n.delete(f.id); else n.add(f.id); return n; })} />
                  </td>
                  {cols.map((c) => <td key={c.key} className={c.key === 'findingId' ? 'dp-sticky-col dp-sticky-col--2' : ''}>{cell(f, c.key)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="dp-pagination">
          <button type="button" className="dp-btn dp-btn--sm" disabled={page <= 0} onClick={() => setPage(page - 1)}>← Prev</button>
          <span className="dp-muted dp-num">{rows.length === 0 ? 'No results' : `Page ${page + 1} of ${pageCount} · ${rows.length.toLocaleString()} findings`}</span>
          <button type="button" className="dp-btn dp-btn--sm" disabled={page >= pageCount - 1} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      </div>

      <Modal
        open={action !== null}
        onClose={() => setAction(null)}
        title={action ? ACTION_TITLE[action] : ''}
        description={`${selected.size} selected finding${selected.size === 1 ? '' : 's'}`}
        footer={(
          <>
            <button type="button" className="dp-btn" onClick={() => setAction(null)}>Cancel</button>
            {action === 'delete'
              ? <button type="button" className="dp-btn dp-btn--danger" onClick={confirmAction}>Delete</button>
              : <button type="button" className="dp-btn dp-btn--primary" onClick={confirmAction}>Confirm</button>}
          </>
        )}
      >
        {action === 'create-incident' ? (
          <div className="dp-form">
            <Field label="Priority" htmlFor="inc-priority"><Select id="inc-priority" defaultValue="2"><option value="1">1 - Critical</option><option value="2">2 - High</option><option value="3">3 - Moderate</option><option value="4">4 - Low</option></Select></Field>
            <Field label="Assigned To" htmlFor="inc-assigned"><TextInput id="inc-assigned" /></Field>
            <Field label="Assignment Group" htmlFor="inc-group"><TextInput id="inc-group" /></Field>
            <Field label="Notes" htmlFor="inc-notes"><Textarea id="inc-notes" rows={3} /></Field>
          </div>
        ) : action === 'defer' ? (
          <div className="dp-form">
            <Field label="Reason" htmlFor="defer-reason"><Select id="defer-reason"><option>Awaiting vendor fix</option><option>Maintenance window</option><option>Compensating control</option></Select></Field>
            <Field label="Defer until" htmlFor="defer-until"><TextInput id="defer-until" type="date" /></Field>
          </div>
        ) : action === 'false-positive' ? (
          <Field label="Justification" htmlFor="fp-just"><Textarea id="fp-just" rows={3} /></Field>
        ) : action === 'duplicate' ? (
          <Field label="Duplicate Of" htmlFor="dup-of"><TextInput id="dup-of" className="dp-mono" /></Field>
        ) : action === 'assign' ? (
          <Field label="Assignment Group" htmlFor="assign-group"><Select id="assign-group"><option>Payments Platform</option><option>Core Infra</option><option>Identity</option></Select></Field>
        ) : action === 'delete' ? (
          <Alert tone="danger" title="This permanently deletes the selected findings.">They will be re-created only if the underlying correlation is detected again.</Alert>
        ) : (
          <p className="dp-muted">The selected findings will be marked resolved.</p>
        )}
      </Modal>

      <Modal
        open={queueDialog}
        onClose={() => setQueueDialog(false)}
        title={queue && queueTitle === queue.title ? 'Edit Queue' : 'Save Current View'}
        footer={(
          <>
            <button type="button" className="dp-btn" onClick={() => setQueueDialog(false)}>Cancel</button>
            <button type="button" className="dp-btn dp-btn--primary" disabled={queueTitle.trim().length === 0} onClick={() => { setQueue({ title: queueTitle.trim(), isDefault: false }); setQueueDialog(false); setNotice(`Saved queue "${queueTitle.trim()}".`); }}>Save</button>
          </>
        )}
      >
        <div className="dp-form">
          <Field label="Title" htmlFor="queue-title"><TextInput id="queue-title" value={queueTitle} onChange={(e) => setQueueTitle(e.target.value)} placeholder="Queue title" /></Field>
          <Field label="Description" htmlFor="queue-desc"><Textarea id="queue-desc" rows={3} placeholder="Optional description" /></Field>
        </div>
      </Modal>
    </div>
  );
}
