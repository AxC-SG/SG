import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type ApplicationRiskSummary, type BomComponentSummaryItem } from '../../api/client';
import { FindingSeverityChips } from '../findings/components/FindingSeverityChips';
import { BomComponentDetailPanel } from './BomComponentDetailPanel';
import { ApplicationDetailPanel } from './ApplicationDetailPanel';

const PAGE_SIZE = 100;

function bomLabel(type: string): string {
  return type === 'AI_BOM' ? 'AI BOM' : type;
}

function BomTypeTag({ type }: { type: string }) {
  const colors: Record<string, string> = {
    SBOM: '#2563eb', AI_BOM: '#0891b2', CBOM: '#7c3aed', VENDOR: '#059669', UNMAPPED: '#d88f3d',
  };
  const color = colors[type] ?? 'var(--muted)';
  return (
    <span style={{
      display: 'inline-flex', padding: '2px 7px', borderRadius: 999,
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em',
      color, background: `color-mix(in srgb, ${color} 12%, transparent)`,
      border: `1px solid ${color}40`,
    }}>
      {type === 'UNMAPPED' ? 'Unmapped' : bomLabel(type)}
    </span>
  );
}

function RiskPill({ level }: { level: string }) {
  const map: Record<string, string> = {
    CRITICAL: 'status-pill status-failure',
    HIGH:     'status-pill status-warning',
    MEDIUM:   'status-pill status-unknown',
    LOW:      'status-pill status-open',
    NONE:     'status-pill status-suppressed',
  };
  return <span className={map[level] ?? 'status-pill'}>{level}</span>;
}

function CorrelationPill({ state }: { state: BomComponentSummaryItem['correlationState'] }) {
  const map: Record<string, string> = {
    APPLICABLE:     'status-pill inv-status-applicable',
    NOT_APPLICABLE: 'status-pill status-suppressed',
    UNKNOWN:        'status-pill status-unknown',
    UNCHECKED:      'status-pill status-auto_closed',
  };
  const label: Record<string, string> = {
    APPLICABLE:     'APPLICABLE',
    NOT_APPLICABLE: 'NOT APPLICABLE',
    UNKNOWN:        'UNKNOWN',
    UNCHECKED:      'UNCHECKED',
  };
  return <span className={map[state] ?? 'status-pill'}>{label[state] ?? state}</span>;
}

/**
 * What BOM evidence says about the component's presence, which is distinct from its
 * ACTIVE/RETIRED status. CONFLICTING is the one that needs a person: one source asserted the
 * component is gone while another still reports it, and the system deliberately refuses to
 * pick a winner. WITHDRAWN means no source vouches for it any more -- presence unknown, not
 * disproved. LEGACY_UNKNOWN covers components predating contribution tracking.
 */
function EvidencePill({ state }: { state: BomComponentSummaryItem['bomEvidenceState'] }) {
  if (!state) return <span style={{ color: 'var(--muted)' }}>—</span>;
  const map: Record<string, string> = {
    SUPPORTED:      'status-pill inv-status-applicable',
    CONFLICTING:    'status-pill status-unknown',
    WITHDRAWN:      'status-pill status-suppressed',
    LEGACY_UNKNOWN: 'status-pill status-auto_closed',
  };
  const label: Record<string, string> = {
    SUPPORTED:      'SUPPORTED',
    CONFLICTING:    'CONFLICTING',
    WITHDRAWN:      'WITHDRAWN',
    LEGACY_UNKNOWN: 'UNKNOWN',
  };
  const title: Record<string, string> = {
    SUPPORTED:      'At least one BOM source currently reports this component.',
    CONFLICTING:    'One source asserted this component is absent while another still reports it. Needs review.',
    WITHDRAWN:      'No source vouches for this component any more. Its presence is unknown, not disproved.',
    LEGACY_UNKNOWN: 'Ingested before per-source evidence was tracked, so presence cannot be attributed.',
  };
  return <span className={map[state] ?? 'status-pill'} title={title[state] ?? ''}>{label[state] ?? state}</span>;
}

type WidgetFilter = 'all' | 'bom_mapped' | 'unmapped' | 'vulnerable' | 'eol' | 'ai_bom' | 'cbom';

function WidgetRow({
  items,
  activeFilter,
  onFilter,
}: {
  items: BomComponentSummaryItem[];
  activeFilter: WidgetFilter;
  onFilter: (f: WidgetFilter) => void;
}) {
  const vulnerable = items.filter((c) => c.totalCveCount > 0).length;
  const eol = items.filter((c) => c.isEol).length;
  const bomMapped = items.filter((c) => c.bomTypes.length > 0).length;
  const unmapped = items.length - bomMapped;
  const aiBom = items.filter((c) => c.bomTypes.includes('AI_BOM')).length;
  const cbom = items.filter((c) => c.bomTypes.includes('CBOM')).length;
  const licenses = new Set(items.map((c) => c.license).filter(Boolean)).size;
  const apps = new Set(items.map((c) => c.assetName)).size;

  const stats: { key: WidgetFilter; label: string; value: React.ReactNode; sub: string; color: string; clickable: boolean }[] = [
    { key: 'all',        label: 'Inventory Components', value: items.length.toLocaleString(), sub: `across ${apps} applications`,                                       color: 'var(--title)', clickable: true },
    { key: 'bom_mapped', label: 'BOM-mapped Components', value: bomMapped.toLocaleString(),   sub: 'linked to active BOM records',                                      color: '#2563eb', clickable: true },
    { key: 'unmapped',   label: 'Unmapped Inventory',    value: unmapped.toLocaleString(),     sub: 'active rows without BOM type',                                      color: '#d88f3d', clickable: true },
    { key: 'vulnerable', label: 'Vulnerable',            value: vulnerable,                    sub: `${items.filter(c => c.criticalCveCount > 0).length} with critical CVEs`, color: 'var(--critical)', clickable: true },
    { key: 'eol',        label: 'EOL Components',        value: eol,                           sub: 'past end-of-life',                                                  color: '#d88f3d', clickable: true },
    { key: 'ai_bom',     label: 'AI/ML Libraries',       value: aiBom,                         sub: 'from AI BOMs',                                                      color: '#7c3aed', clickable: true },
    { key: 'cbom',       label: 'Crypto Libraries',      value: cbom,                          sub: 'from CBOMs',                                                        color: '#0891b2', clickable: true },
    { key: 'all',        label: 'Licenses',              value: licenses,                       sub: 'unique licenses',                                                   color: 'var(--muted)', clickable: true },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 12, marginBottom: 20 }}>
      {stats.map(({ key, label, value, sub, color, clickable }, idx) => {
        const isActive = activeFilter === key && key !== 'all';
        return (
          <div
            key={`${label}-${idx}`}
            className="panel"
            onClick={clickable ? () => onFilter(activeFilter === key && key !== 'all' ? 'all' : key) : undefined}
            style={{
              padding: '14px 16px', cursor: clickable ? 'pointer' : 'default',
              outline: isActive ? `2px solid ${color}` : 'none',
              outlineOffset: -2,
            }}
          >
            <div className="panel-caption" style={{ marginBottom: 4, fontSize: 11 }}>{label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color }}>{value}</div>
            <div className="panel-caption" style={{ marginTop: 3, fontSize: 11 }}>{sub}</div>
          </div>
        );
      })}
    </div>
  );
}

function EcosystemBreakdown({
  items,
  activeEcosystem,
  onEcosystemFilter,
}: {
  items: BomComponentSummaryItem[];
  activeEcosystem: string;
  onEcosystemFilter: (eco: string) => void;
}) {
  const counts: Record<string, number> = {};
  for (const c of items) {
    const eco = (c.ecosystem ?? 'other').toLowerCase();
    counts[eco] = (counts[eco] ?? 0) + 1;
  }
  const total = items.length || 1;
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="panel" style={{ padding: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <h4 style={{ margin: 0 }}>Ecosystem Breakdown</h4>
      </div>
      {sorted.map(([name, count]) => {
        const pct = Math.round((count / total) * 100);
        const isActive = activeEcosystem === name;
        return (
          <div
            key={name}
            onClick={() => onEcosystemFilter(isActive ? '' : name)}
            style={{
              marginBottom: 10, cursor: 'pointer', borderRadius: 6, padding: '4px 6px',
              background: isActive ? 'color-mix(in srgb, var(--accent) 10%, transparent)' : 'transparent',
              outline: isActive ? '1px solid var(--accent)' : 'none',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ fontWeight: 600, textTransform: 'uppercase', fontSize: 12, color: isActive ? 'var(--accent)' : undefined }}>{name}</span>
              <span className="panel-caption">{count} ({pct}%)</span>
            </div>
            <div style={{ height: 6, borderRadius: 999, background: 'var(--border)', overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: isActive ? 'var(--accent)' : 'var(--accent)', borderRadius: 999, opacity: isActive ? 1 : 0.6 }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function BomTypeBreakdown({
  items,
  activeBomType,
  onBomTypeFilter,
}: {
  items: BomComponentSummaryItem[];
  activeBomType: string;
  onBomTypeFilter: (t: string) => void;
}) {
  const bomTypeDefs = [
    { key: 'SBOM',   label: 'SBOM',   color: '#2563eb' },
    { key: 'AI_BOM', label: 'AI BOM', color: '#0891b2' },
    { key: 'CBOM',   label: 'CBOM',   color: '#7c3aed' },
    { key: 'VENDOR', label: 'Vendor', color: '#059669' },
  ];
  const counts: Record<string, number> = {};
  for (const c of items) {
    for (const t of c.bomTypes) {
      counts[t] = (counts[t] ?? 0) + 1;
    }
  }
  const mappedCount = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const unmappedCount = items.filter((c) => c.bomTypes.length === 0).length;

  return (
    <div className="panel" style={{ padding: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <div>
          <h4 style={{ margin: 0 }}>BOM Type Distribution</h4>
          <span className="panel-caption">
            {mappedCount.toLocaleString()} mapped · {unmappedCount.toLocaleString()} unmapped inventory rows
          </span>
        </div>
      </div>
      {bomTypeDefs.filter((t) => (counts[t.key] ?? 0) > 0).map(({ key, label, color }) => {
        const isActive = activeBomType === key;
        return (
        <div
          key={key}
          onClick={() => onBomTypeFilter(isActive ? '' : key)}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 8px', borderBottom: '1px solid var(--border)',
            cursor: 'pointer', borderRadius: 6,
            background: isActive ? `color-mix(in srgb, ${color} 10%, transparent)` : 'transparent',
            outline: isActive ? `1px solid ${color}40` : 'none',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 12, height: 12, borderRadius: 3, background: color }} />
            <span style={{ fontWeight: 600, fontSize: 13, color: isActive ? color : undefined }}>{label}</span>
          </div>
          <span style={{ fontWeight: 700, fontSize: 16, color: isActive ? color : undefined }}>{counts[key] ?? 0}</span>
        </div>
        );
      })}
      {Object.keys(counts).length === 0 && (
        <span className="panel-caption">No data</span>
      )}
    </div>
  );
}

type BomView = 'list' | 'component-detail' | 'app-detail';

export function BomComponents() {
  const [view, setView] = React.useState<BomView>('list');
  const [selectedComponent, setSelectedComponent] = React.useState<BomComponentSummaryItem | null>(null);
  const [selectedApp, setSelectedApp] = React.useState<ApplicationRiskSummary | null>(null);
  const [query, setQuery] = React.useState('');
  const [ecosystemFilter, setEcosystemFilter] = React.useState('');
  const [riskFilter, setRiskFilter] = React.useState('');
  const [bomTypeFilter, setBomTypeFilter] = React.useState('');
  const [widgetFilter, setWidgetFilter] = React.useState<WidgetFilter>('all');
  const [page, setPage] = React.useState(0);

  const { data, isPending, isError } = useQuery({
    queryKey: ['bom-components'],
    queryFn: async () => {
      const all: BomComponentSummaryItem[] = [];
      const pageSize = 2000;
      for (let page = 0; ; page += 1) {
        const batch = await api.listBomComponents(page, pageSize);
        all.push(...batch);
        if (batch.length < pageSize) return all;
      }
    },
  });

  const items = React.useMemo(() => data ?? [], [data]);

  // Build application count per package name+version
  const appCountMap = React.useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const c of items) {
      const key = `${c.packageName}@${c.version ?? ''}`;
      if (!m.has(key)) m.set(key, new Set());
      m.get(key)!.add(c.assetId);
    }
    return m;
  }, [items]);

  const ecosystems = [...new Set(items.map((c) => (c.ecosystem ?? '').toLowerCase()).filter(Boolean))].sort();

  const filtered = items.filter((c) => {
    if (query && !(c.packageName ?? '').toLowerCase().includes(query.toLowerCase())) return false;
    if (ecosystemFilter && (c.ecosystem ?? '').toLowerCase() !== ecosystemFilter) return false;
    if (riskFilter && c.riskLevel !== riskFilter) return false;
    if (bomTypeFilter && !c.bomTypes.includes(bomTypeFilter)) return false;
    if (widgetFilter === 'bom_mapped' && c.bomTypes.length === 0) return false;
    if (widgetFilter === 'unmapped' && c.bomTypes.length > 0) return false;
    if (widgetFilter === 'vulnerable' && c.totalCveCount === 0) return false;
    if (widgetFilter === 'eol' && !c.isEol) return false;
    if (widgetFilter === 'ai_bom' && !c.bomTypes.includes('AI_BOM')) return false;
    if (widgetFilter === 'cbom' && !c.bomTypes.includes('CBOM')) return false;
    return true;
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const hasFilters = query || ecosystemFilter || riskFilter || bomTypeFilter || widgetFilter !== 'all';

  const resetPage = () => setPage(0);

  if (view === 'app-detail' && selectedApp) {
    return (
      <ApplicationDetailPanel
        app={selectedApp}
        onBack={() => { setSelectedApp(null); setView('component-detail'); }}
      />
    );
  }

  if (view === 'component-detail' && selectedComponent) {
    const packageKey = `${selectedComponent.packageName}@${selectedComponent.version ?? ''}`;
    const relatedAssetIds = [...(appCountMap.get(packageKey) ?? new Set<string>())];
    // Build assetId → componentId map for all instances of this package across apps
    const assetIdToComponentId: Record<string, string> = {};
    for (const c of items) {
      if (c.packageName === selectedComponent.packageName && c.version === selectedComponent.version) {
        assetIdToComponentId[c.assetId] = c.componentId;
      }
    }
    return (
      <BomComponentDetailPanel
        componentId={selectedComponent.componentId}
        seed={selectedComponent}
        relatedAssetIds={relatedAssetIds}
        assetIdToComponentId={assetIdToComponentId}
        onClose={() => { setSelectedComponent(null); setView('list'); }}
        onSelectApp={(app) => { setSelectedApp(app); setView('app-detail'); }}
      />
    );
  }

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading BOM components…</p>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <p style={{ color: 'var(--critical)' }}>Failed to load BOM components.</p>
      </div>
    );
  }

  return (
    <div className="page-grid" style={{ gap: 0 }}>
      <WidgetRow
        items={items}
        activeFilter={widgetFilter}
        onFilter={(f) => {
          // Widget cards are authoritative "jump to this view" actions — clear the secondary
          // facet filters (ecosystem/risk/BOM-type/search) so a stale facet selection can't
          // silently intersect with the widget's filter and make the click look like a no-op.
          setWidgetFilter(f);
          setEcosystemFilter('');
          setRiskFilter('');
          setBomTypeFilter('');
          setQuery('');
          resetPage();
        }}
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        <EcosystemBreakdown
          items={items}
          activeEcosystem={ecosystemFilter}
          onEcosystemFilter={(eco) => { setEcosystemFilter(eco); resetPage(); }}
        />
        <BomTypeBreakdown
          items={items}
          activeBomType={bomTypeFilter}
          onBomTypeFilter={(t) => { setBomTypeFilter(t); resetPage(); }}
        />
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>BOM Components</h3>
            <span className="panel-caption">
              All components across SBOM, CBOM, and AI BOM documents — with correlation and risk status
            </span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10, padding: '0 0 14px', flexWrap: 'wrap' }}>
          <input
            type="text"
            className="filter-input"
            placeholder="Filter component name…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ flex: '1 1 180px', minWidth: 140 }}
          />
          <select className="filter-input" style={{ width: 'auto' }} value={ecosystemFilter}
            onChange={(e) => setEcosystemFilter(e.target.value)}>
            <option value="">All ecosystems</option>
            {ecosystems.map((eco) => (
              <option key={eco} value={eco}>{eco}</option>
            ))}
          </select>
          <select className="filter-input" style={{ width: 'auto' }} value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}>
            <option value="">All risk levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="NONE">None</option>
          </select>
          <select className="filter-input" style={{ width: 'auto' }} value={bomTypeFilter}
            onChange={(e) => setBomTypeFilter(e.target.value)}>
            <option value="">All BOM types</option>
            <option value="SBOM">SBOM</option>
            <option value="AI_BOM">AI BOM</option>
            <option value="CBOM">CBOM</option>
            <option value="VENDOR">Vendor</option>
          </select>
          {hasFilters && (
            <button type="button" className="btn btn-secondary btn-sm"
              onClick={() => { setQuery(''); setEcosystemFilter(''); setRiskFilter(''); setBomTypeFilter(''); setWidgetFilter('all'); resetPage(); }}>
              Clear filters
            </button>
          )}
        </div>

        <div className="panel-caption" style={{ padding: '0 0 8px', fontSize: 11 }}>
          Showing {Math.min(page * PAGE_SIZE + 1, filtered.length)}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length} components
        </div>

        {items.length === 0 ? (
          <div className="empty-state">
            <p>No components found. Ingest a BOM for an APPLICATION asset to see components here.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Version</th>
                  <th>Ecosystem</th>
                  <th>BOM Types</th>
                  <th>Application</th>
                  <th>Risk</th>
                  <th>CVEs</th>
                  <th>Findings</th>
                  <th>Correlation</th>
                  <th>BOM Evidence</th>
                  <th>EOL</th>
                  <th>License</th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((c) => {
                  const appCount = appCountMap.get(`${c.packageName}@${c.version ?? ''}`)?.size ?? 1;
                  return (
                    <tr
                      key={c.componentId}
                      style={{ cursor: 'pointer' }}
                      onClick={() => { setSelectedComponent(c); setView('component-detail'); }}
                    >
                      <td>
                        <div style={{ fontWeight: 600 }}>{c.packageName}</div>
                        {c.purl && <div className="panel-caption mono" style={{ fontSize: 10 }}>{c.purl}</div>}
                      </td>
                      <td className="mono">{c.version ?? '—'}</td>
                      <td>
                        {c.ecosystem
                          ? <span className="status-pill status-auto_closed">{c.ecosystem}</span>
                          : <span className="panel-caption">—</span>}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {c.bomTypes.length > 0
                            ? c.bomTypes.map((t) => <BomTypeTag key={t} type={t} />)
                            : <BomTypeTag type="UNMAPPED" />}
                        </div>
                      </td>
                      <td style={{ fontWeight: 600 }}>{appCount}</td>
                      <td><RiskPill level={c.riskLevel} /></td>
                      <td>
                        {c.totalCveCount > 0
                          ? <span style={{ fontWeight: 600, color: c.criticalCveCount > 0 ? 'var(--critical)' : c.highCveCount > 0 ? 'var(--high)' : 'var(--title)' }}>{c.totalCveCount}</span>
                          : <span className="panel-caption">—</span>}
                      </td>
                      <td>
                        <FindingSeverityChips
                          critical={c.criticalFindingCount}
                          high={c.highFindingCount}
                          other={Math.max(0, c.findingCount - c.criticalFindingCount - c.highFindingCount)}
                        />
                      </td>
                      <td><CorrelationPill state={c.correlationState} /></td>
                      <td><EvidencePill state={c.bomEvidenceState} /></td>
                      <td>
                        {c.isEol ? (
                          <div>
                            <span className="status-pill status-failure">EOL</span>
                            {c.eolDate && <div className="panel-caption" style={{ fontSize: 10 }}>{c.eolDate}</div>}
                          </div>
                        ) : <span className="panel-caption">—</span>}
                      </td>
                      <td>{c.license ?? '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {filtered.length === 0 && items.length > 0 && (
          <div className="empty-state"><p>No components match the current filters.</p></div>
        )}

        {totalPages > 1 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 16, borderTop: '1px solid var(--border)' }}>
            <span className="panel-caption" style={{ fontSize: 12 }}>
              Page {page + 1} of {totalPages}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page === 0}
                onClick={() => setPage(p => p - 1)}
              >
                ← Prev
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={page >= totalPages - 1}
                onClick={() => setPage(p => p + 1)}
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
