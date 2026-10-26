import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type ApplicationRiskSummary } from '../../api/client';
import { timeAgo } from '../../lib/time';
import { ApplicationDetailPanel } from './ApplicationDetailPanel';

// ── Shared helpers ────────────────────────────────────────────────────────────

function bomLabel(type: string): string {
  return type === 'AI_BOM' ? 'AI BOM' : type;
}

function BomTypeBadge({ type }: { type: string }) {
  const colorMap: Record<string, { color: string; bg: string }> = {
    SBOM:   { color: '#2563eb', bg: 'color-mix(in srgb, #2563eb 12%, transparent)' },
    CBOM:   { color: '#7c3aed', bg: 'color-mix(in srgb, #7c3aed 12%, transparent)' },
    AI_BOM: { color: '#0891b2', bg: 'color-mix(in srgb, #0891b2 12%, transparent)' },
    VENDOR: { color: '#059669', bg: 'color-mix(in srgb, #059669 12%, transparent)' },
  };
  const { color, bg } = colorMap[type] ?? { color: 'var(--muted)', bg: 'var(--panel-muted)' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '2px 8px',
      borderRadius: 999, fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
      color, background: bg, border: `1px solid ${color}40`,
    }}>
      {bomLabel(type)}
    </span>
  );
}

function RiskBadge({ level, score }: { level: string; score: number }) {
  const colorMap: Record<string, { color: string; bg: string }> = {
    CRITICAL: { color: 'var(--critical)', bg: 'color-mix(in srgb, var(--critical) 12%, transparent)' },
    HIGH:     { color: 'var(--high)',     bg: 'color-mix(in srgb, var(--high) 12%, transparent)' },
    MEDIUM:   { color: '#d88f3d',         bg: 'color-mix(in srgb, #d88f3d 12%, transparent)' },
    LOW:      { color: 'var(--accent)',   bg: 'color-mix(in srgb, var(--accent) 10%, transparent)' },
    NONE:     { color: 'var(--muted)',    bg: 'color-mix(in srgb, var(--muted) 8%, transparent)' },
  };
  const { color, bg } = colorMap[level] ?? colorMap['NONE'];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 6,
      padding: '3px 10px', borderRadius: 999, fontWeight: 700,
      fontSize: 13, color, background: bg, border: `1px solid ${color}60`,
    }}>
      <span style={{ fontSize: 16 }}>{score.toFixed(1)}</span>
      <span style={{ fontSize: 11, opacity: 0.85 }}>{level}</span>
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

function RiskBar({ score, level }: { score: number; level: string }) {
  const pct = (score / 10) * 100;
  const colorMap: Record<string, string> = {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
    MEDIUM: '#d88f3d', LOW: 'var(--accent)', NONE: 'var(--muted)',
  };
  return (
    <div style={{ height: 5, borderRadius: 999, background: 'var(--border)', overflow: 'hidden', margin: '6px 0 10px' }}>
      <div style={{ height: '100%', width: `${pct}%`, background: colorMap[level] ?? colorMap['NONE'], borderRadius: 999, transition: 'width 0.4s ease' }} />
    </div>
  );
}

function RiskBarInline({ score, level }: { score: number; level: string }) {
  const colorMap: Record<string, string> = {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
    MEDIUM: '#d88f3d', LOW: 'var(--accent)', NONE: 'var(--muted)',
  };
  const color = colorMap[level] ?? colorMap['NONE'];
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 999, background: 'var(--border)', overflow: 'hidden', minWidth: 60 }}>
        <div style={{ height: '100%', borderRadius: 999, width: `${Math.min(100, score * 10)}%`, background: color }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, minWidth: 28 }}>{score.toFixed(1)}</span>
    </div>
  );
}

function CveSeverityRow({ critical, high, medium, low }: {
  critical: number; high: number; medium: number; low: number;
}) {
  const chips = [
    { count: critical, label: 'CRITICAL', color: 'var(--critical)' },
    { count: high,     label: 'HIGH',     color: 'var(--high)' },
    { count: medium,   label: 'MED',      color: '#d88f3d' },
    { count: low,      label: 'LOW',      color: 'var(--accent)' },
  ].filter(c => c.count > 0);

  if (chips.length === 0) return <span className="panel-caption" style={{ fontSize: 11 }}>No CVEs correlated</span>;
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {chips.map(({ count, label, color }) => (
        <span key={label} style={{
          display: 'inline-flex', alignItems: 'center', gap: 3,
          padding: '1px 7px', borderRadius: 999, fontSize: 11, fontWeight: 600,
          color, border: `1px solid ${color}50`,
          background: `color-mix(in srgb, ${color} 8%, transparent)`,
        }}>
          {count} {label}
        </span>
      ))}
    </div>
  );
}

function CveInlineBar({ critical, high, medium, low, total }: {
  critical: number; high: number; medium: number; low: number; total: number;
}) {
  if (total === 0) return <span className="panel-caption">—</span>;
  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
      {critical > 0 && <span style={{ fontWeight: 700, color: 'var(--critical)', fontSize: 12 }}>{critical}C</span>}
      {high > 0     && <span style={{ fontWeight: 700, color: 'var(--high)',     fontSize: 12 }}>{high}H</span>}
      {medium > 0   && <span style={{ fontWeight: 700, color: '#d88f3d',         fontSize: 12 }}>{medium}M</span>}
      {low > 0      && <span style={{ fontWeight: 700, color: 'var(--muted)',     fontSize: 12 }}>{low}L</span>}
    </div>
  );
}

function FilterPills({ value, options, onChange }: {
  value: string;
  options: string[];
  onChange: (v: string) => void;
}) {
  return (
    <div style={{ display: 'flex', gap: 6 }}>
      {options.map(opt => (
        <button
          key={opt}
          type="button"
          onClick={() => onChange(opt)}
          style={{
            padding: '3px 12px', borderRadius: 999, fontSize: 11, fontWeight: 600,
            cursor: 'pointer', border: '1px solid var(--border)',
            background: value === opt ? 'var(--accent)' : 'var(--panel-muted)',
            color: value === opt ? 'var(--panel)' : 'var(--text)',
          }}
        >
          {opt}
        </button>
      ))}
    </div>
  );
}

// ── Summary widgets ───────────────────────────────────────────────────────────

function SummaryWidgets({ apps }: { apps: ApplicationRiskSummary[] }) {
  const highRisk = apps.filter(a => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length;
  const totalComponents = apps.reduce((s, a) => s + a.totalComponents, 0);
  const totalVulnerable = apps.reduce((s, a) => s + a.vulnerableComponents, 0);
  const totalCritical = apps.reduce((s, a) => s + a.criticalCveCount, 0);
  const bomTypeSet = new Set(apps.flatMap(a => a.bomTypes));
  const stats = [
    { label: 'Applications tracked',  value: apps.length,                      sub: `${highRisk} high / critical risk` },
    { label: 'Total components',      value: totalComponents.toLocaleString(),  sub: 'across all BOMs' },
    { label: 'Vulnerable components', value: totalVulnerable,                   sub: `${totalCritical} with critical CVEs` },
    { label: 'BOM types ingested',    value: bomTypeSet.size,                   sub: [...bomTypeSet].map(bomLabel).join(' · ') || '—' },
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 20 }}>
      {stats.map(({ label, value, sub }) => (
        <div key={label} className="panel" style={{ padding: '16px 20px' }}>
          <div className="panel-caption" style={{ marginBottom: 4 }}>{label}</div>
          <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1.15 }}>{value}</div>
          <div className="panel-caption" style={{ marginTop: 4 }}>{sub}</div>
        </div>
      ))}
    </div>
  );
}

// ── Card view (top 10) ────────────────────────────────────────────────────────

function AppCard({ app, onSelect }: { app: ApplicationRiskSummary; onSelect: (app: ApplicationRiskSummary) => void }) {
  const borderColor =
    app.riskLevel === 'CRITICAL' ? 'color-mix(in srgb, var(--critical) 35%, transparent)' :
    app.riskLevel === 'HIGH'     ? 'color-mix(in srgb, var(--high) 30%, transparent)' :
    'var(--border)';

  return (
    <div
      className="panel"
      onClick={() => onSelect(app)}
      style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, border: `1px solid ${borderColor}`, cursor: 'pointer' }}
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <span style={{ fontWeight: 700, fontSize: 16 }}>{app.assetName}</span>
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {app.bomTypes.map(t => <BomTypeBadge key={t} type={t} />)}
          </div>
        </div>
        <div className="panel-caption mono" style={{ fontSize: 11 }}>{app.assetIdentifier}</div>
      </div>

      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <RiskBadge level={app.riskLevel} score={app.riskScore} />
          <span className="panel-caption" style={{ fontSize: 11 }}>Scout Risk Score</span>
        </div>
        <RiskBar score={app.riskScore} level={app.riskLevel} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
        {[
          { value: app.totalComponents,    label: 'components' },
          { value: app.vulnerableComponents, label: 'vulnerable' },
          { value: app.eolComponents,      label: 'EOL' },
        ].map(({ value, label }) => (
          <div key={label} style={{ textAlign: 'center', padding: '8px 4px', borderRadius: 6, background: 'var(--panel-muted)', border: '1px solid var(--border)' }}>
            <div style={{ fontWeight: 700, fontSize: 18 }}>{value}</div>
            <div className="panel-caption" style={{ fontSize: 11 }}>{label}</div>
          </div>
        ))}
      </div>

      <CveSeverityRow critical={app.criticalCveCount} high={app.highCveCount} medium={app.mediumCveCount} low={app.lowCveCount} />

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: 8, borderTop: '1px solid var(--border)' }}>
        <span className="panel-caption" style={{ fontSize: 11 }}>
          {app.lastIngestedAt ? `Ingested ${timeAgo(app.lastIngestedAt)}` : 'Not yet ingested'}
        </span>
        <span className="panel-caption" style={{ fontSize: 11 }}>{app.businessCriticality}</span>
      </div>
    </div>
  );
}

// ── List view (all applications) ──────────────────────────────────────────────

function AllApplicationsListView({
  apps,
  onBack,
  onSelect,
}: {
  apps: ApplicationRiskSummary[];
  onBack: () => void;
  onSelect: (app: ApplicationRiskSummary) => void;
}) {
  const [riskFilter, setRiskFilter] = React.useState<string>('ALL');
  const [sortBy, setSortBy] = React.useState<'risk' | 'name' | 'components'>('risk');

  const filtered = riskFilter === 'ALL' ? apps : apps.filter(a => a.riskLevel === riskFilter);
  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'risk') return b.riskScore - a.riskScore;
    if (sortBy === 'components') return b.totalComponents - a.totalComponents;
    return a.assetName.localeCompare(b.assetName);
  });

  return (
    <div className="page-grid" style={{ gap: 16 }}>
      {/* Back nav */}
      <div>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onBack} style={{ fontSize: 12 }}>
          ← Back
        </button>
      </div>

      <div className="panel">
        {/* Header */}
        <div className="panel-header" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3 style={{ margin: 0 }}>All Applications</h3>
            <span className="panel-caption">{sorted.length} of {apps.length} applications</span>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <FilterPills
              value={riskFilter}
              options={['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']}
              onChange={setRiskFilter}
            />
            <select className="filter-input" style={{ width: 'auto' }} value={sortBy} onChange={e => setSortBy(e.target.value as typeof sortBy)}>
              <option value="risk">Sort: Risk score</option>
              <option value="components">Sort: Components</option>
              <option value="name">Sort: Name</option>
            </select>
          </div>
        </div>

        {sorted.length === 0 ? (
          <div className="empty-state"><p>No applications match the selected filter.</p></div>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Application</th>
                  <th>BOM types</th>
                  <th>Criticality</th>
                  <th>Components</th>
                  <th>Vulnerable</th>
                  <th>Findings</th>
                  <th>EOL</th>
                  <th>CVEs</th>
                  <th>Risk score</th>
                  <th>Ingested</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map(app => (
                  <tr key={app.assetId} style={{ cursor: 'pointer' }} onClick={() => onSelect(app)}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{app.assetName}</div>
                      <div className="mono panel-caption" style={{ fontSize: 10 }}>{app.assetIdentifier}</div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {app.bomTypes.length > 0
                          ? app.bomTypes.map(t => <BomTypeBadge key={t} type={t} />)
                          : <span className="panel-caption">—</span>}
                      </div>
                    </td>
                    <td><span className="status-pill status-auto_closed">{app.businessCriticality}</span></td>
                    <td style={{ fontWeight: 600 }}>{app.totalComponents}</td>
                    <td>
                      {app.vulnerableComponents > 0
                        ? <span style={{ fontWeight: 700, color: 'var(--high)' }}>{app.vulnerableComponents}</span>
                        : <span className="panel-caption">0</span>}
                    </td>
                    <td>
                      {app.findingCount > 0
                        ? <span style={{ fontWeight: 700, color: 'var(--accent)' }}>{app.findingCount}</span>
                        : <span className="panel-caption">—</span>}
                    </td>
                    <td>
                      {app.eolComponents > 0
                        ? <span style={{ fontWeight: 700, color: '#d88f3d' }}>{app.eolComponents}</span>
                        : <span className="panel-caption">0</span>}
                    </td>
                    <td>
                      <CveInlineBar
                        critical={app.criticalCveCount} high={app.highCveCount}
                        medium={app.mediumCveCount} low={app.lowCveCount} total={app.totalCveCount}
                      />
                    </td>
                    <td style={{ minWidth: 140 }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        <RiskPill level={app.riskLevel} />
                        <RiskBarInline score={app.riskScore} level={app.riskLevel} />
                      </div>
                    </td>
                    <td className="panel-caption" style={{ whiteSpace: 'nowrap', fontSize: 11 }}>
                      {app.lastIngestedAt ? timeAgo(app.lastIngestedAt) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

type NavMode = 'cards' | 'list' | 'detail';

export function ApplicationsDashboard() {
  const [mode, setMode] = React.useState<NavMode>('cards');
  const [prevMode, setPrevMode] = React.useState<NavMode>('cards');
  const [selectedApp, setSelectedApp] = React.useState<ApplicationRiskSummary | null>(null);

  const selectApp = (app: ApplicationRiskSummary, from: NavMode) => {
    setPrevMode(from);
    setSelectedApp(app);
    setMode('detail');
  };

  const { data, isPending, isError } = useQuery({
    queryKey: ['application-risk'],
    queryFn: () => api.getApplicationRisk(),
  });

  const apps = data ?? [];

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading application risk data…</p>
      </div>
    );
  }
  if (isError) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <p style={{ color: 'var(--critical)' }}>Failed to load application risk data.</p>
      </div>
    );
  }
  if (apps.length === 0) {
    return (
      <div className="panel">
        <div className="empty-state">
          <p>No application assets found. Upload a BOM for an APPLICATION asset to see risk here.</p>
        </div>
      </div>
    );
  }

  if (mode === 'detail' && selectedApp) {
    return (
      <ApplicationDetailPanel
        app={selectedApp}
        onBack={() => { setMode(prevMode); setSelectedApp(null); }}
      />
    );
  }

  if (mode === 'list') {
    return (
      <AllApplicationsListView
        apps={apps}
        onBack={() => setMode('cards')}
        onSelect={app => selectApp(app, 'list')}
      />
    );
  }

  // Card view — top 10 by risk score
  const top10 = [...apps].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);

  return (
    <div className="page-grid" style={{ gap: 0 }}>
      <SummaryWidgets apps={apps} />

      <div className="panel">
        <div className="panel-header" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3>Applications Risk Overview</h3>
            <span className="panel-caption">
              Top {top10.length} applications by risk score · dependency vulnerability correlation across all BOM types
            </span>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setMode('list')}
          >
            View all ({apps.length})
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16, padding: '4px 0 8px' }}>
          {top10.map(app => <AppCard key={app.assetId} app={app} onSelect={a => selectApp(a, 'cards')} />)}
        </div>
      </div>
    </div>
  );
}
