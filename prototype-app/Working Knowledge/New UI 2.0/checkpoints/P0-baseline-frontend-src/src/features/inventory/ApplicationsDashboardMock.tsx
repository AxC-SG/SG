/**
 * MOCK — Applications Risk Dashboard
 * Static hardcoded data. Replace with real API queries before shipping.
 */
import React from 'react';

type BomKind = 'SBOM' | 'CBOM' | 'AI_BOM';
type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

interface AppRiskRecord {
  id: string;
  name: string;
  identifier: string;
  bomTypes: BomKind[];
  riskLevel: RiskLevel;
  riskScore: number;
  totalComponents: number;
  vulnerableComponents: number;
  eolComponents: number;
  criticalCves: number;
  highCves: number;
  mediumCves: number;
  lowCves: number;
  lastIngested: string;
  repo?: string;
}

const MOCK_APPS: AppRiskRecord[] = [
  {
    id: '1',
    name: 'kanra-mobile',
    identifier: 'pkg:npm/kanra-mobile@1.0.0',
    bomTypes: ['SBOM', 'AI_BOM'],
    riskLevel: 'CRITICAL',
    riskScore: 9.1,
    totalComponents: 616,
    vulnerableComponents: 3,
    eolComponents: 2,
    criticalCves: 1,
    highCves: 4,
    mediumCves: 7,
    lowCves: 1,
    lastIngested: '2 hours ago',
    repo: 'ggkarthik/kanra-mobile',
  },
  {
    id: '2',
    name: 'kanra',
    identifier: 'pkg:npm/kanra@2.1.0',
    bomTypes: ['SBOM', 'CBOM', 'AI_BOM'],
    riskLevel: 'HIGH',
    riskScore: 7.4,
    totalComponents: 284,
    vulnerableComponents: 5,
    eolComponents: 1,
    criticalCves: 0,
    highCves: 9,
    mediumCves: 12,
    lowCves: 3,
    lastIngested: '1 day ago',
    repo: 'ggkarthik/kanra',
  },
  {
    id: '3',
    name: 'kanraai',
    identifier: 'pkg:npm/kanraai@0.9.2',
    bomTypes: ['SBOM', 'AI_BOM'],
    riskLevel: 'MEDIUM',
    riskScore: 5.2,
    totalComponents: 148,
    vulnerableComponents: 2,
    eolComponents: 0,
    criticalCves: 0,
    highCves: 2,
    mediumCves: 6,
    lowCves: 0,
    lastIngested: '3 days ago',
    repo: 'ggkarthik/kanraai',
  },
  {
    id: '4',
    name: 'scout-backend',
    identifier: 'com.prototype:vulnwatch-backend@1.0',
    bomTypes: ['SBOM'],
    riskLevel: 'LOW',
    riskScore: 2.1,
    totalComponents: 97,
    vulnerableComponents: 0,
    eolComponents: 0,
    criticalCves: 0,
    highCves: 0,
    mediumCves: 3,
    lowCves: 1,
    lastIngested: '5 days ago',
    repo: 'ggkarthik/VScout',
  },
];

function BomTypeBadge({ type }: { type: BomKind }) {
  const map: Record<BomKind, { label: string; color: string; bg: string }> = {
    SBOM:   { label: 'SBOM',   color: '#2563eb', bg: 'color-mix(in srgb, #2563eb 12%, transparent)' },
    CBOM:   { label: 'CBOM',   color: '#7c3aed', bg: 'color-mix(in srgb, #7c3aed 12%, transparent)' },
    AI_BOM: { label: 'AI BOM', color: '#0891b2', bg: 'color-mix(in srgb, #0891b2 12%, transparent)' },
  };
  const { label, color, bg } = map[type];
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', padding: '2px 8px',
      borderRadius: 999, fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
      color, background: bg, border: `1px solid ${color}40`,
    }}>
      {label}
    </span>
  );
}

function RiskBadge({ level, score }: { level: RiskLevel; score: number }) {
  const map: Record<RiskLevel, { color: string; bg: string }> = {
    CRITICAL: { color: 'var(--critical)', bg: 'color-mix(in srgb, var(--critical) 12%, transparent)' },
    HIGH:     { color: 'var(--high)',     bg: 'color-mix(in srgb, var(--high) 12%, transparent)' },
    MEDIUM:   { color: '#d88f3d',         bg: 'color-mix(in srgb, #d88f3d 12%, transparent)' },
    LOW:      { color: 'var(--accent)',   bg: 'color-mix(in srgb, var(--accent) 10%, transparent)' },
    NONE:     { color: 'var(--muted)',    bg: 'color-mix(in srgb, var(--muted) 8%, transparent)' },
  };
  const { color, bg } = map[level];
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

function RiskBar({ score, level }: { score: number; level: RiskLevel }) {
  const pct = (score / 10) * 100;
  const colorMap: Record<RiskLevel, string> = {
    CRITICAL: 'var(--critical)',
    HIGH:     'var(--high)',
    MEDIUM:   '#d88f3d',
    LOW:      'var(--accent)',
    NONE:     'var(--muted)',
  };
  return (
    <div style={{
      height: 5, borderRadius: 999,
      background: 'var(--border)', overflow: 'hidden', margin: '6px 0 10px',
    }}>
      <div style={{
        height: '100%', width: `${pct}%`,
        background: colorMap[level], borderRadius: 999,
        transition: 'width 0.4s ease',
      }} />
    </div>
  );
}

function CveSeverityRow({ critical, high, medium, low }: {
  critical: number; high: number; medium: number; low: number;
}) {
  const chips: Array<{ count: number; label: string; color: string }> = [
    { count: critical, label: 'CRITICAL', color: 'var(--critical)' },
    { count: high,     label: 'HIGH',     color: 'var(--high)' },
    { count: medium,   label: 'MED',      color: '#d88f3d' },
    { count: low,      label: 'LOW',      color: 'var(--accent)' },
  ].filter((c) => c.count > 0);

  if (chips.length === 0) {
    return <span className="panel-caption" style={{ fontSize: 11 }}>No CVEs correlated</span>;
  }
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

function HighRiskBanner({ apps }: { apps: AppRiskRecord[] }) {
  const flagged = apps.filter((a) => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH');
  if (flagged.length === 0) return null;
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 14, padding: '12px 18px',
      borderRadius: 8, marginBottom: 20,
      background: 'color-mix(in srgb, var(--critical) 6%, var(--panel))',
      border: '1px solid color-mix(in srgb, var(--critical) 30%, transparent)',
    }}>
      <span style={{ fontSize: 22 }}>⚠</span>
      <div style={{ flex: 1, display: 'grid', gap: 2 }}>
        <strong style={{ fontSize: 14, color: 'var(--critical)' }}>
          {flagged.length} application{flagged.length > 1 ? 's' : ''} require immediate attention
        </strong>
        <span className="panel-caption">
          {flagged.map((a) => a.name).join(', ')} — critical or high dependency risk detected
        </span>
      </div>
      <button type="button" className="btn btn-secondary btn-sm">View findings →</button>
    </div>
  );
}

function SummaryWidgets({ apps }: { apps: AppRiskRecord[] }) {
  const totalApps = apps.length;
  const highRisk = apps.filter((a) => a.riskLevel === 'CRITICAL' || a.riskLevel === 'HIGH').length;
  const totalComponents = apps.reduce((s, a) => s + a.totalComponents, 0);
  const totalVulnerable = apps.reduce((s, a) => s + a.vulnerableComponents, 0);
  const totalCritical = apps.reduce((s, a) => s + a.criticalCves, 0);
  const bomTypeSet = new Set(apps.flatMap((a) => a.bomTypes));

  const stats = [
    { label: 'Applications tracked', value: totalApps,                        sub: `${highRisk} high / critical risk` },
    { label: 'Total components',     value: totalComponents.toLocaleString(), sub: 'across all BOMs' },
    { label: 'Vulnerable components',value: totalVulnerable,                  sub: `${totalCritical} with critical CVEs` },
    { label: 'BOM types ingested',   value: bomTypeSet.size,                  sub: [...bomTypeSet].join(' · ') },
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

function AppCard({ app }: { app: AppRiskRecord }) {
  const borderColor =
    app.riskLevel === 'CRITICAL' ? 'color-mix(in srgb, var(--critical) 35%, transparent)' :
    app.riskLevel === 'HIGH'     ? 'color-mix(in srgb, var(--high) 30%, transparent)' :
    'var(--border)';

  return (
    <div className="panel" style={{
      padding: 20, display: 'flex', flexDirection: 'column', gap: 12,
      border: `1px solid ${borderColor}`,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <span style={{ fontWeight: 700, fontSize: 16 }}>{app.name}</span>
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
            {app.bomTypes.map((t) => <BomTypeBadge key={t} type={t} />)}
          </div>
        </div>
        <div className="panel-caption mono" style={{ fontSize: 11 }}>{app.identifier}</div>
        {app.repo && (
          <div className="panel-caption" style={{ fontSize: 11 }}>
            ⬡ {app.repo}
          </div>
        )}
      </div>

      {/* Risk score */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
          <RiskBadge level={app.riskLevel} score={app.riskScore} />
          <span className="panel-caption" style={{ fontSize: 11 }}>Scout Risk Score</span>
        </div>
        <RiskBar score={app.riskScore} level={app.riskLevel} />
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
        {[
          { value: app.totalComponents, label: 'components' },
          { value: app.vulnerableComponents, label: 'vulnerable' },
          { value: app.eolComponents, label: 'EOL' },
        ].map(({ value, label }) => (
          <div key={label} style={{
            textAlign: 'center', padding: '8px 4px', borderRadius: 6,
            background: 'var(--panel-muted)', border: '1px solid var(--border)',
          }}>
            <div style={{ fontWeight: 700, fontSize: 18 }}>{value}</div>
            <div className="panel-caption" style={{ fontSize: 11 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* CVE breakdown */}
      <CveSeverityRow
        critical={app.criticalCves}
        high={app.highCves}
        medium={app.mediumCves}
        low={app.lowCves}
      />

      {/* Footer */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        paddingTop: 8, borderTop: '1px solid var(--border)',
      }}>
        <span className="panel-caption" style={{ fontSize: 11 }}>Ingested {app.lastIngested}</span>
        <div style={{ display: 'flex', gap: 6 }}>
          <button type="button" className="btn btn-ghost btn-sm">View BOM</button>
          <button type="button" className="btn btn-secondary btn-sm">Findings</button>
        </div>
      </div>
    </div>
  );
}

export function ApplicationsDashboardMock() {
  const [sortBy, setSortBy] = React.useState<'risk' | 'name' | 'components'>('risk');
  const [riskFilter, setRiskFilter] = React.useState<RiskLevel | 'ALL'>('ALL');

  const filtered = riskFilter === 'ALL'
    ? MOCK_APPS
    : MOCK_APPS.filter((a) => a.riskLevel === riskFilter);

  const sorted = [...filtered].sort((a, b) => {
    if (sortBy === 'risk') return b.riskScore - a.riskScore;
    if (sortBy === 'components') return b.totalComponents - a.totalComponents;
    return a.name.localeCompare(b.name);
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      <HighRiskBanner apps={MOCK_APPS} />
      <SummaryWidgets apps={MOCK_APPS} />

      <div className="panel">
        <div className="panel-header" style={{ flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3>Applications Risk Overview</h3>
            <span className="panel-caption">
              Risk scores derived from dependency vulnerability correlation across all BOM types
            </span>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {/* Risk filter pills */}
            <div style={{ display: 'flex', gap: 6 }}>
              {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => setRiskFilter(level)}
                  style={{
                    padding: '3px 10px', borderRadius: 999, fontSize: 11, fontWeight: 600,
                    cursor: 'pointer', border: '1px solid var(--border)',
                    background: riskFilter === level ? 'var(--accent)' : 'var(--panel-muted)',
                    color: riskFilter === level ? 'var(--panel)' : 'var(--text)',
                  }}
                >
                  {level}
                </button>
              ))}
            </div>
            <select
              className="filter-input"
              style={{ width: 'auto' }}
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
            >
              <option value="risk">Sort: Risk score</option>
              <option value="components">Sort: Components</option>
              <option value="name">Sort: Name</option>
            </select>
          </div>
        </div>

        {sorted.length === 0 ? (
          <div className="empty-state"><p>No applications match the selected risk filter.</p></div>
        ) : (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
            gap: 16, padding: '4px 0 8px',
          }}>
            {sorted.map((app) => <AppCard key={app.id} app={app} />)}
          </div>
        )}
      </div>
    </div>
  );
}
