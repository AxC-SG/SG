/**
 * MOCK — BOM Components Tab
 * Static hardcoded data. Replace with real API queries before shipping.
 */
import React from 'react';

type ComponentRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';

interface BomComponentRecord {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  license: string;
  appName: string;
  bomType: string;
  riskLevel: ComponentRisk;
  cveCount: number;
  criticalCves: number;
  highCves: number;
  isEol: boolean;
  eolDate?: string;
  scope?: string;
  correlationState: 'APPLICABLE' | 'NOT_APPLICABLE' | 'UNKNOWN' | 'UNCHECKED';
}

const MOCK_COMPONENTS: BomComponentRecord[] = [
  { id: '1', name: 'shell-quote',        version: '1.8.3',   ecosystem: 'npm',   purl: 'pkg:npm/shell-quote@1.8.3',        license: 'MIT',    appName: 'kanra-mobile', bomType: 'SBOM',   riskLevel: 'CRITICAL', cveCount: 1, criticalCves: 1, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'APPLICABLE' },
  { id: '2', name: 'ua-parser-js',       version: '0.7.41',  ecosystem: 'npm',   purl: 'pkg:npm/ua-parser-js@0.7.41',      license: 'MIT',    appName: 'kanra-mobile', bomType: 'SBOM',   riskLevel: 'HIGH',     cveCount: 3, criticalCves: 0, highCves: 3, isEol: false, scope: 'runtime',    correlationState: 'NOT_APPLICABLE' },
  { id: '3', name: 'lodash',             version: '4.17.20', ecosystem: 'npm',   purl: 'pkg:npm/lodash@4.17.20',           license: 'MIT',    appName: 'kanra-mobile', bomType: 'SBOM',   riskLevel: 'MEDIUM',   cveCount: 2, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'APPLICABLE' },
  { id: '4', name: 'moment',             version: '2.29.1',  ecosystem: 'npm',   purl: 'pkg:npm/moment@2.29.1',            license: 'MIT',    appName: 'kanra-mobile', bomType: 'SBOM',   riskLevel: 'HIGH',     cveCount: 4, criticalCves: 0, highCves: 4, isEol: true,  eolDate: '2023-09-01', scope: 'runtime', correlationState: 'APPLICABLE' },
  { id: '5', name: 'axios',              version: '0.21.1',  ecosystem: 'npm',   purl: 'pkg:npm/axios@0.21.1',             license: 'MIT',    appName: 'kanra-mobile', bomType: 'SBOM',   riskLevel: 'HIGH',     cveCount: 2, criticalCves: 0, highCves: 2, isEol: false, scope: 'runtime',    correlationState: 'APPLICABLE' },
  { id: '6', name: '@supabase/storage-js',version: '2.101.1',ecosystem: 'npm',   purl: 'pkg:npm/@supabase/storage-js@2.101.1', license: 'MIT', appName: 'kanra-mobile', bomType: 'SBOM', riskLevel: 'NONE',   cveCount: 0, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'NOT_APPLICABLE' },
  { id: '7', name: 'openai',             version: '4.52.0',  ecosystem: 'npm',   purl: 'pkg:npm/openai@4.52.0',            license: 'Apache', appName: 'kanra',        bomType: 'AI_BOM', riskLevel: 'NONE',     cveCount: 0, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'NOT_APPLICABLE' },
  { id: '8', name: 'langchain',          version: '0.2.5',   ecosystem: 'npm',   purl: 'pkg:npm/langchain@0.2.5',          license: 'MIT',    appName: 'kanra',        bomType: 'AI_BOM', riskLevel: 'MEDIUM',   cveCount: 1, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'UNKNOWN' },
  { id: '9', name: 'gpt-tokenizer',      version: '2.1.2',   ecosystem: 'npm',   purl: 'pkg:npm/gpt-tokenizer@2.1.2',      license: 'MIT',    appName: 'kanra',        bomType: 'AI_BOM', riskLevel: 'NONE',     cveCount: 0, criticalCves: 0, highCves: 0, isEol: false,              correlationState: 'NOT_APPLICABLE' },
  { id: '10', name: 'crypto',            version: '1.0.1',   ecosystem: 'npm',   purl: 'pkg:npm/crypto@1.0.1',             license: 'ISC',    appName: 'kanra',        bomType: 'CBOM',   riskLevel: 'HIGH',     cveCount: 2, criticalCves: 0, highCves: 2, isEol: false, scope: 'runtime',    correlationState: 'APPLICABLE' },
  { id: '11', name: 'node-forge',        version: '1.3.1',   ecosystem: 'npm',   purl: 'pkg:npm/node-forge@1.3.1',         license: 'BSD',    appName: 'kanra',        bomType: 'CBOM',   riskLevel: 'MEDIUM',   cveCount: 1, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'NOT_APPLICABLE' },
  { id: '12', name: 'express',           version: '4.18.2',  ecosystem: 'npm',   purl: 'pkg:npm/express@4.18.2',           license: 'MIT',    appName: 'kanraai',      bomType: 'SBOM',   riskLevel: 'LOW',      cveCount: 1, criticalCves: 0, highCves: 0, isEol: false, scope: 'runtime',    correlationState: 'APPLICABLE' },
];

const WIDGET_STATS = [
  { label: 'Total Components', value: '1,145', sub: 'across 4 applications', color: 'var(--title)' },
  { label: 'Vulnerable',        value: '23',    sub: '6 APPLICABLE CVEs',      color: 'var(--critical)' },
  { label: 'EOL Components',    value: '3',     sub: 'past end-of-life',        color: '#d88f3d' },
  { label: 'AI/ML Libraries',   value: '47',    sub: 'from AI BOMs',            color: '#7c3aed' },
  { label: 'Crypto Libraries',  value: '18',    sub: 'from CBOMs',              color: '#0891b2' },
  { label: 'Licenses',          value: '9',     sub: 'unique licenses',         color: 'var(--muted)' },
];

function WidgetRow() {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12, marginBottom: 20 }}>
      {WIDGET_STATS.map(({ label, value, sub, color }) => (
        <div key={label} className="panel" style={{ padding: '14px 16px' }}>
          <div className="panel-caption" style={{ marginBottom: 4, fontSize: 11 }}>{label}</div>
          <div style={{ fontSize: 24, fontWeight: 700, color }}>{value}</div>
          <div className="panel-caption" style={{ marginTop: 3, fontSize: 11 }}>{sub}</div>
        </div>
      ))}
    </div>
  );
}

function EcosystemBreakdown() {
  const ecosystems = [
    { name: 'npm', count: 1008, pct: 88 },
    { name: 'maven', count: 97, pct: 8 },
    { name: 'pip', count: 30, pct: 3 },
    { name: 'other', count: 10, pct: 1 },
  ];
  return (
    <div className="panel" style={{ padding: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <h4 style={{ margin: 0 }}>Ecosystem Breakdown</h4>
      </div>
      {ecosystems.map(({ name, count, pct }) => (
        <div key={name} style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
            <span style={{ fontWeight: 600, textTransform: 'uppercase', fontSize: 12 }}>{name}</span>
            <span className="panel-caption">{count} ({pct}%)</span>
          </div>
          <div style={{ height: 6, borderRadius: 999, background: 'var(--border)', overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: 'var(--accent)', borderRadius: 999 }} />
          </div>
        </div>
      ))}
    </div>
  );
}

function BomTypeBreakdown() {
  const types = [
    { label: 'SBOM', count: 1048, color: '#2563eb' },
    { label: 'AI BOM', count: 62, color: '#0891b2' },
    { label: 'CBOM', count: 35, color: '#7c3aed' },
  ];
  return (
    <div className="panel" style={{ padding: 16 }}>
      <div className="panel-header" style={{ marginBottom: 12 }}>
        <h4 style={{ margin: 0 }}>BOM Type Distribution</h4>
      </div>
      {types.map(({ label, count, color }) => (
        <div key={label} style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '10px 0', borderBottom: '1px solid var(--border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 12, height: 12, borderRadius: 3, background: color }} />
            <span style={{ fontWeight: 600, fontSize: 13 }}>{label}</span>
          </div>
          <span style={{ fontWeight: 700, fontSize: 16 }}>{count}</span>
        </div>
      ))}
    </div>
  );
}

function RiskPill({ level }: { level: ComponentRisk }) {
  const map: Record<ComponentRisk, { label: string; className: string }> = {
    CRITICAL: { label: 'CRITICAL', className: 'status-pill status-failure' },
    HIGH:     { label: 'HIGH',     className: 'status-pill status-warning' },
    MEDIUM:   { label: 'MEDIUM',   className: 'status-pill status-unknown' },
    LOW:      { label: 'LOW',      className: 'status-pill status-open' },
    NONE:     { label: 'Clear',    className: 'status-pill status-suppressed' },
  };
  return <span className={map[level].className}>{map[level].label}</span>;
}

function CorrelationPill({ state }: { state: BomComponentRecord['correlationState'] }) {
  const map: Record<BomComponentRecord['correlationState'], { label: string; cls: string }> = {
    APPLICABLE:     { label: 'APPLICABLE',     cls: 'status-pill inv-status-applicable' },
    NOT_APPLICABLE: { label: 'NOT APPLICABLE', cls: 'status-pill status-suppressed' },
    UNKNOWN:        { label: 'UNKNOWN',        cls: 'status-pill status-unknown' },
    UNCHECKED:      { label: 'UNCHECKED',      cls: 'status-pill status-auto_closed' },
  };
  return <span className={map[state].cls}>{map[state].label}</span>;
}

function BomTypeTag({ type }: { type: string }) {
  const colors: Record<string, string> = {
    SBOM: '#2563eb', AI_BOM: '#0891b2', CBOM: '#7c3aed',
  };
  const color = colors[type] ?? 'var(--muted)';
  return (
    <span style={{
      display: 'inline-flex', padding: '2px 7px', borderRadius: 999,
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em',
      color, background: `color-mix(in srgb, ${color} 12%, transparent)`,
      border: `1px solid ${color}40`,
    }}>
      {type.replace('_', ' ')}
    </span>
  );
}

export function BomComponentsMock() {
  const [query, setQuery] = React.useState('');
  const [ecosystemFilter, setEcosystemFilter] = React.useState('');
  const [riskFilter, setRiskFilter] = React.useState('');
  const [bomTypeFilter, setBomTypeFilter] = React.useState('');

  const filtered = MOCK_COMPONENTS.filter((c) => {
    if (query && !c.name.toLowerCase().includes(query.toLowerCase())) return false;
    if (ecosystemFilter && c.ecosystem !== ecosystemFilter) return false;
    if (riskFilter && c.riskLevel !== riskFilter) return false;
    if (bomTypeFilter && c.bomType !== bomTypeFilter) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      <WidgetRow />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
        <EcosystemBreakdown />
        <BomTypeBreakdown />
      </div>

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>BOM Components</h3>
            <span className="panel-caption">
              All components across SBOM, CBOM, and AI BOM documents — with correlation and risk status
            </span>
          </div>
          <button type="button" className="btn btn-secondary btn-sm">Export CSV</button>
        </div>

        {/* Filters */}
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
            <option value="npm">npm</option>
            <option value="maven">maven</option>
            <option value="pip">pip</option>
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
          </select>
          {(query || ecosystemFilter || riskFilter || bomTypeFilter) && (
            <button type="button" className="btn btn-secondary btn-sm"
              onClick={() => { setQuery(''); setEcosystemFilter(''); setRiskFilter(''); setBomTypeFilter(''); }}>
              Clear filters
            </button>
          )}
        </div>

        <div className="panel-caption" style={{ padding: '0 0 8px', fontSize: 11 }}>
          Showing {filtered.length} of {MOCK_COMPONENTS.length} components (mock data)
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Component</th>
                <th>Version</th>
                <th>Ecosystem</th>
                <th>BOM Type</th>
                <th>Application</th>
                <th>Risk</th>
                <th>CVEs</th>
                <th>Correlation</th>
                <th>EOL</th>
                <th>License</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((c) => (
                <tr key={c.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{c.name}</div>
                    <div className="panel-caption mono" style={{ fontSize: 10 }}>{c.purl}</div>
                  </td>
                  <td className="mono">{c.version}</td>
                  <td><span className="status-pill status-auto_closed">{c.ecosystem}</span></td>
                  <td><BomTypeTag type={c.bomType} /></td>
                  <td>
                    <div style={{ fontWeight: 500 }}>{c.appName}</div>
                    {c.scope && <div className="panel-caption" style={{ fontSize: 11 }}>{c.scope}</div>}
                  </td>
                  <td><RiskPill level={c.riskLevel} /></td>
                  <td>
                    {c.cveCount > 0 ? (
                      <div>
                        <span style={{ fontWeight: 600 }}>{c.cveCount}</span>
                        {c.criticalCves > 0 && (
                          <span className="panel-caption" style={{ color: 'var(--critical)', marginLeft: 4 }}>
                            {c.criticalCves}C
                          </span>
                        )}
                        {c.highCves > 0 && (
                          <span className="panel-caption" style={{ color: 'var(--high)', marginLeft: 4 }}>
                            {c.highCves}H
                          </span>
                        )}
                      </div>
                    ) : <span className="panel-caption">—</span>}
                  </td>
                  <td><CorrelationPill state={c.correlationState} /></td>
                  <td>
                    {c.isEol ? (
                      <div>
                        <span className="status-pill status-failure">EOL</span>
                        {c.eolDate && <div className="panel-caption" style={{ fontSize: 10 }}>{c.eolDate}</div>}
                      </div>
                    ) : <span className="panel-caption">—</span>}
                  </td>
                  <td>{c.license || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="empty-state"><p>No components match the current filters.</p></div>
        )}
      </div>
    </div>
  );
}
