/**
 * MOCK — Enhanced BOM Inventory Page
 * Adds: on-demand ingestion per repo, delete/run actions per row, relevant options.
 * Static hardcoded data. Replace with real API queries before shipping.
 */
import React from 'react';

type BomType = 'SBOM' | 'AI_BOM' | 'CBOM' | 'VENDOR';
type BomStatus = 'ACTIVE' | 'SUPERSEDED' | 'INACTIVE';
type SourceMethod = 'GITHUB_REPO' | 'GITHUB_RELEASE' | 'UPLOAD' | 'ENDPOINT';

interface BomInventoryRow {
  id: string;
  bomType: BomType;
  supplier: string;
  sourceMethod: SourceMethod;
  sourceRef: string;
  repo?: string;
  format: string;
  specFamily: string;
  componentCount: number;
  correlatedCount: number;
  vulnerabilityLinks: number;
  status: BomStatus;
  supported: boolean;
  supportLevel: string;
  ingestedAt: string;
  ingestedBy: string;
  lastRunAt?: string;
  nextScheduledRun?: string;
}

const MOCK_BOMS: BomInventoryRow[] = [
  {
    id: 'b1', bomType: 'SBOM',   supplier: 'kanra-mobile', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ abc1234', repo: 'ggkarthik/kanra-mobile',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 616, correlatedCount: 45, vulnerabilityLinks: 13,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '2 hours ago', ingestedBy: 'local-analyst',
    lastRunAt: '2 hours ago', nextScheduledRun: 'in 4 hours 58 min',
  },
  {
    id: 'b2', bomType: 'AI_BOM', supplier: 'kanra-mobile', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ def5678', repo: 'ggkarthik/kanra-mobile',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 12, correlatedCount: 2, vulnerabilityLinks: 1,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '2 hours ago', ingestedBy: 'local-analyst',
    lastRunAt: '2 hours ago', nextScheduledRun: 'in 4 hours 58 min',
  },
  {
    id: 'b3', bomType: 'SBOM',   supplier: 'kanra', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ ghi9012', repo: 'ggkarthik/kanra',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 284, correlatedCount: 31, vulnerabilityLinks: 22,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '1 day ago', ingestedBy: 'local-analyst',
    lastRunAt: '1 day ago', nextScheduledRun: 'in 3 hours 12 min',
  },
  {
    id: 'b4', bomType: 'CBOM',   supplier: 'kanra', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ jkl3456', repo: 'ggkarthik/kanra',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 35, correlatedCount: 8, vulnerabilityLinks: 3,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '1 day ago', ingestedBy: 'local-analyst',
    lastRunAt: '1 day ago', nextScheduledRun: 'in 3 hours 12 min',
  },
  {
    id: 'b5', bomType: 'AI_BOM', supplier: 'kanra', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ mno7890', repo: 'ggkarthik/kanra',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 50, correlatedCount: 5, vulnerabilityLinks: 1,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '1 day ago', ingestedBy: 'local-analyst',
    lastRunAt: '1 day ago', nextScheduledRun: 'in 3 hours 12 min',
  },
  {
    id: 'b6', bomType: 'SBOM',   supplier: 'kanraai', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ pqr1234', repo: 'ggkarthik/kanraai',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 148, correlatedCount: 12, vulnerabilityLinks: 7,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '3 days ago', ingestedBy: 'local-analyst',
    lastRunAt: '3 days ago', nextScheduledRun: 'in 1 hour 44 min',
  },
  {
    id: 'b7', bomType: 'AI_BOM', supplier: 'kanraai', sourceMethod: 'GITHUB_REPO',
    sourceRef: 'main @ stu5678', repo: 'ggkarthik/kanraai',
    format: 'CycloneDX', specFamily: 'cyclonedx', componentCount: 22, correlatedCount: 2, vulnerabilityLinks: 0,
    status: 'ACTIVE', supported: true, supportLevel: 'Current',
    ingestedAt: '3 days ago', ingestedBy: 'local-analyst',
    lastRunAt: '3 days ago', nextScheduledRun: 'in 1 hour 44 min',
  },
  {
    id: 'b8', bomType: 'SBOM',   supplier: 'scout-backend', sourceMethod: 'UPLOAD',
    sourceRef: 'manual-upload', repo: undefined,
    format: 'SPDX', specFamily: 'spdx', componentCount: 97, correlatedCount: 0, vulnerabilityLinks: 4,
    status: 'ACTIVE', supported: true, supportLevel: 'Previous',
    ingestedAt: '5 days ago', ingestedBy: 'local-analyst',
  },
];

// Group BOMs by repo for on-demand run
const REPOS = [
  { repo: 'ggkarthik/kanra-mobile', bomIds: ['b1', 'b2'], bomCount: 2 },
  { repo: 'ggkarthik/kanra',        bomIds: ['b3', 'b4', 'b5'], bomCount: 3 },
  { repo: 'ggkarthik/kanraai',      bomIds: ['b6', 'b7'], bomCount: 2 },
];

function BomTypeBadge({ type }: { type: BomType }) {
  const map: Record<BomType, { label: string; color: string }> = {
    SBOM:   { label: 'SBOM',   color: '#2563eb' },
    AI_BOM: { label: 'AI BOM', color: '#0891b2' },
    CBOM:   { label: 'CBOM',   color: '#7c3aed' },
    VENDOR: { label: 'VENDOR', color: 'var(--muted)' },
  };
  const { label, color } = map[type];
  return (
    <span style={{
      display: 'inline-flex', padding: '2px 8px', borderRadius: 999,
      fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
      color, background: `color-mix(in srgb, ${color} 12%, transparent)`,
      border: `1px solid ${color}40`,
    }}>
      {label}
    </span>
  );
}

function StatusBadge({ status }: { status: BomStatus }) {
  const cls = status === 'ACTIVE' ? 'status-pill status-open'
    : status === 'SUPERSEDED'     ? 'status-pill status-suppressed'
    :                               'status-pill status-auto_closed';
  return <span className={cls}>{status}</span>;
}

function SupportBadge({ level, supported }: { level: string; supported: boolean }) {
  const cls = !supported ? 'status-pill status-failure'
    : level === 'Current'  ? 'status-pill status-open'
    : level === 'Previous' ? 'status-pill status-unknown'
    :                        'status-pill status-suppressed';
  return <span className={cls}>{level}</span>;
}

function RunningSpinner() {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--accent)' }}>
      <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>↻</span>
      Running…
    </span>
  );
}

function OnDemandRepoPanel() {
  const [running, setRunning] = React.useState<Record<string, boolean>>({});

  function handleRun(repo: string) {
    setRunning((prev) => ({ ...prev, [repo]: true }));
    setTimeout(() => setRunning((prev) => ({ ...prev, [repo]: false })), 3000);
  }

  return (
    <div className="panel" style={{ marginBottom: 20 }}>
      <div className="panel-header">
        <div>
          <h4 style={{ margin: 0 }}>On-Demand Ingestion</h4>
          <span className="panel-caption">
            Trigger BOM ingestion immediately for a specific GitHub repository
          </span>
        </div>
      </div>
      <div style={{ display: 'grid', gap: 10 }}>
        {REPOS.map(({ repo, bomCount }) => (
          <div key={repo} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 14px', borderRadius: 8,
            background: 'var(--panel-muted)', border: '1px solid var(--border)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontSize: 18 }}>⬡</span>
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>{repo}</div>
                <div className="panel-caption" style={{ fontSize: 11 }}>
                  {bomCount} BOM document{bomCount > 1 ? 's' : ''} · GitHub repository
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {running[repo] ? <RunningSpinner /> : null}
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={!!running[repo]}
                onClick={() => handleRun(repo)}
              >
                ▶ Run now
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardWidgets() {
  const total = MOCK_BOMS.length;
  const totalComponents = MOCK_BOMS.reduce((s, b) => s + b.componentCount, 0);
  const totalVulnLinks = MOCK_BOMS.reduce((s, b) => s + b.vulnerabilityLinks, 0);
  const totalCorrelated = MOCK_BOMS.reduce((s, b) => s + b.correlatedCount, 0);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 20 }}>
      {[
        { label: 'BOM documents', value: total },
        { label: 'Total components', value: totalComponents.toLocaleString() },
        { label: 'Correlated', value: totalCorrelated },
        { label: 'Vulnerability links', value: totalVulnLinks },
        { label: 'Repositories', value: REPOS.length },
      ].map(({ label, value }) => (
        <div key={label} className="panel" style={{ padding: '14px 16px' }}>
          <div className="panel-caption" style={{ marginBottom: 4, fontSize: 11 }}>{label}</div>
          <div style={{ fontSize: 26, fontWeight: 700 }}>{value}</div>
        </div>
      ))}
    </div>
  );
}

export function BomInventoryMock() {
  const [rows, setRows] = React.useState(MOCK_BOMS);
  const [runningRows, setRunningRows] = React.useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = React.useState<string | null>(null);
  const [typeFilter, setTypeFilter] = React.useState('');

  function handleRunRow(id: string) {
    setRunningRows((prev) => new Set(prev).add(id));
    setTimeout(() => {
      setRunningRows((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }, 3000);
  }

  function handleDeleteRow(id: string) {
    setRows((prev) => prev.filter((r) => r.id !== id));
    setConfirmDelete(null);
  }

  const filtered = typeFilter ? rows.filter((r) => r.bomType === typeFilter) : rows;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Delete confirmation modal */}
      {confirmDelete && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 999,
          background: 'rgba(0,0,0,0.45)', display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div className="panel" style={{ padding: 28, maxWidth: 420, width: '90%' }}>
            <h4 style={{ marginBottom: 10 }}>Remove BOM record?</h4>
            <p className="panel-caption" style={{ marginBottom: 20 }}>
              This will remove the BOM record and all linked components. This cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-ghost" onClick={() => setConfirmDelete(null)}>Cancel</button>
              <button type="button" className="btn btn-danger btn-sm" onClick={() => handleDeleteRow(confirmDelete)}>
                Remove
              </button>
            </div>
          </div>
        </div>
      )}

      <DashboardWidgets />
      <OnDemandRepoPanel />

      <div className="panel">
        <div className="panel-header">
          <div>
            <h3>BOM Inventory</h3>
            <span className="panel-caption">
              All ingested BOM records — SBOM, AI BOM, CBOM, and Vendor BOMs
            </span>
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <select className="filter-input" style={{ width: 'auto' }} value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}>
              <option value="">All BOM types</option>
              <option value="SBOM">SBOM</option>
              <option value="AI_BOM">AI BOM</option>
              <option value="CBOM">CBOM</option>
              <option value="VENDOR">Vendor</option>
            </select>
            <button type="button" className="btn btn-secondary btn-sm">Upload BOM</button>
          </div>
        </div>

        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Supplier / Source</th>
                <th>Format</th>
                <th>Support</th>
                <th>Components</th>
                <th>Correlated</th>
                <th>Vuln Links</th>
                <th>Status</th>
                <th>Last Run</th>
                <th>Next Run</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.id}>
                  <td><BomTypeBadge type={row.bomType} /></td>
                  <td>
                    <div style={{ fontWeight: 600 }}>{row.supplier}</div>
                    {row.repo && (
                      <div className="panel-caption" style={{ fontSize: 11 }}>
                        ⬡ {row.repo}
                      </div>
                    )}
                    <div className="panel-caption mono" style={{ fontSize: 10 }}>{row.sourceRef}</div>
                  </td>
                  <td>
                    <div>{row.format}</div>
                    <div className="panel-caption" style={{ fontSize: 11 }}>{row.specFamily}</div>
                  </td>
                  <td><SupportBadge level={row.supportLevel} supported={row.supported} /></td>
                  <td style={{ fontWeight: 600 }}>{row.componentCount}</td>
                  <td>{row.correlatedCount}</td>
                  <td>{row.vulnerabilityLinks}</td>
                  <td><StatusBadge status={row.status} /></td>
                  <td>
                    {runningRows.has(row.id)
                      ? <RunningSpinner />
                      : <span className="panel-caption">{row.lastRunAt ?? '—'}</span>
                    }
                  </td>
                  <td>
                    {row.nextScheduledRun
                      ? <span className="panel-caption">{row.nextScheduledRun}</span>
                      : <span className="panel-caption">—</span>
                    }
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      {row.repo && (
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          title="Run ingestion now"
                          disabled={runningRows.has(row.id)}
                          onClick={() => handleRunRow(row.id)}
                          style={{ padding: '3px 8px', fontSize: 13 }}
                        >
                          ▶
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        title="View BOM detail"
                        style={{ padding: '3px 8px', fontSize: 13 }}
                      >
                        ⊞
                      </button>
                      <button
                        type="button"
                        title="Delete this BOM record"
                        style={{
                          padding: '3px 8px', fontSize: 13, cursor: 'pointer',
                          background: 'none', border: '1px solid var(--border)',
                          borderRadius: 6, color: 'var(--critical)',
                        }}
                        onClick={() => setConfirmDelete(row.id)}
                      >
                        ✕
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="empty-state">
            <p>No BOM records match the current filter.</p>
          </div>
        )}
      </div>
    </div>
  );
}
