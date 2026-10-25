import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, type ApplicationRiskSummary, type BomComponentDetail, type BomComponentSummaryItem } from '../../api/client';
import { cveWorkbenchApi } from '../cve-workbench/api';
import type { Finding } from '../findings/types';
import { timeAgo } from '../../lib/time';
import { pathForVulnRepoView, pathForFindingDetail } from '../../app/routes';

// ── Shared pills / badges ────────────────────────────────────────────────────

function SeverityPill({ severity }: { severity: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: 'status-pill status-failure',
    HIGH:     'status-pill status-warning',
    MEDIUM:   'status-pill status-unknown',
    LOW:      'status-pill status-open',
  };
  return <span className={map[severity ?? ''] ?? 'status-pill'}>{severity ?? '—'}</span>;
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

function BomTypeTag({ type }: { type: string }) {
  const colors: Record<string, string> = {
    SBOM: '#2563eb', AI_BOM: '#0891b2', CBOM: '#7c3aed', VENDOR: '#059669',
  };
  const label = type === 'AI_BOM' ? 'AI BOM' : type;
  const color = colors[type] ?? 'var(--muted)';
  return (
    <span style={{
      display: 'inline-flex', padding: '2px 7px', borderRadius: 999,
      fontSize: 10, fontWeight: 700, letterSpacing: '0.05em',
      color, background: `color-mix(in srgb, ${color} 12%, transparent)`,
      border: `1px solid ${color}40`,
    }}>
      {label}
    </span>
  );
}

function ApplicabilityPill({ state }: { state: string }) {
  const map: Record<string, string> = {
    APPLICABLE:     'status-pill inv-status-applicable',
    NOT_APPLICABLE: 'status-pill status-suppressed',
    UNKNOWN:        'status-pill status-unknown',
  };
  const label: Record<string, string> = {
    APPLICABLE: 'APPLICABLE', NOT_APPLICABLE: 'NOT APPLICABLE', UNKNOWN: 'UNKNOWN',
  };
  return <span className={map[state] ?? 'status-pill'}>{label[state] ?? state}</span>;
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    OPEN:        'status-pill status-open',
    RESOLVED:    'status-pill status-suppressed',
    SUPPRESSED:  'status-pill status-suppressed',
    AUTO_CLOSED: 'status-pill status-auto_closed',
  };
  return <span className={map[status] ?? 'status-pill'}>{status.replace('_', ' ')}</span>;
}

// ── Tab bar ──────────────────────────────────────────────────────────────────

type Tab = 'overview' | 'applications' | 'vulnerabilities' | 'lifecycle' | 'findings';

function TabBar({ active, tabs, onSelect }: {
  active: Tab;
  tabs: { key: Tab; label: string }[];
  onSelect: (t: Tab) => void;
}) {
  return (
    <div style={{ display: 'flex', gap: 0, borderBottom: '2px solid var(--border)', marginBottom: 20 }}>
      {tabs.map(({ key, label }) => (
        <button
          key={key}
          type="button"
          onClick={() => onSelect(key)}
          style={{
            padding: '8px 16px', border: 'none', background: 'none', cursor: 'pointer',
            fontSize: 13, fontWeight: active === key ? 700 : 500,
            color: active === key ? 'var(--accent)' : 'var(--muted)',
            borderBottom: active === key ? '2px solid var(--accent)' : '2px solid transparent',
            marginBottom: -2,
          }}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

// ── Detail row helper ────────────────────────────────────────────────────────

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
      <span style={{ width: 160, flexShrink: 0, fontSize: 11, fontWeight: 600, textTransform: 'uppercase', color: 'var(--muted)', paddingTop: 1 }}>
        {label}
      </span>
      <span style={{ fontSize: 13 }}>{children}</span>
    </div>
  );
}

// ── Stat card helper ─────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="panel" style={{ padding: '12px 16px', textAlign: 'center', minWidth: 90 }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? 'var(--title)' }}>{value}</div>
      <div className="panel-caption" style={{ fontSize: 10 }}>{label}</div>
    </div>
  );
}

// ── Overview tab ─────────────────────────────────────────────────────────────

function OverviewTab({ d }: { d: BomComponentDetail }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="panel" style={{ padding: 16 }}>
        <h4 style={{ margin: '0 0 12px' }}>Details</h4>
        <DetailRow label="Name">{d.packageName}</DetailRow>
        {d.packageGroup && <DetailRow label="Group">{d.packageGroup}</DetailRow>}
        <DetailRow label="Version">{d.version ?? '—'}</DetailRow>
        <DetailRow label="Ecosystem">
          {d.ecosystem ? <span className="status-pill status-auto_closed">{d.ecosystem}</span> : '—'}
        </DetailRow>
        <DetailRow label="License">{d.license ?? '—'}</DetailRow>
        <DetailRow label="Scope">{d.scope ?? '—'}</DetailRow>
        {d.purl && (
          <DetailRow label="PURL">
            <span className="mono" style={{ fontSize: 11, wordBreak: 'break-all' }}>{d.purl}</span>
          </DetailRow>
        )}
        <DetailRow label="BOM types">
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {d.bomTypes.length > 0 ? d.bomTypes.map(t => <BomTypeTag key={t} type={t} />) : '—'}
          </div>
        </DetailRow>
        <DetailRow label="Ingested">{timeAgo(d.ingestedAt)}</DetailRow>
        <DetailRow label="Last observed">{timeAgo(d.lastObservedAt)}</DetailRow>
      </div>

      <div className="panel" style={{ padding: 16 }}>
        <h4 style={{ margin: '0 0 12px' }}>EOL &amp; Lifecycle</h4>
        <DetailRow label="Is EOL">
          {d.isEol
            ? <span className="status-pill status-failure">EOL</span>
            : <span className="status-pill status-suppressed">Active</span>}
        </DetailRow>
        <DetailRow label="EOL date">{d.eolDate ?? '—'}</DetailRow>
        <DetailRow label="Support ends">{d.eolSupportEndDate ?? '—'}</DetailRow>
        <DetailRow label="Support phase">{d.supportPhase ?? '—'}</DetailRow>
        <DetailRow label="EOL slug">{d.eolSlug ?? '—'}</DetailRow>
        <DetailRow label="EOL cycle">{d.eolCycle ?? '—'}</DetailRow>
        <DetailRow label="EOL checked">{d.eolCheckedAt ? timeAgo(d.eolCheckedAt) : '—'}</DetailRow>
      </div>
    </div>
  );
}

// ── Applications tab ─────────────────────────────────────────────────────────

function CveBar({ critical, high, medium, low, total }: {
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

function RiskBar({ score, level }: { score: number; level: string }) {
  const color = level === 'CRITICAL' ? 'var(--critical)'
    : level === 'HIGH' ? 'var(--high)'
    : level === 'MEDIUM' ? '#d88f3d'
    : level === 'LOW' ? 'var(--accent)'
    : 'var(--border)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 999, background: 'var(--border)', overflow: 'hidden', minWidth: 60 }}>
        <div style={{ height: '100%', borderRadius: 999, width: `${Math.min(100, score * 10)}%`, background: color }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, minWidth: 30 }}>{score.toFixed(1)}</span>
    </div>
  );
}

function ApplicationsTab({ d, relatedAssetIds, assetIdToComponentId, onSelectApp }: { d: BomComponentDetail; relatedAssetIds: string[]; assetIdToComponentId: Record<string, string>; onSelectApp?: (app: ApplicationRiskSummary) => void }) {
  const [selectedAssetIds, setSelectedAssetIds] = React.useState<Set<string>>(new Set());
  const [showCreateModal, setShowCreateModal] = React.useState(false);

  const { data: appRisk, isPending, isError } = useQuery({
    queryKey: ['application-risk'],
    queryFn: () => api.getApplicationRisk(),
    staleTime: 60_000,
  });

  // Show all applications that contain a component with the same package (relatedAssetIds includes all assetIds for this purl)
  const relatedSet = new Set(relatedAssetIds.length > 0 ? relatedAssetIds : [d.assetId]);
  const apps = appRisk?.filter(a => relatedSet.has(a.assetId)) ?? [];
  // Fallback: always include the owning asset if nothing else matched
  const app = apps.length > 0 ? null : appRisk?.find(a => a.assetId === d.assetId);

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading application details…</p>
      </div>
    );
  }
  if (isError) {
    return (
      <div className="panel" style={{ padding: 32 }}>
        <p style={{ color: 'var(--critical)' }}>Could not load application details.</p>
      </div>
    );
  }

  const rows = apps.length > 0 ? apps : (app ? [app] : []);

  if (rows.length === 0) {
    return (
      <div className="panel" style={{ padding: 32 }}>
        <p className="panel-caption">No application data available.</p>
      </div>
    );
  }

  const allSelected = rows.length > 0 && rows.every(r => selectedAssetIds.has(r.assetId));

  const toggleAll = () => {
    setSelectedAssetIds(() => {
      if (allSelected) return new Set();
      return new Set(rows.map(r => r.assetId));
    });
  };

  const toggleRow = (assetId: string) => {
    setSelectedAssetIds(prev => {
      const next = new Set(prev);
      if (next.has(assetId)) next.delete(assetId); else next.add(assetId);
      return next;
    });
  };

  const selectedApps = rows.filter(r => selectedAssetIds.has(r.assetId));

  return (
    <>
      <div className="panel">
        {/* Selection toolbar */}
        {selectedAssetIds.size > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'color-mix(in srgb, var(--accent) 6%, transparent)' }}>
            <span style={{ fontSize: 13, color: 'var(--accent)', fontWeight: 600 }}>
              {selectedAssetIds.size} application{selectedAssetIds.size !== 1 ? 's' : ''} selected
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" className="btn btn-secondary btn-sm" onClick={() => setSelectedAssetIds(new Set())}>
                Clear
              </button>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => setShowCreateModal(true)}
                disabled={d.totalCveCount === 0}
              >
                Create Findings for {selectedAssetIds.size} app{selectedAssetIds.size !== 1 ? 's' : ''}
              </button>
            </div>
          </div>
        )}
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                    title="Select all"
                  />
                </th>
                <th>Application</th>
                <th>BOM types</th>
                <th>Criticality</th>
                <th>Components</th>
                <th>Vulnerable</th>
                <th>EOL</th>
                <th>CVEs</th>
                <th>Risk score</th>
                <th>Ingested</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.assetId}
                  style={{
                    cursor: 'pointer',
                    background: selectedAssetIds.has(row.assetId)
                      ? 'color-mix(in srgb, var(--accent) 6%, transparent)'
                      : undefined,
                  }}
                  onClick={() => toggleRow(row.assetId)}
                >
                  <td onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedAssetIds.has(row.assetId)}
                      onChange={() => toggleRow(row.assetId)}
                      style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                    />
                  </td>
                  <td>
                    <div
                      style={{ fontWeight: 600, color: 'var(--accent)', textDecoration: 'underline', cursor: 'pointer' }}
                      onClick={e => { e.stopPropagation(); onSelectApp?.(row); }}
                    >{row.assetName}</div>
                    <div className="mono panel-caption" style={{ fontSize: 10 }}>{row.assetIdentifier}</div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {row.bomTypes.length > 0
                        ? row.bomTypes.map(t => <BomTypeTag key={t} type={t} />)
                        : <span className="panel-caption">—</span>}
                    </div>
                  </td>
                  <td>
                    <span className="status-pill status-auto_closed">{row.businessCriticality}</span>
                  </td>
                  <td style={{ fontWeight: 600 }}>{row.totalComponents}</td>
                  <td>
                    {row.vulnerableComponents > 0
                      ? <span style={{ fontWeight: 700, color: 'var(--high)' }}>{row.vulnerableComponents}</span>
                      : <span className="panel-caption">0</span>}
                  </td>
                  <td>
                    {row.eolComponents > 0
                      ? <span style={{ fontWeight: 700, color: '#d88f3d' }}>{row.eolComponents}</span>
                      : <span className="panel-caption">0</span>}
                  </td>
                  <td>
                    <CveBar
                      critical={row.criticalCveCount}
                      high={row.highCveCount}
                      medium={row.mediumCveCount}
                      low={row.lowCveCount}
                      total={row.totalCveCount}
                    />
                  </td>
                  <td style={{ minWidth: 130 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <RiskPill level={row.riskLevel} />
                      <RiskBar score={row.riskScore} level={row.riskLevel} />
                    </div>
                  </td>
                  <td className="panel-caption" style={{ whiteSpace: 'nowrap', fontSize: 11 }}>
                    {row.lastIngestedAt ? timeAgo(row.lastIngestedAt) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreateModal && (
        <FindingConfigModal
          d={d}
          selectedApps={selectedApps}
          assetIdToComponentId={assetIdToComponentId}
          onClose={() => setShowCreateModal(false)}
          onCreated={() => setShowCreateModal(false)}
        />
      )}
    </>
  );
}

// ── Vulnerabilities tab ───────────────────────────────────────────────────────

function VulnerabilitiesTab({ d }: { d: BomComponentDetail }) {
  const navigate = useNavigate();
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...d.cves].sort((a, b) =>
    (severityOrder[a.severity ?? ''] ?? 9) - (severityOrder[b.severity ?? ''] ?? 9)
  );

  if (sorted.length === 0) {
    return <div className="empty-state"><p>No correlated CVEs for this component.</p></div>;
  }

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>CVE ID</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>EPSS</th>
            <th>Applicability</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(cve => (
            <tr
              key={cve.cveId}
              style={{ cursor: 'pointer' }}
              onClick={() => navigate(pathForVulnRepoView('org-cves', cve.externalId))}
            >
              <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap', color: 'var(--accent)', textDecoration: 'underline' }}>{cve.externalId}</td>
              <td><SeverityPill severity={cve.severity} /></td>
              <td>{cve.cvssScore != null ? cve.cvssScore.toFixed(1) : '—'}</td>
              <td>{cve.epssScore != null ? `${(cve.epssScore * 100).toFixed(2)}%` : '—'}</td>
              <td><ApplicabilityPill state={cve.applicabilityState} /></td>
              <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {cve.title ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── EOL Lifecycle tab ─────────────────────────────────────────────────────────

function LifecycleTab({ d }: { d: BomComponentDetail }) {
  if (!d.eolSlug) {
    return (
      <div className="empty-state">
        <p>No EOL lifecycle data — <code>eolSlug</code> not resolved for this component.</p>
        <p className="panel-caption" style={{ marginTop: 4 }}>
          EOL mapping is resolved automatically by the nightly EOL pipeline.
        </p>
      </div>
    );
  }

  if (d.eolReleases.length === 0) {
    return (
      <div className="empty-state">
        <p>EOL slug <code>{d.eolSlug}</code> is mapped but no release cycles were found.</p>
      </div>
    );
  }

  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            <th>Cycle</th>
            <th>Release date</th>
            <th>Latest version</th>
            <th>Latest release</th>
            <th>Support ends</th>
            <th>EOL date</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {d.eolReleases.map(r => (
            <tr key={r.cycle} style={r.cycle === d.eolCycle ? { background: 'color-mix(in srgb, var(--accent) 8%, transparent)' } : {}}>
              <td style={{ fontWeight: r.cycle === d.eolCycle ? 700 : 500 }}>
                {r.cycle}
                {r.cycle === d.eolCycle && (
                  <span className="status-pill status-auto_closed" style={{ marginLeft: 6, fontSize: 9 }}>current</span>
                )}
                {r.isLts && (
                  <span className="status-pill" style={{ marginLeft: 4, fontSize: 9, background: '#14532d22', color: '#16a34a', border: '1px solid #16a34a40' }}>LTS</span>
                )}
              </td>
              <td>{r.releaseDate ?? '—'}</td>
              <td>{r.latestVersion ?? '—'}</td>
              <td>{r.latestReleaseDate ?? '—'}</td>
              <td>{r.supportEndDate ?? '—'}</td>
              <td>{r.eolDate ?? '—'}</td>
              <td>
                {r.isEol
                  ? <span className="status-pill status-failure">EOL</span>
                  : <span className="status-pill status-suppressed">Active</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Findings tab ─────────────────────────────────────────────────────────────

function FindingsTab({ d, onCountLoaded }: { d: BomComponentDetail; onCountLoaded?: (count: number) => void }) {
  const { data, isPending, isError } = useQuery({
    queryKey: ['findings', 'component', d.packageName, d.ecosystem],
    queryFn: () => api.listFindings({
      packageName: d.packageName,
      ecosystem: d.ecosystem ?? undefined,
      size: 100,
    }),
  });

  React.useEffect(() => {
    if (data) onCountLoaded?.(data.items?.length ?? 0);
  }, [data, onCountLoaded]);

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading findings…</p>
      </div>
    );
  }
  if (isError) {
    return (
      <div className="panel" style={{ padding: 32 }}>
        <p style={{ color: 'var(--critical)' }}>Failed to load findings.</p>
      </div>
    );
  }

  const findings: Finding[] = data?.items ?? [];

  if (findings.length === 0) {
    return (
      <div className="empty-state">
        <p>No findings created for <strong>{d.packageName}</strong>.</p>
      </div>
    );
  }

  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) =>
    (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="panel-caption" style={{ fontSize: 11 }}>
        {findings.length} finding{findings.length !== 1 ? 's' : ''} for {d.packageName}
        {d.ecosystem ? ` (${d.ecosystem})` : ''}
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>CVE</th>
              <th>Asset</th>
              <th>Status</th>
              <th>CVSS / EPSS</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(f => (
              <tr key={f.id} style={{ cursor: 'pointer' }}>
                <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>
                  <Link
                    to={pathForFindingDetail(f.displayId || f.id)}
                    state={{ finding: f }}
                    style={{ color: 'var(--accent)', textDecoration: 'underline' }}
                    onClick={e => e.stopPropagation()}
                  >
                    {f.displayId}
                  </Link>
                </td>
                <td><SeverityPill severity={f.severity} /></td>
                <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                  {f.source ?? '—'}
                </td>
                <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.assetName}
                </td>
                <td><StatusPill status={f.status} /></td>
                <td>
                  <span style={{ fontSize: 11 }}>
                    {f.riskScore != null ? f.riskScore.toFixed(1) : '—'}
                    {f.epss != null && (
                      <span className="panel-caption" style={{ marginLeft: 4 }}>
                        {(f.epss * 100).toFixed(1)}%
                      </span>
                    )}
                  </span>
                </td>
                <td className="panel-caption" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                  {timeAgo(f.firstObservedAt)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Finding Configuration Modal ───────────────────────────────────────────────

function FindingConfigModal({
  d,
  selectedApps,
  assetIdToComponentId = {},
  onClose,
  onCreated,
}: {
  d: BomComponentDetail;
  selectedApps?: ApplicationRiskSummary[];
  assetIdToComponentId?: Record<string, string>;
  onClose: () => void;
  onCreated: (msg?: string) => void;
}) {
  const [title, setTitle] = React.useState(`${d.packageName} remediation`);
  const [priority, setPriority] = React.useState('MEDIUM');
  const [dueDate, setDueDate] = React.useState('');
  const [tags, setTags] = React.useState('');
  const [notes, setNotes] = React.useState('');
  const [selectedCveIds, setSelectedCveIds] = React.useState<Set<string>>(
    () => new Set(d.cves.map(c => c.externalId))
  );
  const queryClient = useQueryClient();

  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sortedCves = [...d.cves].sort((a, b) =>
    (severityOrder[a.severity ?? ''] ?? 9) - (severityOrder[b.severity ?? ''] ?? 9)
  );

  const toggleCve = (externalId: string) => {
    setSelectedCveIds(prev => {
      const next = new Set(prev);
      if (next.has(externalId)) next.delete(externalId); else next.add(externalId);
      return next;
    });
  };

  const mutation = useMutation({
    mutationFn: async () => {
      const cvesToCreate = sortedCves.filter(c => selectedCveIds.has(c.externalId));
      if (cvesToCreate.length === 0) throw new Error('Select at least one CVE.');
      const justification = [
        title.trim() ? `Title: ${title.trim()}` : null,
        `Priority: ${priority}`,
        dueDate ? `Due date: ${dueDate}` : null,
        tags.trim() ? `Tags: ${tags.trim()}` : null,
        notes.trim() ? `Notes: ${notes.trim()}` : null,
        `Created from BOM component: ${d.packageName} ${d.version ?? ''}`.trim(),
        selectedApps && selectedApps.length > 0
          ? `Applications in scope: ${selectedApps.map(a => a.assetName).join(', ')}`
          : null,
      ].filter(Boolean).join('\n');
      // Resolve component IDs for all selected apps; fall back to the single componentId
      const scopedComponentIds = selectedApps && selectedApps.length > 0
        ? selectedApps.map(a => assetIdToComponentId[a.assetId] ?? d.componentId)
        : [d.componentId];
      const applicabilityDecisions = Object.fromEntries(
        scopedComponentIds.map(id => [id, 'APPLICABLE' as const])
      );
      const analystDispositions = Object.fromEntries(
        scopedComponentIds.map(id => [id, 'IMPACTED' as const])
      );
      const results = await Promise.all(
        cvesToCreate.map(cve =>
          cveWorkbenchApi.createManualFindings(cve.externalId, {
            justification,
            componentIds: scopedComponentIds,
            componentApplicabilityDecisions: applicabilityDecisions,
            componentAnalystDispositions: analystDispositions,
          })
        )
      );
      return results;
    },
    onSuccess: (results) => {
      const created = results.reduce((s, r) => s + r.createdCount + r.reopenedCount, 0);
      const already = results.reduce((s, r) => s + r.alreadyOpenCount, 0);
      void queryClient.invalidateQueries({ queryKey: ['findings', 'component', d.packageName] });
      onCreated(created > 0
        ? `Created or reopened ${created} finding(s).${already > 0 ? ` ${already} already open.` : ''}`
        : `${already} finding(s) already open — nothing new to create.`
      );
      onClose();
    },
  });

  return (
    <>
      {/* backdrop — click to close */}
      <div
        style={{ position: 'fixed', inset: 0, background: 'rgba(15,23,42,0.45)', zIndex: 119 }}
        role="presentation"
        onClick={onClose}
      />

      {/* right-side drawer */}
      <aside
        className="panel cve-findings-config-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Create Findings"
      >
        {/* Header */}
        <div className="cve-findings-modal-header">
          <div>
            <h3 style={{ margin: '0 0 4px', fontSize: 17, fontWeight: 700 }}>Create Findings</h3>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--muted)' }}>
              Configure scope and metadata for <strong>{d.packageName}</strong>.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            style={{
              background: 'color-mix(in srgb, var(--critical) 10%, transparent)',
              border: 'none',
              borderRadius: 8,
              width: 32,
              height: 32,
              cursor: 'pointer',
              fontSize: 16,
              color: 'var(--critical)',
              flexShrink: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >✕</button>
        </div>

        {/* Scrollable body */}
        <div className="cve-findings-modal-grid">
          {mutation.isError && (
            <div className="notice error" style={{ marginBottom: 12 }}>
              {mutation.error instanceof Error ? mutation.error.message : 'Failed to create findings.'}
            </div>
          )}

          {/* Applications in scope */}
          {selectedApps && selectedApps.length > 0 && (
            <div>
              <div className="cw-label" style={{ marginBottom: 8 }}>Applications in scope</div>
              <div style={{ border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden', background: 'var(--panel)' }}>
                {selectedApps.map((a, i) => (
                  <div
                    key={a.assetId}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '8px 14px',
                      borderBottom: i < selectedApps.length - 1 ? '1px solid var(--border)' : 'none',
                    }}
                  >
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 13 }}>{a.assetName}</div>
                      <div className="mono panel-caption" style={{ fontSize: 10 }}>{a.assetIdentifier}</div>
                    </div>
                    <RiskPill level={a.riskLevel} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Finding title — full width */}
          <div className="cw-field">
            <label className="cw-label">Finding title</label>
            <input className="cw-input" value={title} onChange={e => setTitle(e.target.value)} />
          </div>

          {/* Priority + Due date — 2-col */}
          <div className="cve-findings-modal-row">
            <div className="cw-field">
              <label className="cw-label">Priority</label>
              <select className="cw-input" value={priority} onChange={e => setPriority(e.target.value)}>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>
            <div className="cw-field">
              <label className="cw-label">Due date</label>
              <input type="date" className="cw-input" value={dueDate} onChange={e => setDueDate(e.target.value)} />
            </div>
          </div>

          {/* Tags — full width */}
          <div className="cw-field">
            <label className="cw-label">Tags</label>
            <input className="cw-input" placeholder="e.g. internet-facing, patching" value={tags} onChange={e => setTags(e.target.value)} />
          </div>

          {/* CVEs */}
          {sortedCves.length > 0 && (
            <div>
              <div className="cw-label" style={{ marginBottom: 8 }}>CVEs — all selected by default</div>
              <div style={{ border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden', background: 'var(--panel)' }}>
                {sortedCves.map((cve, i) => (
                  <label
                    key={cve.externalId}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
                      cursor: 'pointer',
                      borderBottom: i < sortedCves.length - 1 ? '1px solid var(--border)' : 'none',
                      background: selectedCveIds.has(cve.externalId)
                        ? 'color-mix(in srgb, var(--accent) 6%, transparent)'
                        : 'transparent',
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedCveIds.has(cve.externalId)}
                      onChange={() => toggleCve(cve.externalId)}
                      style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                    />
                    <span className="mono" style={{ fontWeight: 600, flex: 1, fontSize: 13 }}>{cve.externalId}</span>
                    <SeverityPill severity={cve.severity} />
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Notes */}
          <div className="cw-field">
            <label className="cw-label">Notes</label>
            <textarea
              className="cw-input cw-textarea"
              placeholder="Describe remediation approach or ticket creation context…"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              style={{ minHeight: 96 }}
            />
          </div>
        </div>

        {/* Footer */}
        <div className="cve-findings-modal-actions" style={{ padding: '14px 20px', flexShrink: 0 }}>
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={mutation.isPending}>
            Close
          </button>
          <button
            type="button"
            className="btn btn-primary"
            disabled={mutation.isPending || selectedCveIds.size === 0}
            onClick={() => mutation.mutate()}
          >
            {mutation.isPending ? 'Creating…' : `Create Findings (${selectedCveIds.size * (selectedApps && selectedApps.length > 0 ? selectedApps.length : 1)})`}
          </button>
        </div>
      </aside>
    </>
  );
}

// ── Header summary stats ──────────────────────────────────────────────────────

function HeaderStats({ d }: { d: BomComponentDetail }) {
  return (
    <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
      <StatCard label="Total CVEs"   value={d.totalCveCount}    color={d.totalCveCount > 0 ? 'var(--title)' : undefined} />
      <StatCard label="Critical"     value={d.criticalCveCount} color={d.criticalCveCount > 0 ? 'var(--critical)' : undefined} />
      <StatCard label="High"         value={d.highCveCount}     color={d.highCveCount > 0 ? 'var(--high)' : undefined} />
      <StatCard label="EOL Releases" value={d.eolReleases.length} />
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export function BomComponentDetailPanel({
  componentId,
  seed,
  relatedAssetIds = [],
  assetIdToComponentId = {},
  onClose,
  onSelectApp,
}: {
  componentId: string;
  seed: BomComponentSummaryItem;
  relatedAssetIds?: string[];
  assetIdToComponentId?: Record<string, string>;
  onClose: () => void;
  onSelectApp?: (app: ApplicationRiskSummary) => void;
}) {
  const [activeTab, setActiveTab] = React.useState<Tab>('overview');
  const [liveFindingCount, setLiveFindingCount] = React.useState<number>(seed.findingCount);

  const { data, isPending, isError } = useQuery({
    queryKey: ['bom-component-detail', componentId],
    queryFn: () => api.getBomComponentDetail(componentId),
  });

  const d = data;

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview',        label: 'Overview' },
    { key: 'applications',    label: `Applications (${relatedAssetIds.length > 0 ? relatedAssetIds.length : 1})` },
    { key: 'vulnerabilities', label: `Vulnerabilities (${d?.totalCveCount ?? seed.totalCveCount})` },
    { key: 'lifecycle',       label: `EOL Lifecycle${d?.eolReleases.length ? ` (${d.eolReleases.length})` : ''}` },
    { key: 'findings',        label: `Findings${liveFindingCount > 0 ? ` (${liveFindingCount})` : ''}` },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {/* Back nav */}
      <div style={{ marginBottom: 16 }}>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={onClose}
          style={{ fontSize: 12 }}
        >
          ← Back to BOM Components
        </button>
      </div>

      {/* Header card */}
      <div className="panel" style={{ padding: '20px 24px', marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 4 }}>
              <h2 style={{ margin: 0, fontSize: 22 }}>{seed.packageName}</h2>
              {seed.version && (
                <span style={{ fontSize: 16, color: 'var(--muted)', fontWeight: 400 }}>{seed.version}</span>
              )}
              <RiskPill level={seed.riskLevel} />
            </div>
            {seed.purl && (
              <div className="mono panel-caption" style={{ fontSize: 11, marginBottom: 8 }}>{seed.purl}</div>
            )}
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              {seed.bomTypes.map(t => <BomTypeTag key={t} type={t} />)}
              {seed.ecosystem && (
                <span className="status-pill status-auto_closed">{seed.ecosystem}</span>
              )}
              {seed.isEol && <span className="status-pill status-failure">EOL</span>}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 10 }}>
            {d && <HeaderStats d={d} />}
          </div>
        </div>
      </div>

      {/* Loading / error for detail fetch */}
      {isPending && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--muted)', fontSize: 13, marginBottom: 12 }}>
          <div className="loading-spinner" style={{ width: 14, height: 14 }} />
          Loading details…
        </div>
      )}
      {isError && (
        <div style={{ color: 'var(--critical)', fontSize: 13, marginBottom: 12 }}>
          Failed to load component details.
        </div>
      )}

      {/* Tabs */}
      {d && (
        <>
          <TabBar active={activeTab} tabs={tabs} onSelect={setActiveTab} />
          {activeTab === 'overview'        && <OverviewTab d={d} />}
          {activeTab === 'applications'    && <ApplicationsTab d={d} relatedAssetIds={relatedAssetIds} assetIdToComponentId={assetIdToComponentId} onSelectApp={onSelectApp} />}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesTab d={d} />}
          {activeTab === 'lifecycle'       && <LifecycleTab d={d} />}
          {activeTab === 'findings'        && <FindingsTab d={d} onCountLoaded={setLiveFindingCount} />}
        </>
      )}
    </div>
  );
}
