import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api, type ApplicationCveItem, type ApplicationRiskSummary, type BomComponentSummaryItem } from '../../api/client';
import { cveWorkbenchApi } from '../cve-workbench/api';
import { timeAgo } from '../../lib/time';

// ── Shared pills / helpers ────────────────────────────────────────────────────

function BomTypeBadge({ type }: { type: string }) {
  const label = type === 'AI_BOM' ? 'AI BOM' : type;
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
      {label}
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

function SeverityPill({ severity }: { severity: string | null }) {
  const map: Record<string, string> = {
    CRITICAL: 'status-pill status-failure',
    HIGH:     'status-pill status-warning',
    MEDIUM:   'status-pill status-unknown',
    LOW:      'status-pill status-open',
  };
  return <span className={map[severity ?? ''] ?? 'status-pill'}>{severity ?? '—'}</span>;
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

function StatCard({ label, value, color }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="panel" style={{ padding: '12px 16px', textAlign: 'center', minWidth: 90 }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: color ?? 'var(--title)' }}>{value}</div>
      <div className="panel-caption" style={{ fontSize: 10 }}>{label}</div>
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────────

type Tab = 'overview' | 'depends-on' | 'vulnerabilities' | 'findings';

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

// ── Overview tab ──────────────────────────────────────────────────────────────

function OverviewTab({ app }: { app: ApplicationRiskSummary }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      {/* Left — app details */}
      <div className="panel" style={{ padding: 16 }}>
        <h4 style={{ margin: '0 0 12px' }}>Application Details</h4>
        <DetailRow label="Name">{app.assetName}</DetailRow>
        <DetailRow label="Identifier">
          <span className="mono" style={{ fontSize: 11 }}>{app.assetIdentifier}</span>
        </DetailRow>
        <DetailRow label="Business criticality">
          <span className="status-pill status-auto_closed">{app.businessCriticality}</span>
        </DetailRow>
        <DetailRow label="BOM types">
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {app.bomTypes.length > 0
              ? app.bomTypes.map(t => <BomTypeBadge key={t} type={t} />)
              : '—'}
          </div>
        </DetailRow>
        <DetailRow label="Last ingested">
          {app.lastIngestedAt ? timeAgo(app.lastIngestedAt) : '—'}
        </DetailRow>
      </div>

      {/* Right — risk summary */}
      <div className="panel" style={{ padding: 16 }}>
        <h4 style={{ margin: '0 0 12px' }}>Risk Summary</h4>
        <DetailRow label="Risk level"><RiskPill level={app.riskLevel} /></DetailRow>
        <DetailRow label="Risk score">
          <div style={{ width: '100%' }}>
            <RiskBarInline score={app.riskScore} level={app.riskLevel} />
          </div>
        </DetailRow>
        <DetailRow label="Total components">{app.totalComponents}</DetailRow>
        <DetailRow label="Vulnerable">
          {app.vulnerableComponents > 0
            ? <span style={{ fontWeight: 700, color: 'var(--high)' }}>{app.vulnerableComponents}</span>
            : '0'}
        </DetailRow>
        <DetailRow label="EOL components">
          {app.eolComponents > 0
            ? <span style={{ fontWeight: 700, color: '#d88f3d' }}>{app.eolComponents}</span>
            : '0'}
        </DetailRow>
        <DetailRow label="Critical CVEs">
          {app.criticalCveCount > 0
            ? <span style={{ fontWeight: 700, color: 'var(--critical)' }}>{app.criticalCveCount}</span>
            : '0'}
        </DetailRow>
        <DetailRow label="High CVEs">
          {app.highCveCount > 0
            ? <span style={{ fontWeight: 700, color: 'var(--high)' }}>{app.highCveCount}</span>
            : '0'}
        </DetailRow>
        <DetailRow label="Medium CVEs">{app.mediumCveCount}</DetailRow>
        <DetailRow label="Low CVEs">{app.lowCveCount}</DetailRow>
      </div>
    </div>
  );
}

// ── Depends On tab ────────────────────────────────────────────────────────────

function DependsOnTab({ app }: { app: ApplicationRiskSummary }) {
  const [query, setQuery] = React.useState('');
  const [riskFilter, setRiskFilter] = React.useState('');
  const [eolFilter, setEolFilter] = React.useState(false);

  const { data, isPending, isError } = useQuery({
    queryKey: ['bom-components'],
    queryFn: () => api.listBomComponents(),
    staleTime: 60_000,
  });

  const allComponents = data ?? [];
  const appComponents = allComponents.filter(c => c.assetId === app.assetId);

  const filtered = appComponents.filter(c => {
    if (query && !c.packageName.toLowerCase().includes(query.toLowerCase())) return false;
    if (riskFilter && c.riskLevel !== riskFilter) return false;
    if (eolFilter && !c.isEol) return false;
    return true;
  });

  const vulnerableCount = appComponents.filter(c => c.totalCveCount > 0).length;
  const eolCount = appComponents.filter(c => c.isEol).length;

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading components…</p>
      </div>
    );
  }
  if (isError) {
    return <div className="panel" style={{ padding: 32 }}><p style={{ color: 'var(--critical)' }}>Failed to load components.</p></div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Summary bar */}
      <div style={{ display: 'flex', gap: 12 }}>
        <StatCard label="Total" value={appComponents.length} />
        <StatCard label="Vulnerable" value={vulnerableCount} color={vulnerableCount > 0 ? 'var(--high)' : undefined} />
        <StatCard label="EOL" value={eolCount} color={eolCount > 0 ? '#d88f3d' : undefined} />
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          className="filter-input"
          placeholder="Filter component…"
          value={query}
          onChange={e => setQuery(e.target.value)}
          style={{ flex: '1 1 180px', minWidth: 140 }}
        />
        <select className="filter-input" style={{ width: 'auto' }} value={riskFilter} onChange={e => setRiskFilter(e.target.value)}>
          <option value="">All risk levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
          <option value="NONE">None</option>
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, cursor: 'pointer' }}>
          <input type="checkbox" checked={eolFilter} onChange={e => setEolFilter(e.target.checked)} />
          EOL only
        </label>
        {(query || riskFilter || eolFilter) && (
          <button type="button" className="btn btn-secondary btn-sm"
            onClick={() => { setQuery(''); setRiskFilter(''); setEolFilter(false); }}>
            Clear
          </button>
        )}
      </div>

      <div className="panel-caption" style={{ fontSize: 11 }}>
        Showing {filtered.length} of {appComponents.length} components
      </div>

      {appComponents.length === 0 ? (
        <div className="empty-state"><p>No components found for this application.</p></div>
      ) : filtered.length === 0 ? (
        <div className="empty-state"><p>No components match the current filters.</p></div>
      ) : (
        <div className="panel">
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Classifier</th>
                  <th>Version</th>
                  <th>Declared license</th>
                  <th>PURL</th>
                  <th>CVEs</th>
                  <th>Risk</th>
                  <th>EOL</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(c => (
                  <tr key={c.componentId}>
                    <td style={{ fontWeight: 600 }}>{c.packageName}</td>
                    <td>
                      {c.ecosystem
                        ? <span className="status-pill status-auto_closed">{c.ecosystem}</span>
                        : <span className="panel-caption">—</span>}
                    </td>
                    <td className="mono">{c.version ?? '—'}</td>
                    <td>{c.license ?? '—'}</td>
                    <td>
                      {c.purl
                        ? <span className="mono panel-caption" style={{ fontSize: 10 }}>{c.purl}</span>
                        : '—'}
                    </td>
                    <td>
                      {c.totalCveCount > 0 ? (
                        <div style={{ display: 'flex', gap: 4 }}>
                          <span style={{ fontWeight: 600 }}>{c.totalCveCount}</span>
                          {c.criticalCveCount > 0 && <span style={{ color: 'var(--critical)', fontSize: 11 }}>{c.criticalCveCount}C</span>}
                          {c.highCveCount > 0 && <span style={{ color: 'var(--high)', fontSize: 11 }}>{c.highCveCount}H</span>}
                        </div>
                      ) : <span className="panel-caption">—</span>}
                    </td>
                    <td><RiskPill level={c.riskLevel} /></td>
                    <td>
                      {c.isEol
                        ? <span className="status-pill status-failure">EOL</span>
                        : <span className="panel-caption">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Vulnerabilities tab ───────────────────────────────────────────────────────

function VulnerabilitiesTab({ app }: { app: ApplicationRiskSummary }) {
  const navigate = useNavigate();
  const { data: cves, isPending, isError } = useQuery<ApplicationCveItem[]>({
    queryKey: ['app-cves', app.assetId],
    queryFn: () => api.getApplicationCves(app.assetId),
  });

  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...(cves ?? [])].sort((a, b) =>
    (severityOrder[a.severity ?? ''] ?? 9) - (severityOrder[b.severity ?? ''] ?? 9)
  );

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const c of sorted) {
    const s = c.severity?.toUpperCase() ?? '';
    if (s in counts) counts[s as keyof typeof counts]++;
  }

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading vulnerabilities…</p>
      </div>
    );
  }
  if (isError) {
    return <div className="panel" style={{ padding: 32 }}><p style={{ color: 'var(--critical)' }}>Failed to load vulnerabilities.</p></div>;
  }

  if (sorted.length === 0) {
    return (
      <div className="empty-state">
        <p>No CVEs correlated for <strong>{app.assetName}</strong>.</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 12 }}>
        <StatCard label="Critical" value={counts.CRITICAL} color={counts.CRITICAL > 0 ? 'var(--critical)' : undefined} />
        <StatCard label="High"     value={counts.HIGH}     color={counts.HIGH > 0 ? 'var(--high)' : undefined} />
        <StatCard label="Medium"   value={counts.MEDIUM}   color={counts.MEDIUM > 0 ? '#d88f3d' : undefined} />
        <StatCard label="Low"      value={counts.LOW} />
      </div>
      <div className="panel">
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Severity</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Matched Software</th>
                <th>Version</th>
                <th>Last Evaluated</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map(c => (
                <tr key={c.vulnerabilityId}>
                  <td>
                    <button
                      type="button"
                      className="mono"
                      onClick={() => navigate(`/vuln-repo/org-cves/${encodeURIComponent(c.externalId)}`)}
                      style={{ fontWeight: 600, color: 'var(--accent)', background: 'none', border: 'none', padding: 0, cursor: 'pointer', textDecoration: 'underline' }}
                    >
                      {c.externalId}
                    </button>
                  </td>
                  <td><SeverityPill severity={c.severity ?? 'UNKNOWN'} /></td>
                  <td>{c.cvssScore != null ? c.cvssScore.toFixed(1) : '—'}</td>
                  <td>{c.epssScore != null ? `${(c.epssScore * 100).toFixed(2)}%` : '—'}</td>
                  <td style={{ fontWeight: 500 }}>{c.packageName}</td>
                  <td className="mono">{c.version ?? '—'}</td>
                  <td className="panel-caption">{c.lastEvaluatedAt ? timeAgo(c.lastEvaluatedAt) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Findings tab ──────────────────────────────────────────────────────────────

function FindingsTab({ app }: { app: ApplicationRiskSummary }) {
  const { data, isPending, isError } = useQuery({
    queryKey: ['findings', 'app-findings', app.assetId],
    queryFn: () => api.listFindings({ assetName: app.assetName, size: 200 }),
  });

  const findings = data?.items ?? [];
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) =>
    (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9)
  );

  if (isPending) {
    return (
      <div className="panel" style={{ padding: 40, textAlign: 'center' }}>
        <div className="loading-spinner" />
        <p className="panel-caption" style={{ marginTop: 12 }}>Loading findings…</p>
      </div>
    );
  }
  if (isError) {
    return <div className="panel" style={{ padding: 32 }}><p style={{ color: 'var(--critical)' }}>Failed to load findings.</p></div>;
  }
  if (findings.length === 0) {
    return <div className="empty-state"><p>No findings for <strong>{app.assetName}</strong>.</p></div>;
  }

  return (
    <div className="panel">
      <div className="panel-caption" style={{ padding: '0 0 10px', fontSize: 11 }}>
        {findings.length} finding{findings.length !== 1 ? 's' : ''}
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>CVE</th>
              <th>Component</th>
              <th>Version</th>
              <th>Status</th>
              <th>EPSS</th>
              <th>First seen</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(f => (
              <tr key={f.id}>
                <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap' }}>{f.displayId}</td>
                <td>
                  <span className={`status-pill ${f.severity === 'CRITICAL' ? 'status-failure' : f.severity === 'HIGH' ? 'status-warning' : f.severity === 'MEDIUM' ? 'status-unknown' : 'status-open'}`}>
                    {f.severity}
                  </span>
                </td>
                <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{f.source}</td>
                <td style={{ fontWeight: 500 }}>{f.packageName}</td>
                <td className="mono">{f.packageVersion}</td>
                <td>
                  <span className={`status-pill ${f.status === 'OPEN' ? 'status-open' : f.status === 'RESOLVED' ? 'status-suppressed' : 'status-auto_closed'}`}>
                    {f.status.replace('_', ' ')}
                  </span>
                </td>
                <td>{f.epss != null ? `${(f.epss * 100).toFixed(2)}%` : '—'}</td>
                <td className="panel-caption" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{timeAgo(f.firstObservedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Main panel ────────────────────────────────────────────────────────────────

export function ApplicationDetailPanel({
  app,
  onBack,
}: {
  app: ApplicationRiskSummary;
  onBack: () => void;
}) {
  const [activeTab, setActiveTab] = React.useState<Tab>('overview');
  const [createMsg, setCreateMsg] = React.useState<string | null>(null);
  const queryClient = useQueryClient();

  // Pre-fetch component count from cached query
  const { data: components } = useQuery({
    queryKey: ['bom-components'],
    queryFn: () => api.listBomComponents(),
    staleTime: 60_000,
  });
  const appComponents = (components ?? []).filter((c: BomComponentSummaryItem) => c.assetId === app.assetId);

  // Pre-fetch CVEs (also used by VulnerabilitiesTab via same queryKey)
  const { data: appCves } = useQuery<ApplicationCveItem[]>({
    queryKey: ['app-cves', app.assetId],
    queryFn: () => api.getApplicationCves(app.assetId),
    staleTime: 60_000,
  });

  const createFindingsMutation = useMutation({
    mutationFn: async () => {
      const cves = appCves ?? [];
      if (cves.length === 0) throw new Error('No CVEs to create findings for.');

      // Group component IDs by CVE externalId
      const cveComponentMap = new Map<string, string[]>();
      for (const c of cves) {
        const existing = cveComponentMap.get(c.externalId) ?? [];
        if (!existing.includes(c.componentId)) existing.push(c.componentId);
        cveComponentMap.set(c.externalId, existing);
      }

      const results = await Promise.all(
        Array.from(cveComponentMap.entries()).map(([externalId, componentIds]) => {
          const componentApplicabilityDecisions: Record<string, 'APPLICABLE'> =
            Object.fromEntries(componentIds.map(id => [id, 'APPLICABLE']));
          const componentAnalystDispositions: Record<string, 'IMPACTED'> =
            Object.fromEntries(componentIds.map(id => [id, 'IMPACTED']));
          return cveWorkbenchApi.createManualFindings(externalId, {
            justification: `Created from application: ${app.assetName}`,
            componentIds,
            componentApplicabilityDecisions,
            componentAnalystDispositions,
          });
        })
      );
      return results;
    },
    onSuccess: (results) => {
      const created = results.reduce((s, r) => s + r.createdCount + r.reopenedCount, 0);
      const alreadyOpen = results.reduce((s, r) => s + r.alreadyOpenCount, 0);
      setCreateMsg(
        created > 0
          ? `Created or reopened ${created} finding(s). ${alreadyOpen > 0 ? `${alreadyOpen} already open.` : ''}`
          : `${alreadyOpen} finding(s) already open — nothing new to create.`
      );
      void queryClient.invalidateQueries({ queryKey: ['findings', 'app-findings', app.assetId] });
    },
    onError: (err) => {
      setCreateMsg(err instanceof Error ? err.message : 'Failed to create findings.');
    },
  });

  const tabs: { key: Tab; label: string }[] = [
    { key: 'overview',        label: 'Overview' },
    { key: 'depends-on',      label: `Depends on (${appComponents.length || app.totalComponents})` },
    { key: 'vulnerabilities', label: `Vulnerabilities (${app.totalCveCount})` },
    { key: 'findings',        label: 'Findings' },
  ];

  return (
    <div className="page-grid" style={{ gap: 0 }}>
      {/* Back nav */}
      <div style={{ marginBottom: 16 }}>
        <button type="button" className="btn btn-secondary btn-sm" onClick={onBack} style={{ fontSize: 12 }}>
          ← Back
        </button>
      </div>

      {/* Header */}
      <div className="panel" style={{ padding: '20px 24px', marginBottom: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 4 }}>
              <h2 style={{ margin: 0, fontSize: 22 }}>{app.assetName}</h2>
              <span className={`status-pill ${
                app.riskLevel === 'CRITICAL' ? 'status-failure' :
                app.riskLevel === 'HIGH'     ? 'status-warning' :
                app.riskLevel === 'MEDIUM'   ? 'status-unknown' :
                app.riskLevel === 'LOW'      ? 'status-open'    : 'status-suppressed'
              }`}>{app.riskLevel}</span>
            </div>
            <div className="mono panel-caption" style={{ fontSize: 11, marginBottom: 8 }}>
              {app.assetIdentifier}
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
              {app.bomTypes.map(t => <BomTypeBadge key={t} type={t} />)}
              <span className="status-pill status-auto_closed">{app.businessCriticality}</span>
              {app.lastIngestedAt && (
                <span className="panel-caption" style={{ fontSize: 11 }}>
                  Ingested {timeAgo(app.lastIngestedAt)}
                </span>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 12 }}>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <StatCard label="Components"  value={app.totalComponents} />
              <StatCard label="Vulnerable"  value={app.vulnerableComponents}  color={app.vulnerableComponents > 0 ? 'var(--high)' : undefined} />
              <StatCard label="EOL"         value={app.eolComponents}          color={app.eolComponents > 0 ? '#d88f3d' : undefined} />
              <StatCard label="CVEs"        value={app.totalCveCount}          color={app.totalCveCount > 0 ? 'var(--critical)' : undefined} />
            </div>
            {app.totalCveCount > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                <button
                  type="button"
                  className="btn btn-primary btn-sm"
                  disabled={createFindingsMutation.isPending || (appCves ?? []).length === 0}
                  onClick={() => { setCreateMsg(null); createFindingsMutation.mutate(); }}
                >
                  {createFindingsMutation.isPending ? 'Creating…' : 'Create Findings'}
                </button>
                {createMsg && (
                  <span style={{ fontSize: 11, color: createFindingsMutation.isError ? 'var(--critical)' : 'var(--success, #16a34a)', maxWidth: 280, textAlign: 'right' }}>
                    {createMsg}
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      <TabBar active={activeTab} tabs={tabs} onSelect={setActiveTab} />

      {activeTab === 'overview'        && <OverviewTab app={app} />}
      {activeTab === 'depends-on'      && <DependsOnTab app={app} />}
      {activeTab === 'vulnerabilities' && <VulnerabilitiesTab app={app} />}
      {activeTab === 'findings'        && <FindingsTab app={app} />}
    </div>
  );
}
