import { AlarmClock, ArrowRight, Bug, Flame, PackageX, Server, ShieldAlert, Target } from 'lucide-react';
import {
  CRITICAL_ASSETS, CRITICAL_CVES, EXEC_KPIS, GRID_EXPOSURE, INSIGHTS, REMEDIATION, TOP_SOFTWARE,
} from '../data';
import { Badge, Card, PageHeader, StatTile } from '../components/primitives';
import { EmptyState, FreshnessStatus, Skeleton } from '../components/feedback';
import { usePreview } from '../previewContext';

// Reference for ExposureDashboardPage. Every panel, label, caption and drill-down
// below exists on the live page; only presentation changes.

const fmt = (n: number) => n.toLocaleString();
const pct = (v: number, t: number) => (t > 0 ? Math.round((v / t) * 100) : 0);

function band(count: number, max: number): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (count === 0) return 'none';
  const r = count / max;
  return r > 0.75 ? 'critical' : r > 0.45 ? 'high' : r > 0.2 ? 'medium' : 'low';
}

function GridExposure({ onNavigate }: { onNavigate: (route: string) => void }) {
  const max = Math.max(...GRID_EXPOSURE.flatMap((r) => [r.critical, r.high, r.medium, r.low]));
  const cols = ['critical', 'high', 'medium', 'low'] as const;
  return (
    <Card title="Grid Exposure" subtitle="Open findings across your Scout Grid, by asset domain and severity">
      <div className="dp-table-scroll">
        <table className="dp-heatmap">
          <thead>
            <tr>
              <th>Asset Domain</th>
              {cols.map((c) => <th key={c}>{c[0].toUpperCase() + c.slice(1)}</th>)}
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {GRID_EXPOSURE.map((row) => (
              <tr key={row.domain}>
                <td className="dp-heatmap-label">{row.domain}</td>
                {cols.map((c) => (
                  <td key={c}>
                    <button
                      type="button"
                      className={`dp-heat dp-heat--${c} dp-heat-band--${band(row[c], max)}`}
                      disabled={row[c] === 0}
                      onClick={() => onNavigate('/findings')}
                    >
                      {fmt(row[c])}
                    </button>
                  </td>
                ))}
                <td className="dp-heatmap-total">{fmt(row.critical + row.high + row.medium + row.low)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function RemediationProgress({ onNavigate }: { onNavigate: (route: string) => void }) {
  const r = REMEDIATION;
  const total = r.unresolved + r.inProgress + r.resolved + r.accepted;
  const bars = [
    { label: 'Unresolved', value: r.unresolved, tone: 'critical' },
    { label: 'In Progress', value: r.inProgress, tone: 'warning' },
    { label: 'Resolved', value: r.resolved, tone: 'success' },
    { label: 'Accepted Risk', value: r.accepted, tone: 'neutral' },
  ];
  const sev = [
    { label: 'Critical', value: 84, tone: 'critical' },
    { label: 'High', value: 312, tone: 'high' },
    { label: 'Medium', value: 586, tone: 'medium' },
    { label: 'Low', value: 241, tone: 'low' },
  ];
  const maxSev = Math.max(...sev.map((s) => s.value));
  return (
    <Card title="Remediation Progress" subtitle="Critical CVE finding status breakdown">
      <div className="dp-stack-bar" aria-hidden="true">
        {bars.map((b) => <span key={b.label} className={`dp-fill--${b.tone}`} style={{ width: `${pct(b.value, total)}%` }} />)}
      </div>
      <div className="dp-rows">
        {bars.map((b) => (
          <button key={b.label} type="button" className="dp-row-btn" onClick={() => onNavigate('/findings')}>
            <span className={`dp-swatch dp-swatch--${b.tone}`} />
            <span className="dp-row-label">{b.label}</span>
            <span className="dp-muted dp-num">{pct(b.value, total)}%</span>
            <strong className="dp-num">{fmt(b.value)}</strong>
          </button>
        ))}
      </div>
      <div className="dp-score-split">
        <div className="dp-score">
          <div className="dp-score-ring" style={{ '--dp-score': `${r.securityScore}%` } as React.CSSProperties}>
            <span>{r.securityScore}</span>
          </div>
          <div>
            <strong>Security Score</strong>
            <span className="dp-muted">/ 100 · avg risk {r.avgRisk.toFixed(1)}</span>
          </div>
        </div>
        <div className="dp-sev-rows">
          {sev.map((s) => (
            <button key={s.label} type="button" className="dp-sev-row" onClick={() => onNavigate('/findings')}>
              <span>{s.label}</span>
              <span className="dp-bar-track"><span className={`dp-bar-fill dp-fill--${s.tone}`} style={{ width: `${pct(s.value, maxSev)}%` }} /></span>
              <strong className="dp-num">{fmt(s.value)}</strong>
            </button>
          ))}
        </div>
      </div>
    </Card>
  );
}

function LoadingDashboard() {
  return (
    <div className="dp-page" aria-busy="true" aria-label="Exposure dashboard">
      <div className="dp-kpi-grid">{Array.from({ length: 6 }, (_, i) => <div key={i} className="dp-kpi static"><Skeleton width="60%" /><Skeleton width="40%" height={24} /><Skeleton width="70%" /></div>)}</div>
      <div className="dp-card"><Skeleton width="30%" height={14} /><div style={{ height: 12 }} /><Skeleton height={160} radius={8} /></div>
    </div>
  );
}

export function OverviewPage({ onNavigate }: { onNavigate: (route: string) => void }) {
  const { loading } = usePreview();
  if (loading) return <LoadingDashboard />;
  const k = EXEC_KPIS;
  const maxAssets = Math.max(...TOP_SOFTWARE.map((s) => s.assets));

  return (
    <div className="dp-page">
      <PageHeader
        eyebrow="Enterprise Vulnerability Operations"
        title="Exposure Dashboard"
        meta={<FreshnessStatus updatedAt="Oct 24, 2026, 10:46 AM" />}
      />

      <div className="dp-kpi-grid">
        <StatTile label="Critical Findings" value={fmt(k.criticalFindings)} sub="Active open findings" tone="critical" icon={<Flame size={14} />} onClick={() => onNavigate('/findings')} />
        <StatTile label="Open Findings" value={fmt(k.openFindings)} sub="All severities" tone="warning" icon={<ShieldAlert size={14} />} onClick={() => onNavigate('/findings')} />
        <StatTile label="Impacted CVEs" value={fmt(k.impacted)} sub={`${fmt(k.impactedCritical)} critical · ${fmt(k.impactedHigh)} high`} tone="critical" icon={<Bug size={14} />} onClick={() => onNavigate('/x/vuln-repo')} />
        <StatTile label="CISA KEV Exposure" value={fmt(k.kevImpacted)} sub="Active exploits in the wild" tone="critical" icon={<Target size={14} />} onClick={() => onNavigate('/x/vuln-repo')} />
        <StatTile label="Needs Attention" value={fmt(k.needsAttention)} sub="Awaiting remediation workflow" tone="warning" icon={<AlarmClock size={14} />} onClick={() => onNavigate('/x/vuln-repo')} />
        <StatTile label="EOL Software" value={fmt(k.eol)} sub={`${fmt(k.nearEol)} nearing EOL`} tone="warning" icon={<PackageX size={14} />} onClick={() => onNavigate('/x/platform/eol')} />
      </div>

      <div className="dp-grid-3-2">
        <GridExposure onNavigate={onNavigate} />
        <RemediationProgress onNavigate={onNavigate} />
      </div>

      <div className="dp-grid-2">
        <Card title="Critical CVEs Requiring Action" actions={<button type="button" className="dp-btn dp-btn--ghost dp-btn--sm" onClick={() => onNavigate('/findings')}>View all findings <ArrowRight size={13} /></button>}>
          {CRITICAL_CVES.length === 0 ? <EmptyState icon={<Bug size={18} />} title="No critical unresolved CVEs — good posture." /> : (
            <div className="dp-list">
              {CRITICAL_CVES.map((c) => (
                <button key={c.id} type="button" className="dp-list-row" onClick={() => onNavigate('/x/vuln-repo/org-cves')}>
                  <span className="dp-list-icon"><Bug size={14} /></span>
                  <span className="dp-list-main">
                    <span className="dp-cell-title"><span className="dp-mono">{c.id}</span>{c.exploitKnown ? <Badge tone="warning">Exploit</Badge> : null}<Badge tone="critical" dot>Critical</Badge></span>
                    <span className="dp-muted dp-truncate">{c.title}</span>
                  </span>
                  <span className="dp-muted dp-num dp-nowrap">{fmt(c.findingCount)} findings</span>
                </button>
              ))}
            </div>
          )}
        </Card>

        <Card title="Where Attention Is Required" subtitle="Actionable insights for leadership">
          <div className="dp-insights">
            {INSIGHTS.map((ins) => (
              <div key={ins.text} className={`dp-insight-row dp-insight-row--${ins.level}`}>
                <span className="dp-insight-dot" />
                <div>
                  <p>{ins.text}</p>
                  <button type="button" className="dp-link" onClick={() => onNavigate('/x/vuln-repo')}>{ins.action} →</button>
                </div>
              </div>
            ))}
          </div>
          <button type="button" className="dp-callout-btn" onClick={() => onNavigate('/x/vuln-repo')}>
            <span className="dp-callout-num">29</span>
            <span>CVEs with known exploits tracked</span>
            <ArrowRight size={14} className="dp-ml-auto" />
          </button>
        </Card>
      </div>

      <div className="dp-grid-2">
        <Card title="Most Exposed Software" actions={<button type="button" className="dp-btn dp-btn--ghost dp-btn--sm" onClick={() => onNavigate('/x/inventory/software-identities')}>View all <ArrowRight size={13} /></button>}>
          <div className="dp-bars">
            {TOP_SOFTWARE.map((s) => (
              <button key={s.name} type="button" className="dp-bar-row dp-bar-row--btn" onClick={() => onNavigate('/x/inventory/software-identities')}>
                <div className="dp-bar-head">
                  <span><strong>{s.name}</strong> <span className="dp-muted">{s.vendor}</span></span>
                  <span className="dp-muted dp-num">{s.cves} CVEs · {s.assets} assets</span>
                </div>
                <div className="dp-bar-track"><span className="dp-bar-fill" style={{ width: `${(s.assets / maxAssets) * 100}%` }} /></div>
              </button>
            ))}
          </div>
        </Card>

        <Card title="Critical Exposed Assets" actions={<button type="button" className="dp-btn dp-btn--ghost dp-btn--sm" onClick={() => onNavigate('/x/inventory/hosts')}>View all <ArrowRight size={13} /></button>}>
          <div className="dp-list">
            {CRITICAL_ASSETS.map((a) => (
              <button key={a.name} type="button" className="dp-list-row" onClick={() => onNavigate('/x/inventory/hosts')}>
                <span className="dp-list-icon dp-list-icon--neutral"><Server size={14} /></span>
                <span className="dp-list-main"><span className="dp-mono">{a.name}</span><span className="dp-muted">{a.type}</span></span>
                <span className="dp-num"><strong>{a.count}</strong> <span className="dp-muted">findings</span></span>
              </button>
            ))}
          </div>
          <div className="dp-card-foot dp-muted">Top asset by finding volume: <strong>{CRITICAL_ASSETS[0].name}</strong> · {CRITICAL_ASSETS[0].count} findings</div>
        </Card>
      </div>
    </div>
  );
}
