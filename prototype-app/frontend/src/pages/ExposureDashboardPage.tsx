import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { BellRing, Bug, CalendarX, Flame, ListChecks, ShieldAlert, type LucideIcon } from 'lucide-react';
import { AsyncSection, type AsyncSectionState } from '../components/AsyncSection';
import { MetricValue, type MetricAvailability } from '../components/MetricValue';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { useExposureSummaryQuery, useGridExposureQuery } from '../features/dashboard/queries';
import type { GridExposureRow } from '../features/dashboard/types';
import { useVulnRepoDashboardQuery } from '../features/vuln-repo-dashboard/queries';
import { useEolSummaryQuery } from '../features/eol/queries';
import {
  pathForFindingsWithFilters,
  pathForInventoryView,
  pathForVulnRepoView,
  pathForVulnRepoHostAsset,
  pathForVulnRepoSoftwareAssets,
} from '../app/routes';

function fmt(n: number): string {
  return n.toLocaleString();
}

function pct(value: number, total: number): number {
  if (total <= 0) return 0;
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

// Each dashboard dependency is judged on its own; a failed request is never shown as zero or as a healthy empty result.
type DependencyQuery = { data: unknown; isPending: boolean; isError: boolean; isFetching: boolean; refetch: () => unknown };

function availabilityOf(query: DependencyQuery): MetricAvailability {
  if (query.data) return 'available';
  return query.isPending ? 'pending' : 'unavailable';
}

function sectionStateOf(query: DependencyQuery, isEmpty: boolean): AsyncSectionState {
  if (!query.data) return query.isError ? 'error' : 'pending';
  return isEmpty ? 'empty' : 'ready';
}

function KpiLabel({ icon: Icon, children }: { icon: LucideIcon; children: ReactNode }) {
  return (
    <div className="exec-kpi-label">
      <Icon className="exec-kpi-icon" size={16} aria-hidden="true" focusable="false" />
      {children}
    </div>
  );
}

// N02 owns the tenant lifecycle destination; until it exists, EOL signals explain instead of looping back to Exposure.
const EOL_VIEW_UNAVAILABLE = 'Lifecycle detail view not available yet';

function vulnPath(filters: Record<string, string | number | boolean | undefined>): string {
  const p = new URLSearchParams();
  Object.entries(filters).forEach(([k, v]) => {
    if (v != null && v !== '') p.set(k, String(v));
  });
  const s = p.size > 0 ? `?${p.toString()}` : '';
  return `${pathForVulnRepoView('vulnerabilities')}${s}`;
}

function ExposureFunnelWidget({
  tracked,
  applicable,
  impacted,
  remediation,
  addedWeek,
  impactedWeek,
  onNavigate,
}: {
  tracked: number;
  applicable: number;
  impacted: number;
  remediation: number;
  addedWeek: number;
  impactedWeek: number;
  onNavigate: (path: string) => void;
}) {
  const MIN_RATIO = 0.1;
  const stages = [
    {
      label: 'Tracked',
      value: tracked,
      color: '#E05C5C',
      ratio: 1.0,
      sub: `+${fmt(addedWeek)} this week`,
      path: vulnPath({ includeAll: true }),
    },
    {
      label: 'Applicable',
      value: applicable,
      color: '#D4A843',
      ratio: tracked > 0 ? Math.max(applicable / tracked, MIN_RATIO) : MIN_RATIO,
      sub: `${pct(applicable, tracked)}% of tracked`,
      path: vulnPath({ applicable: true, includeAll: true }),
    },
    {
      label: 'Impacted',
      value: impacted,
      color: '#5BA0D0',
      ratio: tracked > 0 ? Math.max(impacted / tracked, MIN_RATIO) : MIN_RATIO,
      sub: `+${fmt(impactedWeek)} this week`,
      path: vulnPath({ impactedOnly: true, includeAll: true }),
    },
    {
      label: 'Remediation',
      value: remediation,
      color: '#4AAD8F',
      ratio: tracked > 0 ? Math.max(remediation / tracked, MIN_RATIO) : MIN_RATIO,
      sub: `${pct(remediation, Math.max(impacted, 1))}% of impacted`,
      path: vulnPath({ hasFindings: true, includeAll: true }),
    },
  ];

  const FW = 520;
  const CX = FW / 2;
  const SH = 62;
  const GAP = 5;
  const OFFSET_X = 130;
  const VIEWW = OFFSET_X + FW + 20;
  const TOTAL_H = stages.length * SH + (stages.length - 1) * GAP;

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>CVE Exposure Funnel</h2>
        <span className="panel-caption">Volume reduction from intelligence intake to active remediation</span>
      </div>
      <svg
        viewBox={`0 0 ${VIEWW} ${TOTAL_H}`}
        style={{ width: '100%', maxWidth: 780, height: 'auto', display: 'block', margin: '12px auto 4px' }}
        aria-label="CVE Exposure Funnel"
      >
        {stages.map((stage, i) => {
          const topRatio = i === 0 ? 1.0 : stages[i - 1].ratio;
          const topW = topRatio * FW;
          const botW = stage.ratio * FW;
          const yTop = i * (SH + GAP);
          const yBot = yTop + SH;
          const xTopL = OFFSET_X + CX - topW / 2;
          const xTopR = OFFSET_X + CX + topW / 2;
          const xBotL = OFFSET_X + CX - botW / 2;
          const xBotR = OFFSET_X + CX + botW / 2;
          const midY = yTop + SH / 2;

          return (
            <g
              key={stage.label}
              style={{ cursor: 'pointer' }}
              role="button"
              aria-label={`${stage.label} ${fmt(stage.value)} ${stage.sub}`}
              onClick={() => onNavigate(stage.path)}
            >
              <polygon
                points={`${xTopL},${yTop} ${xTopR},${yTop} ${xBotR},${yBot} ${xBotL},${yBot}`}
                fill={stage.color}
                opacity={0.9}
              />
              <text
                x={OFFSET_X - 12}
                y={midY}
                textAnchor="end"
                dominantBaseline="middle"
                fontSize={13}
                fontWeight={600}
                fill="var(--dp-text)"
              >
                {stage.label}{' '}
              </text>
              <text
                x={OFFSET_X + CX}
                y={midY - 10}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={17}
                fontWeight={700}
                fill="#ffffff"
              >
                {fmt(stage.value)}{' '}
              </text>
              <text
                x={OFFSET_X + CX}
                y={midY + 12}
                textAnchor="middle"
                dominantBaseline="middle"
                fontSize={11}
                fill="rgba(255,255,255,0.82)"
              >
                {stage.sub}
              </text>
            </g>
          );
        })}
      </svg>
    </section>
  );
}

const ASSET_TYPE_LABELS: Record<string, string> = {
  HOST: 'Hosts',
  CLOUD_RESOURCE: 'Cloud Resources',
  APPLICATION: 'Applications',
  CONTAINER_IMAGE: 'Container Images',
};

const GRID_SEVERITY_COLUMNS: Array<{ key: 'critical' | 'high' | 'medium' | 'low'; label: string }> = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

function gridCellBand(count: number, max: number): 'low' | 'medium' | 'high' {
  if (max <= 0 || count <= 0) return 'low';
  const ratio = count / max;
  if (ratio >= 0.66) return 'high';
  if (ratio >= 0.33) return 'medium';
  return 'low';
}

function GridExposureWidget({
  rows,
  onNavigate,
}: {
  rows: GridExposureRow[];
  onNavigate: (path: string) => void;
}) {
  const max = Math.max(1, ...rows.flatMap((row) => [row.critical, row.high, row.medium, row.low]));

  return (
      <table className="grid-exposure-table">
        <colgroup>
          <col className="grid-exposure-col-domain" />
          {GRID_SEVERITY_COLUMNS.map((col) => <col key={col.key} className="grid-exposure-col-severity" />)}
          <col className="grid-exposure-col-total" />
        </colgroup>
        <thead>
          <tr>
            <th>Asset Domain</th>
            {GRID_SEVERITY_COLUMNS.map((col) => (
              <th key={col.key}>{col.label}</th>
            ))}
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.assetType}>
              <td className="grid-exposure-row-label" title={ASSET_TYPE_LABELS[row.assetType] ?? row.assetType}>{ASSET_TYPE_LABELS[row.assetType] ?? row.assetType}</td>
              {GRID_SEVERITY_COLUMNS.map((col) => {
                const count = row[col.key];
                const band = gridCellBand(count, max);
                return (
                  <td key={col.key} className={`grid-exposure-cell grid-exposure-cell--${band}`}>
                    <button
                      type="button"
                      className="grid-exposure-cell-btn"
                      disabled={count === 0}
                      onClick={() => onNavigate(pathForFindingsWithFilters({
                        assetType: [row.assetType],
                        severity: [col.key.toUpperCase()],
                        status: ['OPEN'],
                      }))}
                    >
                      {fmt(count)}
                    </button>
                  </td>
                );
              })}
              <td className="grid-exposure-total">{fmt(row.total)}</td>
            </tr>
          ))}
        </tbody>
      </table>
  );
}

type InsightLevel = 'critical' | 'warn' | 'info';

type Insight = {
  level: InsightLevel;
  text: string;
  action: string;
  // Absent when no supported destination exists; the action text then explains why.
  path?: string;
};

export function ExposureDashboardPage() {
  const navigate = useNavigate();
  const dashQ = useExposureSummaryQuery();
  const vulnQ = useVulnRepoDashboardQuery();
  const eolQ = useEolSummaryQuery();
  const gridExposureQ = useGridExposureQuery();

  const dash = dashQ.data;
  const vuln = vulnQ.data;
  const eol = eolQ.data;
  const refreshing = (dashQ.isFetching || vulnQ.isFetching || eolQ.isFetching) && !!(dash || vuln || eol);
  const latestDataUpdate = latestFreshnessValue([
    dashQ.dataUpdatedAt,
    vuln?.generatedAt ?? vulnQ.dataUpdatedAt,
    eolQ.dataUpdatedAt,
  ]);

  if (!dash && dashQ.isPending) {
    return <div className="panel ui2-experience-family" aria-busy="true" aria-label="Exposure dashboard" />;
  }

  const dashAvail = availabilityOf(dashQ);
  const vulnAvail = availabilityOf(vulnQ);
  const eolAvail = availabilityOf(eolQ);
  const retry = (query: DependencyQuery) => () => void query.refetch();
  const refreshFailures = [
    { query: dashQ, label: 'Findings summary' },
    { query: vulnQ, label: 'CVE summary' },
    { query: eolQ, label: 'End-of-life summary' },
    { query: gridExposureQ, label: 'Grid exposure' },
  ].filter(({ query }) => query.isError && query.data);

  // ── Risk posture numbers ──────────────────────────────────────────
  const criticalF      = dash?.criticalFindings ?? 0;
  const openCritical   = dash?.openCritical ?? 0;
  const openHigh       = dash?.openHigh ?? 0;
  const openMedium     = dash?.openMedium ?? 0;
  const openLow        = dash?.openLow ?? 0;
  const avgRisk        = dash?.averageOpenRiskScore ?? 0;
  const securityScore  = Math.round(Math.max(0, 100 - (avgRisk / 10) * 100));
  const topAssets      = dash?.topAssetsAtRisk ?? [];

  // ── CVE exposure numbers ──────────────────────────────────────────
  const tracked        = vuln?.summaryCards.trackedCount ?? 0;
  const applicable     = vuln?.summaryCards.applicableCount ?? 0;
  const impacted       = vuln?.summaryCards.impactedInvestigationDoneCount ?? 0;
  const remediation    = vuln?.summaryCards.remediationCveCount ?? 0;
  const needsAttention = vuln?.summaryCards.needsAttentionCount ?? 0;
  const exploitCves    = vuln?.summaryCards.exploitCount ?? 0;
  const kevImpacted    = vuln?.summaryCards.impactedKevCount ?? 0;
  const impactedCrit   = vuln?.summaryCards.impactedCriticalCount ?? 0;
  const impactedHigh   = vuln?.summaryCards.impactedHighCount ?? 0;
  const critUninv      = vuln?.summaryCards.criticalUninvestigatedCount ?? 0;
  const kevReinv       = vuln?.summaryCards.kevReinvestigationCount ?? 0;

  // ── Weekly trend numbers ──────────────────────────────────────────
  const addedWeek      = vuln?.summaryCards.trackedAddedLastWeek ?? 0;
  const impactedWeek   = vuln?.summaryCards.impactedAddedLastWeek ?? 0;
  const kevWeek        = vuln?.summaryCards.kevAddedLastWeek ?? 0;

  // ── Remediation progress ─────────────────────────────────────────
  const unresolved     = vuln?.resolutionStatus.unresolvedCount ?? 0;
  const inProgress     = vuln?.resolutionStatus.inProgressCount ?? 0;
  const resolved       = vuln?.resolutionStatus.resolvedCount ?? 0;
  const accepted       = vuln?.resolutionStatus.acceptedRiskCount ?? 0;

  // ── EOL ───────────────────────────────────────────────────────────
  const eolCount       = eol?.eolCount ?? 0;
  const nearEolCount   = eol?.nearEolCount ?? 0;

  // ── Insights ─────────────────────────────────────────────────────
  const insights: Insight[] = [];
  if (critUninv > 0) {
    insights.push({
      level: 'critical',
      text: `${fmt(critUninv)} critical CVE${critUninv > 1 ? 's' : ''} applicable to your environment have not been investigated.`,
      action: 'Investigate now',
      path: vulnPath({ severity: 'CRITICAL', applicable: true }),
    });
  }
  if (kevReinv > 0) {
    insights.push({
      level: 'critical',
      text: `${fmt(kevReinv)} CISA KEV CVE${kevReinv > 1 ? 's' : ''} with org impact need re-evaluation after updated guidance.`,
      action: 'Review KEV',
      path: vulnPath({ inKev: true, applicable: true }),
    });
  }
  if (kevWeek > 0) {
    insights.push({
      level: 'warn',
      text: `${fmt(kevWeek)} new CISA KEV CVE${kevWeek > 1 ? 's' : ''} added this week with active exploits in the wild.`,
      action: 'View new KEV',
      path: vulnPath({ inKev: true, createdSinceDays: 7 }),
    });
  }
  if (impactedWeek > 0) {
    insights.push({
      level: 'warn',
      text: `${fmt(impactedWeek)} new CVE${impactedWeek > 1 ? 's were' : ' was'} confirmed impacted in your environment this week.`,
      action: 'View new impacts',
      path: vulnPath({ impactedOnly: true, createdSinceDays: 7 }),
    });
  }
  if (eolCount > 0) {
    insights.push({
      level: 'warn',
      text: `${fmt(eolCount)} end-of-life software component${eolCount > 1 ? 's' : ''} in your environment ${eolCount > 1 ? 'are' : 'is'} no longer receiving security patches.`,
      action: EOL_VIEW_UNAVAILABLE,
    });
  }
  if (impacted > 0 && pct(remediation, impacted) < 40) {
    insights.push({
      level: 'info',
      text: `Only ${pct(remediation, impacted)}% of confirmed impacted CVEs have an active remediation workflow.`,
      action: 'Start remediation',
      path: pathForVulnRepoView('org-cves'),
    });
  }
  if (nearEolCount > 0 && eolCount === 0) {
    insights.push({
      level: 'info',
      text: `${fmt(nearEolCount)} software component${nearEolCount > 1 ? 's are' : ' is'} nearing end-of-life — plan upgrades before security support ends.`,
      action: EOL_VIEW_UNAVAILABLE,
    });
  }

  // ── Critical unresolved CVEs ──────────────────────────────────────
  const criticalUnresolved = vuln?.criticalUnresolved ?? [];
  const topSoftware = [...(vuln?.topAffectedSoftware ?? [])]
    .sort((a, b) => b.cveCount - a.cveCount || b.criticalCount - a.criticalCount)
    .slice(0, 6);
  const impactedAssets = (vuln?.impactedAssets ?? []).slice(0, 6);

  const maxSoftwareCves = Math.max(...topSoftware.map((s) => s.cveCount), 1);
  const maxFinding = Math.max(openCritical, openHigh, openMedium, openLow, 1);

  // Healthy/empty is claimed only once every signal source has loaded; a missing source is reported instead.
  const missingSignals = [
    { query: vulnQ, label: 'CVE summary' },
    { query: eolQ, label: 'end-of-life summary' },
  ].filter(({ query }) => !query.data);
  const insightsState: AsyncSectionState = insights.length > 0
    ? 'ready'
    : missingSignals.some(({ query }) => query.isPending) ? 'pending'
    : missingSignals.length > 0 ? 'error'
    : 'empty';
  const retryMissingSignals = () => missingSignals.forEach(({ query }) => void query.refetch());

  // Organization CVE records by impact state, plus CVEs with a suppressed finding counted separately (N03).
  // They are CVEs, not findings, and the accepted-risk row can overlap the others, so no total or drill-down is implied.
  const remediationBars = [
    { label: 'Impacted or unknown', value: unresolved, cls: 'exec-rem--open' },
    { label: 'Under investigation', value: inProgress, cls: 'exec-rem--in-progress' },
    { label: 'Fixed or not impacted', value: resolved, cls: 'exec-rem--resolved' },
    { label: 'With accepted-risk findings', value: accepted, cls: 'exec-rem--accepted' },
  ];
  const maxStatus = Math.max(unresolved, inProgress, resolved, accepted, 1);

  return (
    <div className="page-grid exec-dashboard ui2-experience-family">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshing}
        refreshLabel="Refreshing exposure view…"
      />

      {refreshFailures.map(({ query, label }) => (
        <AsyncSection
          key={label}
          state="ready"
          refreshError={`${label} could not be refreshed; showing the last loaded values.`}
          onRetry={retry(query)}
          retrying={query.isFetching}
        />
      ))}

      {/* ── Row 1: Risk Posture KPIs ── */}
      <div className="exec-kpi-grid">
        <button
          type="button"
          className={`exec-kpi exec-kpi--${criticalF > 0 ? 'critical' : 'neutral'}`}
          onClick={() => navigate(pathForFindingsWithFilters({ severity: ['CRITICAL'], status: ['OPEN'] }))}
        >
          <div className="exec-kpi-value"><MetricValue availability={dashAvail} value={dash?.criticalFindings} unavailableReason="Findings summary unavailable" /></div>
          <KpiLabel icon={ShieldAlert}>Critical Findings</KpiLabel>
          <div className="exec-kpi-sub">Active open findings</div>
        </button>
        <button
          type="button"
          className="exec-kpi exec-kpi--warn"
          onClick={() => navigate(pathForFindingsWithFilters({ status: ['OPEN'] }))}
        >
          <div className="exec-kpi-value"><MetricValue availability={dashAvail} value={dash?.openFindings} unavailableReason="Findings summary unavailable" /></div>
          <KpiLabel icon={ListChecks}>Open Findings</KpiLabel>
          <div className="exec-kpi-sub">All severities</div>
        </button>
        <button
          type="button"
          className={`exec-kpi exec-kpi--${impactedCrit > 0 ? 'critical' : 'warn'}`}
          onClick={() => navigate(vulnPath({ impactedOnly: true, includeAll: true }))}
        >
          <div className="exec-kpi-value"><MetricValue availability={vulnAvail} value={vuln?.summaryCards.impactedInvestigationDoneCount} unavailableReason="CVE summary unavailable" /></div>
          <KpiLabel icon={Bug}>Impacted CVEs</KpiLabel>
          <div className="exec-kpi-sub">{vuln ? `${fmt(impactedCrit)} critical · ${fmt(impactedHigh)} high` : 'Severity split unavailable'}</div>
        </button>
        <button
          type="button"
          className={`exec-kpi exec-kpi--${kevImpacted > 0 ? 'critical' : 'neutral'}`}
          onClick={() => navigate(vulnPath({ inKev: true, includeAll: true }))}
        >
          <div className="exec-kpi-value"><MetricValue availability={vulnAvail} value={vuln?.summaryCards.impactedKevCount} unavailableReason="CVE summary unavailable" /></div>
          <KpiLabel icon={Flame}>CISA KEV Exposure</KpiLabel>
          <div className="exec-kpi-sub">Impacted CVEs listed in CISA KEV</div>
        </button>
        <button
          type="button"
          className={`exec-kpi exec-kpi--${needsAttention > 0 ? 'warn' : 'neutral'}`}
          onClick={() => navigate('/vuln-repo/vulnerabilities?impactedOnly=true&hasFindings=false')}
        >
          <div className="exec-kpi-value"><MetricValue availability={vulnAvail} value={vuln?.summaryCards.needsAttentionCount} unavailableReason="CVE summary unavailable" /></div>
          <KpiLabel icon={BellRing}>Needs Attention</KpiLabel>
          <div className="exec-kpi-sub">Impacted CVEs with no findings yet</div>
        </button>
        <div className={`exec-kpi exec-kpi--static exec-kpi--${eolCount > 0 ? 'warn' : 'neutral'}`}>
          <div className="exec-kpi-value"><MetricValue availability={eolAvail} value={eol?.eolCount} unavailableReason="End-of-life summary unavailable" /></div>
          <KpiLabel icon={CalendarX}>EOL Software</KpiLabel>
          <div className="exec-kpi-sub">{!eol ? 'Lifecycle split unavailable' : nearEolCount > 0 ? `${fmt(nearEolCount)} nearing EOL` : 'None nearing EOL'}</div>
          <div className="exec-kpi-sub">{EOL_VIEW_UNAVAILABLE}</div>
        </div>
      </div>

      {/* ── Row 2: Grid Exposure + Remediation (7:5 at 1200px and wider, stacked below) ── */}
      <div className="exec-pair">
        <section className="panel">
          <div className="panel-header">
            <h2>Grid Exposure</h2>
            <span className="panel-caption">Open findings across your Scout Grid, by asset domain and severity</span>
          </div>
          <AsyncSection
            state={sectionStateOf(gridExposureQ, (gridExposureQ.data?.rows.length ?? 0) === 0)}
            loadingLabel="Loading grid exposure…"
            emptyMessage="No asset domains report open findings yet."
            errorMessage="Grid exposure could not be loaded."
            onRetry={retry(gridExposureQ)}
            retryLabel="Retry grid exposure"
            retrying={gridExposureQ.isFetching}
          >
            {gridExposureQ.data && <GridExposureWidget rows={gridExposureQ.data.rows} onNavigate={navigate} />}
          </AsyncSection>
        </section>

        {/* Remediation Progress */}
        <section className="panel">
          <div className="panel-header">
            <h2>Remediation Progress</h2>
            <span className="panel-caption">Organization CVE records by impact state, all severities</span>
          </div>

          <AsyncSection
            state={sectionStateOf(vulnQ, false)}
            loadingLabel="Loading remediation status…"
            errorMessage="Remediation status could not be loaded."
            onRetry={retry(vulnQ)}
            retryLabel="Retry CVE summary"
            retrying={vulnQ.isFetching}
          >
          <ul className="exec-rem-stacked" aria-label="CVE records by impact state">
            {remediationBars.map((bar) => (
              <li key={bar.label} className="exec-rem-row exec-rem-row--static">
                <span className="exec-rem-label">{bar.label}</span>
                <div className="exec-rem-track" aria-hidden="true">
                  <div className={`exec-rem-bar ${bar.cls}`} style={{ width: `${pct(bar.value, maxStatus)}%` }} />
                </div>
                <span className="exec-rem-count">{fmt(bar.value)} CVEs</span>
              </li>
            ))}
          </ul>
          <p className="panel-caption exec-rem-note">
            Counts are CVEs, not findings. The accepted-risk row counts CVEs with a suppressed finding and can overlap the
            other rows, so the rows are not a total. Bars are scaled to the largest row.
          </p>
          </AsyncSection>

          <AsyncSection
            state={sectionStateOf(dashQ, false)}
            loadingLabel="Loading findings summary…"
            errorMessage="Findings summary could not be loaded."
            onRetry={retry(dashQ)}
            retryLabel="Retry findings summary"
            retrying={dashQ.isFetching}
          >
          <div className="exec-rem-footer">
            <div className="exec-rem-score-block">
              <div className="exec-rem-score">{securityScore}</div>
              <div className="exec-rem-score-label">Security Score</div>
              <div className="exec-rem-score-sub">/ 100 · avg risk {avgRisk.toFixed(1)}</div>
              <p className="exec-rem-score-explain">100 minus the average open-finding risk score (0–10) × 10. Higher is better.</p>
            </div>
            <div className="exec-rem-breakdown">
              {[
                { label: 'Critical', value: openCritical, cls: 'critical' },
                { label: 'High',     value: openHigh,     cls: 'high' },
                { label: 'Medium',   value: openMedium,   cls: 'medium' },
                { label: 'Low',      value: openLow,      cls: 'low' },
              ].map((s) => (
                <button
                  key={s.label}
                  type="button"
                  className="exec-rem-sev-row"
                  onClick={() => navigate(pathForFindingsWithFilters({ severity: [s.label.toUpperCase()], status: ['OPEN'] }))}
                >
                  <span className="exec-rem-sev-label">{s.label}</span>
                  <div className="exec-rem-sev-track">
                    <div className={`severity-bar severity-bar-${s.cls}`} style={{ width: `${pct(s.value, maxFinding)}%` }} />
                  </div>
                  <span className="exec-rem-sev-count">{fmt(s.value)}</span>
                </button>
              ))}
            </div>
          </div>
          </AsyncSection>
        </section>
      </div>

      {/* ── Row 3: Critical CVEs + Attention ── */}
      <div className="exec-two-col">

        {/* Critical CVEs requiring action */}
        <section className="panel">
          <div className="panel-header">
            <h2>Critical CVEs Requiring Action</h2>
            <button type="button" className="btn-link" onClick={() => navigate(pathForFindingsWithFilters({ severity: ['CRITICAL'], status: ['OPEN'] }))}>
              View all findings
            </button>
          </div>
          <AsyncSection
            state={sectionStateOf(vulnQ, criticalUnresolved.length === 0)}
            loadingLabel="Loading critical CVEs…"
            emptyMessage="No critical unresolved CVEs — good posture."
            errorMessage="Critical CVEs could not be loaded."
            onRetry={retry(vulnQ)}
            retryLabel="Retry CVE summary"
            retrying={vulnQ.isFetching}
          >
            <div className="exec-cve-list">
              {criticalUnresolved.slice(0, 8).map((item) => (
                <button
                  key={item.externalId}
                  type="button"
                  className="exec-cve-row"
                  onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}
                >
                  <div className="exec-cve-left">
                    <span className="exec-cve-id mono">{item.externalId}</span>
                    {item.exploitKnown && <span className="status-pill status-warning exec-cve-exploit">Exploit</span>}
                    <span className="severity-pill severity-critical">Critical</span>
                  </div>
                  <p className="exec-cve-title">{item.title}</p>
                  <div className="exec-cve-findings">{fmt(item.findingCount)} findings</div>
                </button>
              ))}
            </div>
          </AsyncSection>
        </section>

        {/* Where attention is required */}
        <section className="panel">
          <div className="panel-header">
            <h2>Where Attention Is Required</h2>
            <span className="panel-caption">Actionable insights for leadership</span>
          </div>
          <AsyncSection
            state={insightsState}
            loadingLabel="Loading attention signals…"
            emptyMessage="No active attention signals — risk posture is healthy."
            errorMessage={`Attention signals could not be loaded: ${missingSignals.map(({ label }) => label).join(', ')}.`}
            refreshError={missingSignals.length > 0 && !missingSignals.some(({ query }) => query.isPending)
              ? `Some attention signals are unavailable: ${missingSignals.map(({ label }) => label).join(', ')}.`
              : undefined}
            onRetry={retryMissingSignals}
            retryLabel="Retry signals"
            retrying={missingSignals.some(({ query }) => query.isFetching)}
          >
            <div className="exec-insights">
              {insights.map((ins, i) => (
                <div key={i} className={`exec-insight exec-insight--${ins.level}`}>
                  <div className="exec-insight-dot" />
                  <div className="exec-insight-body">
                    <p className="exec-insight-text">{ins.text}</p>
                    {ins.path ? (
                      <button
                        type="button"
                        className="btn-link exec-insight-action"
                        onClick={() => navigate(ins.path!)}
                      >
                        {ins.action} →
                      </button>
                    ) : (
                      <span className="panel-caption exec-insight-action">{ins.action}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </AsyncSection>

          {exploitCves > 0 && (
            <div className="exec-exploit-summary">
              <button
                type="button"
                className="exec-exploit-btn"
                onClick={() => navigate(vulnPath({ inKev: true, includeAll: true }))}
              >
                <span className="exec-exploit-num">{fmt(exploitCves)}</span>
                <span>tracked CVEs with known exploits (KEV or high EPSS). Opens the KEV subset.</span>
              </button>
            </div>
          )}
        </section>
      </div>

      {/* ── Row 4: Most Exposed Software + Exposed Assets ── */}
      <div className="exec-two-col">

        {/* Top affected software */}
        <section className="panel">
          <div className="panel-header">
            <h2>Most Exposed Software</h2>
            <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>
              View all
            </button>
          </div>
          <AsyncSection
            state={sectionStateOf(vulnQ, topSoftware.length === 0)}
            loadingLabel="Loading software exposure…"
            emptyMessage="No software exposure data available."
            errorMessage="Software exposure could not be loaded."
            onRetry={retry(vulnQ)}
            retryLabel="Retry CVE summary"
            retrying={vulnQ.isFetching}
          >
            <div className="exec-software-list">
              {topSoftware.map((sw) => (
                <button
                  key={`${sw.software}-${sw.vendor}`}
                  type="button"
                  className="exec-software-row"
                  onClick={() => navigate(pathForVulnRepoSoftwareAssets(sw.softwareIdentityId, sw.software))}
                >
                  <div className="exec-software-meta">
                    <strong>{sw.software}</strong>
                    <span>{sw.vendor}</span>
                  </div>
                  <div className="exec-software-bar-track">
                    <div
                      className="exec-software-bar"
                      style={{ width: `${pct(sw.cveCount, maxSoftwareCves)}%` }}
                    />
                  </div>
                  <div className="exec-software-counts">
                    <span className="exec-software-cve-count">{fmt(sw.cveCount)} CVEs</span>
                    <span className="exec-software-asset-count">{fmt(sw.impactedAssetCount)} assets</span>
                    <span className={`severity-pill severity-${sw.highestSeverity.toLowerCase()}`}>
                      {sw.highestSeverity.charAt(0) + sw.highestSeverity.slice(1).toLowerCase()}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </AsyncSection>
        </section>

        {/* Critical exposed assets */}
        <section className="panel">
          <div className="panel-header">
            <h2>Critical Exposed Assets</h2>
            <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryView('hosts'))}>
              View all
            </button>
          </div>
          <AsyncSection
            state={sectionStateOf(vulnQ, impactedAssets.length === 0)}
            loadingLabel="Loading exposed assets…"
            emptyMessage="No impacted assets available."
            errorMessage="Exposed assets could not be loaded."
            onRetry={retry(vulnQ)}
            retryLabel="Retry CVE summary"
            retrying={vulnQ.isFetching}
          >
            <div className="exec-assets-list">
              {impactedAssets.map((asset) => (
                <button
                  key={asset.assetId}
                  type="button"
                  className="exec-asset-row"
                  onClick={() => navigate(pathForVulnRepoHostAsset(asset.assetId))}
                >
                  <div className="exec-asset-icon exec-asset-icon--host" aria-hidden="true">
                    {asset.assetType.charAt(0).toUpperCase()}
                  </div>
                  <div className="exec-asset-meta">
                    <strong>{asset.assetName}</strong>
                    <span>{asset.assetType.toLowerCase()} · {asset.identifier}{asset.environment ? ` · ${asset.environment}` : ''}</span>
                  </div>
                  <div className={`exec-asset-cve-count ${asset.cveCount >= 10 ? 'exec-asset-cve-count--high' : ''}`}>
                    {fmt(asset.cveCount)}
                    <span>CVEs</span>
                  </div>
                </button>
              ))}
            </div>
          </AsyncSection>
          {topAssets.length > 0 && (
            <div className="exec-asset-attention">
              <span className="panel-caption">Top asset by finding volume: </span>
              <strong>{topAssets[0]?.key}</strong>
              <span className="panel-caption"> · {fmt(topAssets[0]?.count ?? 0)} findings</span>
            </div>
          )}
        </section>
      </div>

      {/* ── Row 5: CVE Exposure Funnel ── */}
      {vuln ? (
        <ExposureFunnelWidget
          tracked={tracked}
          applicable={applicable}
          impacted={impacted}
          remediation={remediation}
          addedWeek={addedWeek}
          impactedWeek={impactedWeek}
          onNavigate={navigate}
        />
      ) : (
        <section className="panel">
          <div className="panel-header">
            <h2>CVE Exposure Funnel</h2>
            <span className="panel-caption">Volume reduction from intelligence intake to active remediation</span>
          </div>
          <AsyncSection
            state={sectionStateOf(vulnQ, false)}
            loadingLabel="Loading CVE exposure…"
            errorMessage="CVE exposure could not be loaded."
            onRetry={retry(vulnQ)}
            retryLabel="Retry CVE summary"
            retrying={vulnQ.isFetching}
          />
        </section>
      )}

    </div>
  );
}
