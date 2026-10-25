import React from 'react';
import { Link } from 'react-router-dom';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import {
  CveInventoryMappingRecord,
  DashboardCveInventoryMap,
} from '../features/dashboard/types';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { StatCard } from '../components/StatCard';
import { EolRiskWidget } from '../components/EolRiskWidget';
import {
  useDashboardCveInventoryMapQuery,
  useDashboardSummaryQuery
} from '../features/dashboard/queries';
import { pathForConnectView } from '../app/routes';

function summarizeList(values: string[], maxItems = 3): string {
  if (!values || values.length === 0) {
    return '-';
  }
  if (values.length <= maxItems) {
    return values.join(', ');
  }
  return `${values.slice(0, maxItems).join(', ')} +${values.length - maxItems} more`;
}

function severityClassName(severity?: string): string {
  const normalized = (severity ?? '').trim().toLowerCase();
  if (normalized === 'critical') {
    return 'severity-pill severity-critical';
  }
  if (normalized === 'high') {
    return 'severity-pill severity-high';
  }
  if (normalized === 'medium') {
    return 'severity-pill severity-medium';
  }
  return 'severity-pill severity-low';
}

type DashboardPageProps = {
  onViewEol?: () => void;
};

function buildCveInventoryRows(rows: CveInventoryMappingRecord[]): DataTableRow[] {
  return rows.map((row) => ({
    id: row.vulnerabilityId,
    cells: {
      cve: { content: <span className="mono">{row.externalId}</span> },
      severity: {
        content: (
          <span className={severityClassName(row.severity)}>{row.severity || 'UNKNOWN'}</span>
        )
      },
      cvss: { content: row.cvssScore == null ? '-' : row.cvssScore.toFixed(1) },
      identifiers: { content: <span className="mono">{summarizeList(row.matchedIdentifiers)}</span> },
      mappedSoftware: {
        content: (
          <span title={row.mappedSoftware.join(', ')}>
            {row.mappedSoftwareCount.toLocaleString()} ({summarizeList(row.mappedSoftware, 2)})
          </span>
        )
      }
    }
  }));
}

export function DashboardPage({ onViewEol }: DashboardPageProps) {
  const dashboardQuery = useDashboardSummaryQuery();
  const cveInventoryMapQuery = useDashboardCveInventoryMapQuery(5);
  const data = dashboardQuery.data ?? null;
  const cveInventoryMap: DashboardCveInventoryMap | null = cveInventoryMapQuery.data ?? null;
  const error = dashboardQuery.error instanceof Error ? dashboardQuery.error.message : null;
  const topHighRiskMap = React.useMemo(() => cveInventoryMap?.topHighRisk ?? [], [cveInventoryMap]);
  const latestMap = React.useMemo(() => cveInventoryMap?.latest ?? [], [cveInventoryMap]);
  const cveTableColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 140 },
    { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
    { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 96 },
    { id: 'identifiers', label: 'Matched Identifiers', header: 'Matched Identifiers', initialSize: 220 },
    { id: 'mappedSoftware', label: 'Mapped Software', header: 'Mapped Software', initialSize: 240 }
  ], []);
  const topHighRiskRows = React.useMemo(() => buildCveInventoryRows(topHighRiskMap), [topHighRiskMap]);
  const latestRows = React.useMemo(() => buildCveInventoryRows(latestMap), [latestMap]);
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    dashboardQuery.dataUpdatedAt,
    cveInventoryMapQuery.dataUpdatedAt
  ]), [
    cveInventoryMapQuery.dataUpdatedAt,
    dashboardQuery.dataUpdatedAt
  ]);

  if (error) {
    return <div className="panel">Failed to load dashboard: {error}</div>;
  }
  if (!data) {
    return <div className="panel">Loading dashboard...</div>;
  }

  const critical = data.openCritical;
  const high = data.openHigh;
  const medium = data.openMedium;
  const low = data.openLow;
  const maxSeverityCount = Math.max(critical, high, medium, low, 1);
  const avgRisk = data.averageOpenRiskScore;
  const avgConfidence = data.averageOpenConfidenceScore;
  const highConfidenceExposures = data.highConfidenceOpenFindings;
  const securityScore = Math.round(Math.max(0, 100 - (avgRisk / 10) * 100));

  const isFirstRun = data.assets === 0 && data.components === 0 && data.openFindings === 0;

  return (
    <div className="page-grid">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={(dashboardQuery.isFetching || cveInventoryMapQuery.isFetching) && (!!data || !!cveInventoryMap)}
        refreshLabel="Refreshing dashboard signals while keeping current results visible…"
      />

      {isFirstRun && (
        <div className="first-run-banner">
          <div className="first-run-banner-icon">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
          </div>
          <div className="first-run-banner-body">
            <strong>Welcome to Scout.ai</strong>
            <p>No inventory data has been ingested yet. Connect a data source to start discovering vulnerabilities across your software stack.</p>
            <div className="first-run-banner-actions">
              <Link to={pathForConnectView('sources')} className="btn btn-primary">Configure Sources</Link>
            </div>
          </div>
        </div>
      )}

      <div className="stats-grid">
        <StatCard title="Assets" value={data.assets} />
        <StatCard title="Installed Components" value={data.components} />
        <StatCard title="Open Exposures" value={data.openFindings} tone="warn" />
        <StatCard title="Critical Exposures" value={data.criticalFindings} tone="critical" />
        <StatCard title="High Confidence" value={highConfidenceExposures} caption="Confidence >= 0.80" />
        <StatCard title="Avg Confidence" value={Math.round(avgConfidence * 100)} caption="Percent confidence" />
      </div>

      <EolRiskWidget onViewAll={onViewEol} />

      <div className="dashboard-grid">
        <section className="panel">
          <div className="panel-header">
            <h3>Exposure Severity</h3>
            <span className="panel-caption">Open exposures only</span>
          </div>
          <div className="severity-meter">
            {[
              { label: 'Critical', value: critical, className: 'critical' },
              { label: 'High', value: high, className: 'high' },
              { label: 'Medium', value: medium, className: 'medium' },
              { label: 'Low', value: low, className: 'low' }
            ].map((entry) => (
              <div key={entry.label} className="severity-row">
                <div className="severity-label">{entry.label}</div>
                <div className="severity-bar-track">
                  <div
                    className={`severity-bar severity-bar-${entry.className}`}
                    style={{ width: `${(entry.value / maxSeverityCount) * 100}%` }}
                  />
                </div>
                <div className="severity-value">{entry.value.toLocaleString()}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="panel security-score-panel">
          <div className="panel-header">
            <h3>Security Score</h3>
          </div>
          <div className="score-gauge-wrap">
            <div className="score-gauge" style={{ ['--score' as string]: `${securityScore}` }}>
              <div className="score-inner">
                <div className="score-value">{securityScore}</div>
                <div className="score-unit">/ 100</div>
              </div>
            </div>
            <div className="score-note">
              Avg risk: {avgRisk.toFixed(2)} | Avg confidence: {(avgConfidence * 100).toFixed(1)}%
            </div>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h3>Top CVE Inventory Mapping</h3>
          <span className="panel-caption">Identifier-level mapping for top high risk and latest impacted CVEs</span>
        </div>
        {cveInventoryMapQuery.error && !cveInventoryMap ? (
          <div className="panel-caption">Failed to load CVE inventory mapping.</div>
        ) : !cveInventoryMap ? (
          <div className="panel-caption">Loading...</div>
        ) : (<div className="noise-panel-grid">
          <div>
            <div className="noise-subtitle">Top 5 High Risk CVEs</div>
            {topHighRiskMap.length === 0 ? (
              <div className="panel-caption">No high-risk impacted CVEs available.</div>
            ) : (
              <div className="table-scroll">
                <DataTable
                  storageKey="dashboard-top-high-risk-cves"
                  columns={cveTableColumns}
                  rows={topHighRiskRows}
                />
              </div>
            )}
          </div>

          <div>
            <div className="noise-subtitle">Latest 5 Confirmed Impacted / No-Patch CVEs</div>
            {latestMap.length === 0 ? (
              <div className="panel-caption">No recent confirmed impacted or no-patch CVEs available.</div>
            ) : (
              <div className="table-scroll">
                <DataTable
                  storageKey="dashboard-latest-cves"
                  columns={cveTableColumns}
                  rows={latestRows}
                />
              </div>
            )}
          </div>
        </div>)}
      </section>

    </div>
  );
}
