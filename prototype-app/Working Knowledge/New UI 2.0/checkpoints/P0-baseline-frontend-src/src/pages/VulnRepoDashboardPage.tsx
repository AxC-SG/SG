import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import { pathForInventoryView, pathForVulnRepoHostAsset, pathForVulnRepoSoftwareAssets, pathForVulnRepoView } from '../app/routes';
import { useActor } from '../features/auth/context';
import { canAccessPlatformConsole } from '../features/auth/roles';
import { usePlatformVulnSourceStatsQuery, useVulnIntelSourcesSummaryQuery, useVulnRepoDashboardQuery } from '../features/vuln-repo-dashboard/queries';
import type {
  PlatformVulnSourceStat,
  VulnRepoDashboardCriticalUnresolvedItem,
  VulnRepoDashboardRecentAdvisoryItem,
  VulnRepoDashboardSeverityBreakdownItem,
} from '../features/vuln-repo-dashboard/types';
import type { VulnIntelSourceStatus } from '../api/client';

function formatNumber(value: number): string {
  return value.toLocaleString();
}

function formatSeverity(value: string): string {
  return value.toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function severityClassName(value: string): string {
  switch (value.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'severity-pill severity-critical';
    case 'HIGH':
      return 'severity-pill severity-high';
    case 'MEDIUM':
      return 'severity-pill severity-medium';
    case 'LOW':
      return 'severity-pill severity-low';
    default:
      return 'severity-pill';
  }
}

function severityBarClassName(value: string): string {
  switch (value.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--critical';
    case 'HIGH':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--high';
    case 'MEDIUM':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--medium';
    case 'LOW':
      return 'vuln-repo-inline-bar vuln-repo-inline-bar--low';
    default:
      return 'vuln-repo-inline-bar';
  }
}

function statusClassName(value: string): string {
  const normalized = value.trim().toUpperCase().replace(/[\s-]+/g, '_');
  switch (normalized) {
    case 'OPEN':
    case 'UNRESOLVED':
      return 'status-pill status-open';
    case 'IN_PROGRESS':
      return 'status-pill status-in-progress';
    case 'RESOLVED':
      return 'status-pill status-resolved';
    case 'ACCEPTED_RISK':
      return 'status-pill status-warning';
    default:
      return 'status-pill status-unknown';
  }
}

function relativeTime(value?: string): string {
  if (!value) {
    return 'Recently';
  }
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    return 'Recently';
  }
  const deltaMs = Date.now() - timestamp;
  const days = Math.max(0, Math.floor(deltaMs / (24 * 60 * 60 * 1000)));
  if (days <= 0) {
    return 'Today';
  }
  if (days === 1) {
    return '1 day ago';
  }
  if (days < 7) {
    return `${days} days ago`;
  }
  const weeks = Math.floor(days / 7);
  return `${weeks} week${weeks === 1 ? '' : 's'} ago`;
}

function topCount(items: VulnRepoDashboardSeverityBreakdownItem[]): number {
  return items.reduce((max, item) => Math.max(max, item.count), 0);
}

function percentOf(value: number, total: number): number {
  if (total <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

function renderCriticalUnresolvedTags(item: VulnRepoDashboardCriticalUnresolvedItem) {
  return (
    <div className="vuln-repo-dashboard-item-tags">
      <span className={severityClassName(item.severity)}>{formatSeverity(item.severity)}</span>
      <span className={statusClassName(item.statusLabel)}>{item.statusLabel}</span>
      {item.exploitKnown ? <span className="status-pill status-warning">Exploit</span> : null}
    </div>
  );
}

function advisoryRelativeTimeLabel(value?: string): string {
  return value ? relativeTime(value) : 'Recently';
}

function vulnRepoVulnerabilityPath(filters?: Record<string, string | number | boolean | undefined>) {
  const searchParams = new URLSearchParams();
  Object.entries(filters ?? {}).forEach(([key, value]) => {
    if (value == null || value === '') {
      return;
    }
    searchParams.set(key, String(value));
  });
  const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
  return `${pathForVulnRepoView('vulnerabilities')}${suffix}`;
}

function findingsPath(filters?: Record<string, string | number | boolean | undefined>) {
  const searchParams = new URLSearchParams();
  Object.entries(filters ?? {}).forEach(([key, value]) => {
    if (value == null || value === '') {
      return;
    }
    searchParams.set(key, String(value));
  });
  const suffix = searchParams.size > 0 ? `?${searchParams.toString()}` : '';
  return `/findings${suffix}`;
}

function vulnRepoTrackedVulnerabilityPath(filters?: Record<string, string | number | boolean | undefined>) {
  return vulnRepoVulnerabilityPath({ includeAll: true, ...(filters ?? {}) });
}

const SOURCE_DISPLAY_NAMES: Record<string, string> = {
  nvd: 'NVD',
  'cisa-kev': 'CISA KEV',
  kev: 'CISA KEV',
  ghsa: 'GHSA',
  euvd: 'EUVD',
  'japan-vulndb': 'JVN / JVNDB',
  'microsoft-csaf': 'Microsoft CSAF',
  'redhat-csaf': 'Red Hat CSAF',
  advisory: 'Advisory Feed',
};

function sourceDisplayName(key: string): string {
  return SOURCE_DISPLAY_NAMES[key] ?? key;
}

function sourceStatusLabel(status: VulnIntelSourceStatus['status']): string {
  switch (status) {
    case 'completed': return 'OK';
    case 'failed': return 'Failed';
    case 'running': return 'Running';
    case 'never': return 'Never run';
  }
}

function sourceStatusClass(status: VulnIntelSourceStatus['status']): string {
  switch (status) {
    case 'completed': return 'status-pill status-resolved';
    case 'failed': return 'status-pill status-open';
    case 'running': return 'status-pill status-in-progress';
    case 'never': return 'status-pill status-unknown';
  }
}

function intelPath(source: string, severity?: string): string {
  const params = new URLSearchParams();
  params.set('source', source);
  if (severity) params.set('severity', severity);
  return `${pathForVulnRepoView('vulnerabilities')}?${params.toString()}`;
}

function PlatformSourceStatsCard({ sourceKey, stat }: { sourceKey: string; stat: PlatformVulnSourceStat }) {
  const navigate = useNavigate();
  const total = stat.total;
  return (
    <div className="stat-card" style={{ minWidth: 200 }}>
      <div className="stat-title-row">
        <div className="stat-title">{sourceDisplayName(sourceKey)}</div>
      </div>
      <button
        type="button"
        className="btn-link"
        style={{ fontSize: '2rem', fontWeight: 700, lineHeight: 1, textAlign: 'left', color: 'inherit' }}
        onClick={() => navigate(intelPath(sourceKey))}
      >
        {total.toLocaleString()}
      </button>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 8 }}>
        {stat.critical > 0 && (
          <button type="button" className="severity-pill severity-critical" style={{ cursor: 'pointer' }} onClick={() => navigate(intelPath(sourceKey, 'CRITICAL'))}>
            {stat.critical.toLocaleString()} Critical
          </button>
        )}
        {stat.high > 0 && (
          <button type="button" className="severity-pill severity-high" style={{ cursor: 'pointer' }} onClick={() => navigate(intelPath(sourceKey, 'HIGH'))}>
            {stat.high.toLocaleString()} High
          </button>
        )}
        {stat.medium > 0 && (
          <button type="button" className="severity-pill severity-medium" style={{ cursor: 'pointer' }} onClick={() => navigate(intelPath(sourceKey, 'MEDIUM'))}>
            {stat.medium.toLocaleString()} Medium
          </button>
        )}
        {stat.low > 0 && (
          <button type="button" className="severity-pill severity-low" style={{ cursor: 'pointer' }} onClick={() => navigate(intelPath(sourceKey, 'LOW'))}>
            {stat.low.toLocaleString()} Low
          </button>
        )}
        {stat.unknown > 0 && (
          <button type="button" className="severity-pill" style={{ cursor: 'pointer' }} onClick={() => navigate(intelPath(sourceKey, 'UNKNOWN'))}>
            {stat.unknown.toLocaleString()} Unknown
          </button>
        )}
      </div>
    </div>
  );
}

function PlatformIntegrationRunCard({ sourceKey, status }: { sourceKey: string; status: VulnIntelSourceStatus }) {
  return (
    <div className="panel" style={{ padding: '12px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
        <strong>{sourceDisplayName(sourceKey)}</strong>
        <span className={sourceStatusClass(status.status)}>{sourceStatusLabel(status.status)}</span>
      </div>
      {status.completedAt ? (
        <div className="panel-caption" style={{ marginTop: 4 }}>
          Last run: {new Date(status.completedAt).toLocaleString()}
        </div>
      ) : null}
      <div className="panel-caption" style={{ marginTop: 4 }}>
        {status.recordsFetched > 0 && <span>Fetched: {status.recordsFetched.toLocaleString()} </span>}
        {status.recordsInserted > 0 && <span>· Inserted: {status.recordsInserted.toLocaleString()} </span>}
        {status.recordsUpdated > 0 && <span>· Updated: {status.recordsUpdated.toLocaleString()}</span>}
      </div>
      {status.errorMessage ? (
        <div className="notice error" style={{ marginTop: 6, fontSize: 12 }}>{status.errorMessage}</div>
      ) : null}
    </div>
  );
}

function PlatformDashboard() {
  const navigate = useNavigate();
  const sourceStatsQuery = usePlatformVulnSourceStatsQuery();
  const sourcesSummaryQuery = useVulnIntelSourcesSummaryQuery();
  const dashboardQuery = useVulnRepoDashboardQuery(true);

  const sourceStats = sourceStatsQuery.data?.sources ?? {};
  const sourcesSummary = sourcesSummaryQuery.data?.sources ?? {};
  const recentAdvisories: VulnRepoDashboardRecentAdvisoryItem[] = dashboardQuery.data?.recentAdvisories ?? [];

  return (
    <div className="page-grid vuln-repo-dashboard-page">
      <section className="panel vuln-repo-dashboard-panel">
        <div className="panel-header">
          <div className="vuln-repo-dashboard-section-copy">
            <h3>Vulnerability Counts by Source</h3>
            <div className="panel-caption">Total vulnerabilities ingested per intelligence source, grouped by severity</div>
          </div>
        </div>
        {sourceStatsQuery.isPending ? (
          <div className="panel-caption">Loading source stats...</div>
        ) : sourceStatsQuery.error ? (
          <div className="notice error">Failed to load source stats</div>
        ) : Object.keys(sourceStats).length === 0 ? (
          <div className="empty-state">No source data available yet.</div>
        ) : (
          <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
            {Object.entries(sourceStats).map(([key, stat]) => (
              <PlatformSourceStatsCard key={key} sourceKey={key} stat={stat} />
            ))}
          </div>
        )}
      </section>

      <section className="panel vuln-repo-dashboard-panel">
        <div className="panel-header">
          <div className="vuln-repo-dashboard-section-copy">
            <h3>Integration Run Status</h3>
            <div className="panel-caption">Last run status for each vulnerability intelligence source</div>
          </div>
        </div>
        {sourcesSummaryQuery.isPending ? (
          <div className="panel-caption">Loading run status...</div>
        ) : sourcesSummaryQuery.error ? (
          <div className="notice error">Failed to load integration run status</div>
        ) : Object.keys(sourcesSummary).length === 0 ? (
          <div className="empty-state">No integration runs recorded yet.</div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {Object.entries(sourcesSummary).map(([key, status]) => (
              <PlatformIntegrationRunCard key={key} sourceKey={key} status={status} />
            ))}
          </div>
        )}
      </section>

      <section className="panel vuln-repo-dashboard-panel">
        <div className="panel-header">
          <div className="vuln-repo-dashboard-section-copy">
            <h3>Recent advisories</h3>
            <div className="panel-caption">CISA KEV, NVD, and vendor updates</div>
          </div>
          <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('vulnerabilities'))}>View all</button>
        </div>
        {dashboardQuery.isPending ? (
          <div className="panel-caption">Loading advisories...</div>
        ) : (
          <div className="vuln-repo-dashboard-advisory-list">
            {recentAdvisories.length === 0 ? (
              <div className="empty-state">No recent advisories are available right now.</div>
            ) : (
              recentAdvisories.map((item) => (
                <button
                  key={`${item.externalId}-${item.lastModifiedAt ?? item.publishedAt ?? ''}`}
                  type="button"
                  className="vuln-repo-dashboard-advisory-item"
                  onClick={() => navigate(`/vuln-repo/intel/${encodeURIComponent(item.externalId)}`)}
                >
                  <div className="vuln-repo-dashboard-advisory-copy">
                    <strong>{item.externalId}</strong>
                    <p>{item.descriptionSnippet}</p>
                    <div className="vuln-repo-dashboard-item-tags">
                      <span className={severityClassName(item.severity)}>{formatSeverity(item.severity)}</span>
                      <span className="panel-caption">{item.source} · {advisoryRelativeTimeLabel(item.lastModifiedAt ?? item.publishedAt)}</span>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function TenantDashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const dashboardQuery = useVulnRepoDashboardQuery(false);

  const dashboard = dashboardQuery.data;
  const loading = dashboardQuery.isPending && !dashboard;
  const refreshing = dashboardQuery.isFetching && !!dashboard;
  const error = dashboardQuery.error instanceof Error ? dashboardQuery.error.message : '';
  const severityMax = React.useMemo(
    () => topCount(dashboard?.severityBreakdown ?? []),
    [dashboard?.severityBreakdown]
  );
  const topAffectedSoftware = React.useMemo(
    () =>
      [...(dashboard?.topAffectedSoftware ?? [])]
        .sort(
          (left, right) =>
            right.cveCount - left.cveCount ||
            right.criticalCount - left.criticalCount ||
            right.highCount - left.highCount ||
            left.software.localeCompare(right.software)
        )
        .slice(0, 5),
    [dashboard?.topAffectedSoftware]
  );
  const riskOverviewCard = dashboard ? (
    <div className="vuln-repo-dashboard-stat-button">
      <div className="stat-card">
        <div className="stat-title-row">
          <div className="stat-title">Risk Overview</div>
        </div>
        <div className="stat-caption">Severity distribution across tracked CVEs</div>
        <div className="vuln-repo-dashboard-risk-mini">
          {dashboard.severityBreakdown.map((item) => (
            <button
              key={item.severity}
              type="button"
              className="vuln-repo-dashboard-risk-row vuln-repo-dashboard-risk-row--link"
              onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ severity: item.severity }))}
            >
              <span>{formatSeverity(item.severity)}</span>
              <div className="vuln-repo-dashboard-risk-track">
                <span
                  className={severityBarClassName(item.severity)}
                  style={{ width: `${severityMax > 0 ? (item.count / severityMax) * 100 : 0}%` }}
                />
              </div>
              <strong>{formatNumber(item.count)}</strong>
            </button>
          ))}
        </div>
        <div className="vuln-repo-dashboard-risk-footer">
          <button
            type="button"
            className="status-pill status-warning"
            onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({ inKev: true }))}
          >
            {formatNumber(dashboard.summaryCards.exploitCount)} Exploits
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return (
    <div className="page-grid vuln-repo-dashboard-page">
      <PageFreshnessStatus
        updatedAt={dashboard?.generatedAt ?? dashboardQuery.dataUpdatedAt}
        isRefreshing={refreshing}
        refreshLabel="Refreshing vulnerability repository dashboard…"
      />

      {loading ? <div className="panel"><div className="panel-caption">Loading dashboard...</div></div> : null}
      {!dashboard && !loading && error ? <div className="panel"><div className="notice error">Failed to load dashboard: {error}</div></div> : null}

      {dashboard ? (
        <>
          {error ? <div className="notice error">Using cached dashboard data while refresh failed: {error}</div> : null}

          <div className="stats-grid vuln-repo-dashboard-stats-grid">
            <button
              type="button"
              className="vuln-repo-dashboard-stat-button"
              onClick={() => navigate(vulnRepoVulnerabilityPath({ applicable: true, createdSinceDays: 7 }))}
            >
              <div className="stat-card stat-neutral">
                <div className="stat-title-row">
                  <div className="stat-title">Added This Week</div>
                </div>
                <div className="stat-value">{formatNumber(dashboard.summaryCards.trackedAddedLastWeek)}</div>
                <div className="stat-caption">
                  <>
                    <div>{formatNumber(dashboard.summaryCards.applicableAddedLastWeek)} applicable</div>
                    <button
                      type="button"
                      className="btn-link stat-caption-link"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(vulnRepoVulnerabilityPath({ impactedOnly: true, createdSinceDays: 7 }));
                      }}
                    >
                      {formatNumber(dashboard.summaryCards.impactedAddedLastWeek)} impacted after investigation
                    </button>
                  </>
                  <button
                    type="button"
                    className="btn-link stat-caption-link stat-caption-link--kev"
                    onClick={(e) => {
                      e.stopPropagation();
                      navigate(vulnRepoVulnerabilityPath({ inKev: true, createdSinceDays: 7 }));
                    }}
                  >
                    {dashboard.summaryCards.kevAddedLastWeek > 0 ? '⚠\u00a0' : ''}{formatNumber(dashboard.summaryCards.kevAddedLastWeek)} in CISA KEV
                  </button>
                </div>
              </div>
            </button>
            <div className="vuln-repo-dashboard-stat-button vuln-repo-dashboard-funnel-card">
              <div className="stat-card">
                <div className="stat-card-label">CVE Funnel</div>
                <div className="vuln-repo-dashboard-funnel">
                  {[
                    {
                      label: 'Total CVEs',
                      value: dashboard.summaryCards.trackedCount,
                      percent: 100,
                      path: vulnRepoTrackedVulnerabilityPath(),
                    },
                    {
                      label: 'Applicable CVEs',
                      value: dashboard.summaryCards.applicableCount,
                      percent: percentOf(dashboard.summaryCards.applicableCount, dashboard.summaryCards.trackedCount),
                      path: vulnRepoTrackedVulnerabilityPath({ applicable: true }),
                    },
                    {
                      label: 'Impacted after investigation',
                      value: dashboard.summaryCards.impactedInvestigationDoneCount,
                      percent: percentOf(dashboard.summaryCards.impactedInvestigationDoneCount, dashboard.summaryCards.trackedCount),
                      path: vulnRepoVulnerabilityPath({ impactedOnly: true }),
                    },
                    {
                      label: 'Remediation CVEs',
                      value: dashboard.summaryCards.remediationCveCount,
                      percent: percentOf(dashboard.summaryCards.remediationCveCount, dashboard.summaryCards.trackedCount),
                      path: vulnRepoTrackedVulnerabilityPath({ hasFindings: true }),
                    },
                  ].map((item) => (
                    <button key={item.label} type="button" className="vuln-repo-dashboard-funnel-row" onClick={() => navigate(item.path)}>
                      <div className="vuln-repo-dashboard-funnel-copy">
                        <span>{item.label}</span>
                        <strong>{formatNumber(item.value)}</strong>
                      </div>
                      <div className="vuln-repo-dashboard-funnel-track">
                        <span style={{ width: `${item.percent}%` }} />
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
            {dashboard ? (
              <button
                type="button"
                className="vuln-repo-dashboard-stat-button"
                onClick={() => navigate(vulnRepoVulnerabilityPath({ impactedOnly: true, hasFindings: false }))}
              >
                <div className="stat-card stat-critical">
                  <div className="stat-title-row">
                    <div className="stat-title">Needs Attention</div>
                  </div>
                  <div className="stat-value">{formatNumber(dashboard.summaryCards.needsAttentionCount)}</div>
                  <div className="stat-caption">Investigated CVEs awaiting remediation workflow</div>
                  <div className="vuln-repo-attention-subscores">
                    <button
                      type="button"
                      className="btn-link vuln-repo-attention-subscore vuln-repo-attention-subscore--critical"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(vulnRepoVulnerabilityPath({ severity: 'CRITICAL', applicable: true }));
                      }}
                    >
                      <span className="vuln-repo-attention-subscore-value">{formatNumber(dashboard.summaryCards.criticalUninvestigatedCount)}</span>
                      <span className="vuln-repo-attention-subscore-label">critical CVEs uninvestigated</span>
                    </button>
                    <button
                      type="button"
                      className="btn-link vuln-repo-attention-subscore vuln-repo-attention-subscore--kev"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(vulnRepoVulnerabilityPath({ inKev: true, applicable: true }));
                      }}
                    >
                      <span className="vuln-repo-attention-subscore-value">{dashboard.summaryCards.kevReinvestigationCount > 0 ? '⚠\u00a0' : ''}{formatNumber(dashboard.summaryCards.kevReinvestigationCount)}</span>
                      <span className="vuln-repo-attention-subscore-label">KEV CVEs need reinvestigation</span>
                    </button>
                  </div>
                </div>
              </button>
            ) : null}
            {riskOverviewCard}
          </div>

          <div className="dashboard-grid vuln-repo-dashboard-main-grid">
            <section className="panel vuln-repo-dashboard-panel">
              <div className="panel-header">
                <div className="vuln-repo-dashboard-section-copy">
                  <h3>Critical unresolved</h3>
                  <div className="panel-caption">Requires immediate attention</div>
                </div>
                <button type="button" className="btn-link" onClick={() => navigate(findingsPath({ status: 'OPEN' }))}>View all</button>
              </div>
              <div className="vuln-repo-dashboard-unresolved-list">
                {dashboard.criticalUnresolved.length === 0 ? (
                  <div className="empty-state">No unresolved CVEs with created findings are available right now.</div>
                ) : (
                  dashboard.criticalUnresolved.map((item) => (
                    <article
                      key={item.externalId}
                      className="vuln-repo-dashboard-unresolved-item"
                    >
                      <div className="vuln-repo-dashboard-unresolved-copy">
                        <button
                          type="button"
                          className="btn-link vuln-repo-dashboard-cve-link mono"
                          onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}
                        >
                          {item.externalId}
                        </button>
                        {renderCriticalUnresolvedTags(item)}
                        <p>{item.title}</p>
                      </div>
                      <button
                        type="button"
                        className="vuln-repo-dashboard-findings-count btn-link"
                        onClick={(event) => {
                          event.stopPropagation();
                          navigate(findingsPath({ vulnerabilityId: item.externalId, status: 'OPEN' }));
                        }}
                      >
                        <strong>{formatNumber(item.findingCount)}</strong>
                        <span>findings</span>
                      </button>
                    </article>
                  ))
                )}
              </div>
            </section>

            <section className="panel vuln-repo-dashboard-panel">
              <div className="panel-header">
                <div className="vuln-repo-dashboard-section-copy">
                  <h3>Recent advisories</h3>
                  <div className="panel-caption">CISA KEV, NVD, and vendor updates</div>
                </div>
                <button type="button" className="btn-link" onClick={() => navigate(pathForVulnRepoView('vulnerabilities'))}>View all</button>
              </div>
              <div className="vuln-repo-dashboard-advisory-list">
                {dashboard.recentAdvisories.length === 0 ? (
                  <div className="empty-state">No recent advisories are available right now.</div>
                ) : (
                  dashboard.recentAdvisories.map((item) => (
                    <button
                      key={`${item.externalId}-${item.lastModifiedAt ?? item.publishedAt ?? ''}`}
                      type="button"
                      className="vuln-repo-dashboard-advisory-item"
                      onClick={() => navigate(pathForVulnRepoView('org-cves', item.externalId))}
                    >
                      <div className="vuln-repo-dashboard-advisory-copy">
                        <strong>{item.externalId}</strong>
                        <p>{item.descriptionSnippet}</p>
                        <div className="vuln-repo-dashboard-item-tags">
                          <span className={severityClassName(item.severity)}>{formatSeverity(item.severity)}</span>
                          <span className="panel-caption">{item.source} · {advisoryRelativeTimeLabel(item.lastModifiedAt ?? item.publishedAt)}</span>
                        </div>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </section>

          </div>

          <section className="panel vuln-repo-dashboard-panel">
            <div className="panel-header">
              <div className="vuln-repo-dashboard-section-copy">
                <h3>Repository context</h3>
                <div className="panel-caption">Explore concentration in affected software and the latest advisory movement.</div>
              </div>
            </div>
            <div className="vuln-repo-dashboard-context-grid">
              <div className="vuln-repo-dashboard-context-section">
                <div className="vuln-repo-dashboard-panel-block-header">
                  <h4>Top affected software</h4>
                  <div className="panel-caption">Sorted by tracked CVE count</div>
                </div>
                <button type="button" className="btn-link vuln-repo-dashboard-inline-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>Show all</button>
                <div className="vuln-repo-dashboard-software-list">
                  {topAffectedSoftware.length === 0 ? (
                    <div className="empty-state">No software exposure data is available yet.</div>
                  ) : (
                    topAffectedSoftware.map((item) => (
                      <div key={`${item.software}-${item.vendor}`} className="vuln-repo-dashboard-software-row">
                        <div className="vuln-repo-dashboard-software-copy">
                          <strong>{item.software}</strong>
                          <span>{item.vendor}</span>
                        </div>
                        <div className="vuln-repo-dashboard-software-metrics">
                          <div className="vuln-repo-dashboard-breakdown-bar">
                            <span className={severityBarClassName(item.highestSeverity)} style={{ width: '100%' }} />
                          </div>
                          <button
                            type="button"
                            className="btn-link vuln-repo-dashboard-count-link"
                            onClick={() => navigate(vulnRepoTrackedVulnerabilityPath({
                              software: item.software,
                              softwareScope: 'broad',
                              softwareIdentityId: item.softwareIdentityId,
                            }))}
                          >
                            {formatNumber(item.cveCount)}
                          </button>
                          <button
                            type="button"
                            className="btn-link vuln-repo-dashboard-count-link vuln-repo-dashboard-asset-link"
                            onClick={() => navigate(pathForVulnRepoSoftwareAssets(item.softwareIdentityId, item.software))}
                          >
                            {formatNumber(item.impactedAssetCount)} assets
                          </button>
                          <span className={severityClassName(item.highestSeverity)}>{formatSeverity(item.highestSeverity)}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

            </div>
          </section>

          <section className="panel vuln-repo-dashboard-panel">
            <div className="panel-header">
              <div className="vuln-repo-dashboard-section-copy">
                <h3>Impacted assets</h3>
                <div className="panel-caption">Hosts with unresolved CVEs</div>
              </div>
              <button
                type="button"
                className="btn-link"
                onClick={() => navigate(pathForInventoryView('hosts'))}
              >
                View all
              </button>
            </div>
            <div className="vuln-repo-dashboard-assets-grid">
              {dashboard.impactedAssets.length === 0 ? (
                <div className="empty-state">No impacted assets are available yet.</div>
              ) : (
                dashboard.impactedAssets.map((asset) => (
                  <button
                    key={asset.assetId}
                    type="button"
                    className="vuln-repo-dashboard-asset-card"
                    onClick={() => navigate(pathForVulnRepoHostAsset(asset.assetId, `${location.pathname}${location.search}${location.hash}`))}
                  >
                    <div className="vuln-repo-dashboard-asset-copy">
                      <strong>{asset.assetName}</strong>
                      <span>{asset.assetType.toLowerCase()} · {asset.identifier}</span>
                      {asset.environment ? <span>{asset.environment}</span> : null}
                    </div>
                    <span className="vuln-repo-dashboard-asset-count">{formatNumber(asset.cveCount)} CVEs</span>
                  </button>
                ))
              )}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}

export function VulnRepoDashboardPage() {
  const actor = useActor();
  const platformScope = !!actor?.platformScope && canAccessPlatformConsole(actor);
  return platformScope ? <PlatformDashboard /> : <TenantDashboard />;
}
