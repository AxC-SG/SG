import { shouldPollAiRuns } from '../features/ai-security/assessment';
import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import { AI_ARTIFACT_CATEGORIES, isAgentVersionKind, combinedNativeKindFilterValue, stripProviderPrefix } from '../features/ai-security/categories';
import type { AiSeverityGridRow } from '../features/ai-security/types';
import { InventoryShell } from '../features/inventory/InventoryShell';
import { pathForAiBomDeclaredResources, pathForConnectView, pathForInventoryAiAsset, pathForInventoryAiAssets } from '../app/routes';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';

const MAX_GRID_ROWS = 10;
const CATEGORIZED_NATIVE_KINDS = new Set(AI_ARTIFACT_CATEGORIES.flatMap((category) => category.nativeKinds));

const SEVERITY_COLUMNS: Array<{ key: 'critical' | 'high' | 'medium' | 'low'; label: string }> = [
  { key: 'critical', label: 'Critical' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
];

type DisplayGridRow = {
  key: string;
  label: string;
  filterValue: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
};

function sumRows(rows: AiSeverityGridRow[], key: 'critical' | 'high' | 'medium' | 'low' | 'total'): number {
  return rows.reduce((total, row) => total + row[key], 0);
}

/** Rolls per-native-kind severity rows up into the cross-provider categories, keeps the
 * remaining kinds as their own rows (sorted by volume), and folds any overflow beyond
 * maxRows into a single "Other" row so the grid never grows past the cap. */
function buildDisplayGridRows(rows: AiSeverityGridRow[], maxRows: number): DisplayGridRow[] {
  const byNativeKind = new Map(rows.map((row) => [row.nativeKind, row]));

  const categoryRows: DisplayGridRow[] = AI_ARTIFACT_CATEGORIES.map((category) => {
    const members = category.nativeKinds
      .map((kind) => byNativeKind.get(kind))
      .filter((row): row is AiSeverityGridRow => row != null);
    return {
      key: category.key,
      label: category.label,
      filterValue: combinedNativeKindFilterValue(category.nativeKinds),
      critical: sumRows(members, 'critical'),
      high: sumRows(members, 'high'),
      medium: sumRows(members, 'medium'),
      low: sumRows(members, 'low'),
      total: sumRows(members, 'total'),
    };
  });

  const remaining = rows
    .filter((row) => !CATEGORIZED_NATIVE_KINDS.has(row.nativeKind) && !isAgentVersionKind(row.nativeKind))
    .sort((a, b) => b.total - a.total);
  const remainingBudget = Math.max(0, maxRows - categoryRows.length);
  const hasOverflow = remaining.length > remainingBudget;
  const individualRemaining = hasOverflow ? remaining.slice(0, Math.max(0, remainingBudget - 1)) : remaining;
  const overflow = remaining.slice(individualRemaining.length);

  const individualRows: DisplayGridRow[] = individualRemaining.map((row) => ({
    key: row.nativeKind,
    label: stripProviderPrefix(row.nativeKind),
    filterValue: row.nativeKind,
    critical: row.critical,
    high: row.high,
    medium: row.medium,
    low: row.low,
    total: row.total,
  }));

  const overflowRows: DisplayGridRow[] = overflow.length === 0 ? [] : [{
    key: 'OTHER',
    label: `Other (${overflow.length})`,
    filterValue: combinedNativeKindFilterValue(overflow.map((row) => row.nativeKind)),
    critical: sumRows(overflow, 'critical'),
    high: sumRows(overflow, 'high'),
    medium: sumRows(overflow, 'medium'),
    low: sumRows(overflow, 'low'),
    total: sumRows(overflow, 'total'),
  }];

  return [...categoryRows, ...individualRows, ...overflowRows];
}

function severityGridBand(count: number, max: number): 'low' | 'medium' | 'high' {
  if (max <= 0 || count <= 0) return 'low';
  const ratio = count / max;
  if (ratio >= 0.66) return 'high';
  if (ratio >= 0.33) return 'medium';
  return 'low';
}

function findingsPath(params: { severity?: string; nativeKind?: string }): string {
  const search = new URLSearchParams();
  if (params.severity) search.set('severity', params.severity);
  if (params.nativeKind) search.set('nativeKind', params.nativeKind);
  const query = search.toString();
  return query ? `/findings/ai?${query}` : '/findings/ai';
}

export function AiInventoryPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const runsQuery = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: () => api.listAiSecurityRuns(),
    refetchInterval: (query) => shouldPollAiRuns(query.state.data as Array<{ status: string; assessmentStatus?: 'PENDING' | 'RUNNING' | 'COMPLETE' | 'PARTIAL' | 'FAILED' }> | undefined)
      ? RUN_QUEUE_REFRESH_INTERVAL_MS
      : false,
  });
  const shouldPoll = shouldPollAiRuns(runsQuery.data);
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const coverageQuery = useQuery({
    queryKey: ['ai-grid-coverage'],
    queryFn: api.getAiGridCoverage,
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const topRiskArtifactsQuery = useQuery({
    queryKey: ['ai-security-top-risk-artifacts'],
    queryFn: () => api.getAiTopRiskArtifacts(5),
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const severityGridQuery = useQuery({
    queryKey: ['ai-security-severity-grid'],
    queryFn: api.getAiSeverityGrid,
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });

  const summary = summaryQuery.data;
  const coverage = coverageQuery.data;

  const gridRows = severityGridQuery.data?.rows ?? [];
  const displayGridRows = buildDisplayGridRows(gridRows, MAX_GRID_ROWS);
  const gridMax = Math.max(1, ...displayGridRows.flatMap((row) => [row.critical, row.high, row.medium, row.low]));
  const severityTotals = gridRows.reduce(
    (totals, row) => ({
      critical: totals.critical + row.critical,
      high: totals.high + row.high,
      medium: totals.medium + row.medium,
      low: totals.low + row.low,
    }),
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
  const severityMax = Math.max(1, severityTotals.critical, severityTotals.high, severityTotals.medium, severityTotals.low);

  const topRiskAssets = topRiskArtifactsQuery.data ?? [];
  const topRiskMax = Math.max(1, ...topRiskAssets.map((item) => item.score));

  const providerRows = Object.entries(summary?.providerCounts ?? {}).sort(([, a], [, b]) => b - a);
  const providerMax = Math.max(1, ...providerRows.map(([, count]) => count));

  const incompleteScopes = summary?.incompleteScopes ?? 0;
  const unsupportedEvidence = coverage?.unsupported ?? 0;

  return (
    <InventoryShell
      eyebrow="AWS and Azure AI estate"
      title="AI Inventory"
      description="Tenant-scoped cloud AI resources with explicit evidence coverage and discovery limits."
      legacyClassName="ai-security-page"
    >
      <PageFreshnessStatus updatedAt={summary?.lastCompleteSnapshotAt} />

      <div className="ai-severity-grid-row">
        <section className="panel ai-security-table-panel ai-severity-grid--compact">
          <div className="panel-header">
            <div>
              <h3>Severity Grid</h3>
              <p className="panel-caption">AI artifacts with an open finding, by artifact category and severity</p>
            </div>
          </div>
          {displayGridRows.length === 0 ? (
            <div className="empty-state"><p>No open AI findings to grid.</p></div>
          ) : (
            <table className="grid-exposure-table">
              <thead>
                <tr>
                  <th>Artifact category</th>
                  {SEVERITY_COLUMNS.map((column) => <th key={column.key}>{column.label}</th>)}
                  <th>Total</th>
                </tr>
              </thead>
              <tbody>
                {displayGridRows.map((row) => (
                  <tr key={row.key}>
                    <td className="grid-exposure-row-label">{row.label}</td>
                    {SEVERITY_COLUMNS.map((column) => {
                      const count = row[column.key];
                      const band = severityGridBand(count, gridMax);
                      return (
                        <td key={column.key} className={`grid-exposure-cell grid-exposure-cell--${band}`}>
                          <button
                            type="button"
                            className="grid-exposure-cell-btn"
                            disabled={count === 0}
                            onClick={() => navigate(pathForInventoryAiAssets({
                              nativeKind: row.filterValue,
                              severity: column.key.toUpperCase(),
                            }))}
                          >
                            {count.toLocaleString()}
                          </button>
                        </td>
                      );
                    })}
                    <td className="grid-exposure-total">{row.total.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <div className="ai-severity-grid-side">
          <div className="fpl-widget">
            <div className="fpl-widget-title">By Provider</div>
            <div className="fpl-widget-body">
              {providerRows.length === 0 ? (
                <p className="panel-caption">No provider data yet.</p>
              ) : providerRows.map(([providerName, count]) => (
                <button
                  key={providerName}
                  type="button"
                  className="fpl-hbar-row"
                  onClick={() => navigate(pathForInventoryAiAssets({ provider: providerName }))}
                >
                  <span className="fpl-hbar-label">{providerName}</span>
                  <span className="fpl-hbar-track">
                    <span className="fpl-hbar-fill inventory-hbar-accent" style={{ width: `${(count / providerMax) * 100}%` }} />
                  </span>
                  <strong className="fpl-hbar-val">{count.toLocaleString()}</strong>
                </button>
              ))}
            </div>
          </div>

          <button type="button" className="fpl-widget" onClick={() => navigate(pathForConnectView('run-history'))}>
            <div className="fpl-widget-title">Coverage Gaps</div>
            <div className="fpl-kpi-grid">
              <div className="fpl-kpi-card">
                <strong className="fpl-kpi-num">{incompleteScopes.toLocaleString()}</strong>
                <span className="fpl-kpi-label">Incomplete scopes</span>
              </div>
              <div className="fpl-kpi-card">
                <strong className="fpl-kpi-num">{unsupportedEvidence.toLocaleString()}</strong>
                <span className="fpl-kpi-label">Unsupported evidence</span>
              </div>
              <div className="fpl-kpi-card">
                <strong className="fpl-kpi-num">{(summary?.openFindings ?? 0).toLocaleString()}</strong>
                <span className="fpl-kpi-label">Open findings</span>
              </div>
            </div>
          </button>

          <button type="button" className="fpl-widget" onClick={() => navigate(pathForAiBomDeclaredResources())}>
            <div className="fpl-widget-title">AI-BOM Declared Resources</div>
            <p>Models and datasets declared by an uploaded AI-BOM, their deployment-linking coverage, and setup actions.</p>
          </button>
        </div>
      </div>

      <div className="fpl-widgets">
        <button type="button" className="fpl-widget" onClick={() => navigate('/policies')}>
          <div className="fpl-widget-title">Policy Coverage &amp; Risk</div>
          <div className="fpl-kpi-grid">
            <div className="fpl-kpi-card">
              <strong className="fpl-kpi-num">{Math.round(coverage?.ownerFacingDecisionReachabilityPercent ?? 0)}%</strong>
              <span className="fpl-kpi-label">Policy coverage</span>
            </div>
            <div className="fpl-kpi-card">
              <strong className="fpl-kpi-num">{(coverage?.evaluatedFail ?? 0).toLocaleString()}</strong>
              <span className="fpl-kpi-label">Failing checks</span>
            </div>
            <div className="fpl-kpi-card">
              <strong className="fpl-kpi-num">{(coverage?.artifactsFailing ?? 0).toLocaleString()}</strong>
              <span className="fpl-kpi-label">Artifacts failed</span>
            </div>
            <div className="fpl-kpi-card">
              <strong className="fpl-kpi-num">{(coverage?.unsupported ?? 0).toLocaleString()}</strong>
              <span className="fpl-kpi-label">Unsupported evidence</span>
            </div>
          </div>
        </button>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Top 5 Assets at Risk</div>
          <div className="fpl-widget-body">
            {topRiskAssets.length === 0 ? (
              <p className="panel-caption">No AI artifacts have an open finding.</p>
            ) : topRiskAssets.map((item) => (
              <button
                key={item.id}
                type="button"
                className="fpl-hbar-row"
                onClick={() => navigate(pathForInventoryAiAsset(item.id, `${location.pathname}${location.search}`))}
              >
                <span className="fpl-hbar-label">{item.name}</span>
                <span className="fpl-hbar-track">
                  <span className="fpl-hbar-fill" style={{ width: `${(item.score / topRiskMax) * 100}%` }} />
                </span>
                <strong className="fpl-hbar-val">{item.score}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Findings by Severity</div>
          <div className="fpl-widget-body">
            {SEVERITY_COLUMNS.map((column) => (
              <button
                key={column.key}
                type="button"
                className="fpl-hbar-row"
                onClick={() => navigate(findingsPath({ severity: column.key.toUpperCase() }))}
              >
                <span className="fpl-hbar-label">{column.label}</span>
                <span className="fpl-hbar-track">
                  <span className="fpl-hbar-fill" style={{ width: `${(severityTotals[column.key] / severityMax) * 100}%` }} />
                </span>
                <strong className="fpl-hbar-val">{severityTotals[column.key].toLocaleString()}</strong>
              </button>
            ))}
          </div>
        </div>
      </div>
    </InventoryShell>
  );
}
