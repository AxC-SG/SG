import React from 'react';
import { AsyncSection } from '../../../components/AsyncSection';
import { MetricValue, type MetricAvailability } from '../../../components/MetricValue';
import { ChartLegend, DonutChart, HBarChart, WidgetCard } from '../../widgets/FplWidgets';
import type { ColFilters } from '../../../pages/FindingsPage';
import type { FindingSummary } from '../types';

type DueDateBand = 'overdue' | 'due-soon' | 'on-track' | 'no-sla' | null;

// ready: loaded; stale: loaded, but the latest refresh failed; error: never loaded.
export type SourceState = 'pending' | 'ready' | 'stale' | 'error';

type Props = {
  colFilters: ColFilters;
  dueDateBand: DueDateBand;
  severityCounts: Map<string, number>;
  statusCounts: Map<string, number>;
  assetCounts: ReadonlyArray<readonly [string, number]>;
  dueDateCounts: { overdue: number; dueSoon: number; onTrack: number; noSla: number };
  summary?: FindingSummary;
  summaryState: SourceState;
  distributionsState: SourceState;
  backlogState: SourceState;
  onRetrySummary: () => void;
  onRetryDistributions: () => void;
  onRetryBacklog: () => void;
  severityColors: Record<string, string>;
  statusColors: Record<string, string>;
  formatLabel: (value: string) => string;
  onFilterBySeverity: (severity: string) => void;
  onFilterByStatus: (status: string) => void;
  onFilterByAsset: (assetName: string) => void;
  onFilterByDueBand: (band: DueDateBand) => void;
  onCriticalOpenClick: () => void;
  onUnassignedClick: () => void;
  onWithIncidentsClick: () => void;
};

function SourceSection({ state, label, onRetry, children }: { state: SourceState; label: string; onRetry: () => void; children: React.ReactNode }) {
  return (
    <AsyncSection
      state={state === 'pending' ? 'pending' : state === 'error' ? 'error' : 'ready'}
      loadingLabel={`Loading ${label}…`}
      errorMessage={`${label[0].toUpperCase()}${label.slice(1)} could not be loaded.`}
      refreshError={state === 'stale' ? `${label[0].toUpperCase()}${label.slice(1)} could not be refreshed; showing the last loaded values.` : undefined}
      onRetry={onRetry}
    >
      {children}
    </AsyncSection>
  );
}

function availabilityOf(state: SourceState): MetricAvailability {
  return state === 'pending' ? 'pending' : state === 'error' ? 'unavailable' : 'available';
}

export function FindingsSummaryWidgets({
  colFilters,
  dueDateBand,
  severityCounts,
  statusCounts,
  assetCounts,
  dueDateCounts,
  summary,
  summaryState,
  distributionsState,
  backlogState,
  onRetrySummary,
  onRetryDistributions,
  onRetryBacklog,
  severityColors,
  statusColors,
  formatLabel,
  onFilterBySeverity,
  onFilterByStatus,
  onFilterByAsset,
  onFilterByDueBand,
  onCriticalOpenClick,
  onUnassignedClick,
  onWithIncidentsClick,
}: Props) {
  const kpis: Array<{ label: string; value: number | undefined; state: SourceState; color: string; onClick: () => void }> = [
    { label: 'Critical Open', value: summary?.criticalOpenCount, state: summaryState, color: '#ef4444', onClick: onCriticalOpenClick },
    { label: 'Unassigned remediation', value: summary?.unassignedOpenCount, state: summaryState, color: '#f97316', onClick: onUnassignedClick },
    { label: 'With Incidents', value: summary?.withIncidentCount, state: summaryState, color: '#3b82f6', onClick: onWithIncidentsClick },
    { label: 'Overdue', value: backlogState === 'error' ? undefined : dueDateCounts.overdue, state: backlogState, color: '#b91c1c', onClick: () => onFilterByDueBand('overdue') },
  ];

  return (
    <div className="fpl-widgets">
      <WidgetCard title="Exposure by Severity" active={colFilters.severity.length > 0 && colFilters.severity.length < 6}>
        <SourceSection state={distributionsState} label="severity counts" onRetry={onRetryDistributions}>
          <div className="fpl-widget-donut-layout">
            <DonutChart
              size={90}
              sw={16}
              segs={(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const).map((severity) => ({
                key: severity,
                label: severity,
                value: severityCounts.get(severity) ?? 0,
                color: severityColors[severity],
                onClick: () => onFilterBySeverity(severity),
              }))}
            />
            <ChartLegend
              items={(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const)
                .filter((severity) => (severityCounts.get(severity) ?? 0) > 0)
                .map((severity) => ({
                  key: severity,
                  label: severity,
                  value: severityCounts.get(severity) ?? 0,
                  color: severityColors[severity],
                  active: colFilters.severity.includes(severity),
                  onClick: () => onFilterBySeverity(severity),
                }))}
            />
          </div>
        </SourceSection>
      </WidgetCard>

      <WidgetCard title="Findings by Status" active={colFilters.status.length > 0 && colFilters.status.length < 4}>
        <SourceSection state={distributionsState} label="status counts" onRetry={onRetryDistributions}>
          <HBarChart
            activeKey={colFilters.status.length === 1 ? colFilters.status[0] : undefined}
            items={(['OPEN', 'RESOLVED', 'SUPPRESSED', 'AUTO_CLOSED'] as const).map((status) => ({
              key: status,
              label: status === 'SUPPRESSED' ? 'Deferred / Suppressed' : status === 'AUTO_CLOSED' ? 'Closed' : formatLabel(status),
              value: statusCounts.get(status) ?? 0,
              color: statusColors[status],
              onClick: () => onFilterByStatus(status),
            }))}
          />
        </SourceSection>
      </WidgetCard>

      <WidgetCard title="Top Assets at Risk" active={!!colFilters.asset}>
        <SourceSection state={distributionsState} label="affected assets" onRetry={onRetryDistributions}>
          {assetCounts.length === 0 ? (
            <div className="fpl-widget-empty">No open findings</div>
          ) : (
            <HBarChart
              activeKey={colFilters.asset || undefined}
              items={assetCounts.map(([name, count], index) => ({
                key: name,
                label: name,
                value: count,
                color: ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#ddd6fe'][index] ?? '#6366f1',
                onClick: () => onFilterByAsset(name),
              }))}
            />
          )}
        </SourceSection>
      </WidgetCard>

      <WidgetCard title="SLA & Due Date" active={!!dueDateBand}>
        <SourceSection state={backlogState} label="SLA health" onRetry={onRetryBacklog}>
          <HBarChart
            activeKey={dueDateBand ?? undefined}
            items={[
              { key: 'overdue', label: 'Overdue', value: dueDateCounts.overdue, color: '#ef4444', onClick: () => onFilterByDueBand('overdue') },
              { key: 'due-soon', label: 'Due in 7 days', value: dueDateCounts.dueSoon, color: '#f97316', onClick: () => onFilterByDueBand('due-soon') },
              { key: 'on-track', label: 'On Track', value: dueDateCounts.onTrack, color: '#22c55e', onClick: () => onFilterByDueBand('on-track') },
              { key: 'no-sla', label: 'No SLA Set', value: dueDateCounts.noSla, color: '#9ca3af', onClick: () => onFilterByDueBand('no-sla') },
            ]}
          />
        </SourceSection>
      </WidgetCard>

      <WidgetCard title="Key Indicators">
        {summaryState === 'error' && (
          <div className="notice error async-section-notice" role="alert">
            <span>Key indicators could not be loaded.</span>
            <button type="button" className="btn btn-sm" onClick={onRetrySummary}>Retry</button>
          </div>
        )}
        <div className="fpl-kpi-grid">
          {kpis.map((kpi) => (
            <button
              key={kpi.label}
              type="button"
              className="fpl-kpi-card"
              onClick={kpi.onClick}
              style={{ '--kpi-color': kpi.color } as React.CSSProperties}
            >
              <span className="fpl-kpi-num">
                <MetricValue availability={availabilityOf(kpi.state)} value={kpi.value} unavailableReason={`${kpi.label} unavailable`} />
              </span>
              <span className="fpl-kpi-label">{kpi.label}</span>
            </button>
          ))}
        </div>
      </WidgetCard>
    </div>
  );
}
