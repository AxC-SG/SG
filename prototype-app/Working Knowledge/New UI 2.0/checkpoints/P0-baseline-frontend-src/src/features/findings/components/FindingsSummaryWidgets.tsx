import React from 'react';
import { DonutChart, HBarChart, WidgetCard } from '../../widgets/FplWidgets';
import type { ColFilters } from '../../../pages/FindingsPage';
import type { FindingSummary } from '../types';

type DueDateBand = 'overdue' | 'due-soon' | 'on-track' | 'no-sla' | null;

type Props = {
  colFilters: ColFilters;
  dueDateBand: DueDateBand;
  severityCounts: Map<string, number>;
  statusCounts: Map<string, number>;
  assetCounts: ReadonlyArray<readonly [string, number]>;
  dueDateCounts: { overdue: number; dueSoon: number; onTrack: number; noSla: number };
  summary?: FindingSummary;
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

export function FindingsSummaryWidgets({
  colFilters,
  dueDateBand,
  severityCounts,
  statusCounts,
  assetCounts,
  dueDateCounts,
  summary,
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
  return (
    <div className="fpl-widgets">
      <WidgetCard title="Exposure by Severity" active={colFilters.severity.length > 0 && colFilters.severity.length < 6}>
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
          <div className="fpl-widget-legend">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'] as const).map((severity) => {
              const count = severityCounts.get(severity) ?? 0;
              if (!count) return null;
              return (
                <div
                  key={severity}
                  className={`fpl-legend-row${colFilters.severity.includes(severity) ? ' fpl-legend-row--active' : ''}`}
                  onClick={() => onFilterBySeverity(severity)}
                >
                  <span className="fpl-legend-dot" style={{ background: severityColors[severity] }} />
                  <span className="fpl-legend-label">{severity}</span>
                  <strong className="fpl-legend-val">{count}</strong>
                </div>
              );
            })}
          </div>
        </div>
      </WidgetCard>

      <WidgetCard title="Findings by Status" active={colFilters.status.length > 0 && colFilters.status.length < 4}>
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
      </WidgetCard>

      <WidgetCard title="Top Assets at Risk" active={!!colFilters.asset}>
        {assetCounts.length === 0 ? (
          <div className="fpl-widget-empty">No open findings</div>
        ) : (
          <HBarChart
            activeKey={colFilters.asset || undefined}
            items={assetCounts.map(([name, count], index) => ({
              key: name,
              label: name.length > 18 ? `${name.slice(0, 16)}…` : name,
              value: count,
              color: ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#ddd6fe'][index] ?? '#6366f1',
              onClick: () => onFilterByAsset(name),
            }))}
          />
        )}
      </WidgetCard>

      <WidgetCard title="SLA & Due Date" active={!!dueDateBand}>
        <HBarChart
          activeKey={dueDateBand ?? undefined}
          items={[
            { key: 'overdue', label: 'Overdue', value: dueDateCounts.overdue, color: '#ef4444', onClick: () => onFilterByDueBand('overdue') },
            { key: 'due-soon', label: 'Due in 7 days', value: dueDateCounts.dueSoon, color: '#f97316', onClick: () => onFilterByDueBand('due-soon') },
            { key: 'on-track', label: 'On Track', value: dueDateCounts.onTrack, color: '#22c55e', onClick: () => onFilterByDueBand('on-track') },
            { key: 'no-sla', label: 'No SLA Set', value: dueDateCounts.noSla, color: '#9ca3af', onClick: () => onFilterByDueBand('no-sla') },
          ]}
        />
      </WidgetCard>

      <WidgetCard title="Key Indicators">
        <div className="fpl-kpi-grid">
          {[
            { label: 'Critical Open', value: summary?.criticalOpenCount ?? 0, color: '#ef4444', onClick: onCriticalOpenClick },
            { label: 'Unassigned remediation', value: summary?.unassignedOpenCount ?? 0, color: '#f97316', onClick: onUnassignedClick },
            { label: 'With Incidents', value: summary?.withIncidentCount ?? 0, color: '#3b82f6', onClick: onWithIncidentsClick },
            { label: 'Overdue', value: dueDateCounts.overdue, color: '#b91c1c', onClick: () => onFilterByDueBand('overdue') },
          ].map((kpi) => (
            <div key={kpi.label} className="fpl-kpi-card" onClick={kpi.onClick} style={{ '--kpi-color': kpi.color } as React.CSSProperties}>
              <div className="fpl-kpi-num">{kpi.value}</div>
              <div className="fpl-kpi-label">{kpi.label}</div>
            </div>
          ))}
        </div>
      </WidgetCard>
    </div>
  );
}
