import React from 'react';
import { useEolSummaryQuery } from '../features/eol/queries';

type EolRiskWidgetProps = {
  onViewAll?: () => void;
};

export function EolRiskWidget({ onViewAll }: EolRiskWidgetProps) {
  const summaryQuery = useEolSummaryQuery();
  const summary = summaryQuery.data;

  if (summaryQuery.error) {
    return (
      <section className="panel eol-widget">
        <div className="panel-header">
          <h3>End-of-Life Software</h3>
        </div>
        <div className="panel-caption">Failed to load EOL data</div>
      </section>
    );
  }

  return (
    <section className="panel eol-widget">
      <div className="panel-header">
        <h3>End-of-Life Software</h3>
        <span className="panel-caption">Active inventory components</span>
      </div>

      {!summary ? (
        <div className="panel-caption">Loading...</div>
      ) : (
        <>
          <div className="eol-widget-rows">
            <div className="eol-widget-row eol-widget-row-eol">
              <span className="eol-widget-dot eol-dot-eol" aria-hidden="true" />
              <span className="eol-widget-label">End of Life</span>
              <span className="eol-widget-count">{summary.eolCount.toLocaleString()}</span>
            </div>
            <div className="eol-widget-row eol-widget-row-warn">
              <span className="eol-widget-dot eol-dot-warn" aria-hidden="true" />
              <span className="eol-widget-label">EOL within 90 days</span>
              <span className="eol-widget-count">{summary.nearEolCount.toLocaleString()}</span>
            </div>
            <div className="eol-widget-row eol-widget-row-ok">
              <span className="eol-widget-dot eol-dot-ok" aria-hidden="true" />
              <span className="eol-widget-label">Supported</span>
              <span className="eol-widget-count">{summary.supportedCount.toLocaleString()}</span>
            </div>
            <div className="eol-widget-row eol-widget-row-unknown">
              <span className="eol-widget-dot eol-dot-unknown" aria-hidden="true" />
              <span className="eol-widget-label">Unknown</span>
              <span className="eol-widget-count">{summary.unknownCount.toLocaleString()}</span>
            </div>
          </div>

          {onViewAll && (summary.eolCount > 0 || summary.nearEolCount > 0) && (
            <div className="eol-widget-footer">
              <button type="button" className="btn btn-secondary eol-widget-cta" onClick={onViewAll}>
                View EOL Components →
              </button>
            </div>
          )}
        </>
      )}
    </section>
  );
}
