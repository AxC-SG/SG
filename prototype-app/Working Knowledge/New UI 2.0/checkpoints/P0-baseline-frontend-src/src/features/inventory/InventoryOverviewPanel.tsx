import React from 'react';

export type OverviewField = {
  label: string;
  value: React.ReactNode;
};

type InventoryOverviewPanelProps = {
  alerts?: React.ReactNode;
  primaryTitle?: string;
  primaryFields: OverviewField[];
  primaryFooter?: React.ReactNode;
  secondaryTitle?: string;
  secondaryFields?: OverviewField[];
};

/**
 * Generic 2-column "Overview" tab body for an inventory asset detail page: identity/
 * resource/ownership fields in the primary (left) column, free-form observed
 * attributes in the secondary (right) column. Shared shape across inventory types
 * (AI, host, ...) — only wired into AI inventory for now; other inventory detail
 * pages keep their own layout until they're moved onto this component too.
 */
export function InventoryOverviewPanel({
  alerts,
  primaryTitle = 'Resource details',
  primaryFields,
  primaryFooter,
  secondaryTitle = 'Observed facts',
  secondaryFields,
}: InventoryOverviewPanelProps) {
  return (
    <div className="iov-panel">
      {alerts && <div className="iov-alerts">{alerts}</div>}

      <div className="iov-columns">
        <div className="fd3-panel">
          <div className="fd3-panel-title">{primaryTitle}</div>
          <div className="fd3-panel-body fd3-kv-table">
            {primaryFields.map((field) => <OverviewRow key={field.label} field={field} />)}
          </div>
          {primaryFooter && <div className="iov-primary-footer">{primaryFooter}</div>}
        </div>

        {secondaryFields && secondaryFields.length > 0 && (
          <div className="fd3-panel">
            <div className="fd3-panel-title">{secondaryTitle}</div>
            <div className="fd3-panel-body fd3-kv-table">
              {secondaryFields.map((field) => <OverviewRow key={field.label} field={field} />)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function OverviewRow({ field }: { field: OverviewField }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{field.label}</span>
      <span className="fd3-kv-val">{field.value ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}
