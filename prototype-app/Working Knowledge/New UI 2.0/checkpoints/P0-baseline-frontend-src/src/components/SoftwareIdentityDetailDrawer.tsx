import React from 'react';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from './DataTable';
import { useSoftwareIdentityDetailQuery } from '../features/software-identities/queries';
import type { SoftwareIdentityDetail } from '../features/software-identities/types';
import { EolBadge } from './EolBadge';

type Props = {
  softwareIdentityId: string;
  onClose: () => void;
};

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return parsed.toLocaleString();
}

function joinValues(values: string[]): string {
  return values.length === 0 ? '-' : values.join(', ');
}

function lifecycleLabel(detail: SoftwareIdentityDetail): string {
  if (detail.eolComponentCount > 0) {
    return `${detail.eolComponentCount} EOL`;
  }
  if (detail.nearEolComponentCount > 0) {
    return `${detail.nearEolComponentCount} near EOL`;
  }
  if (detail.unknownEolComponentCount > 0) {
    return `${detail.unknownEolComponentCount} unknown`;
  }
  return 'Supported';
}

export function SoftwareIdentityDetailDrawer({ softwareIdentityId, onClose }: Props) {
  const detailQuery = useSoftwareIdentityDetailQuery(softwareIdentityId);
  const detail = detailQuery.data;
  const error = detailQuery.error instanceof Error ? detailQuery.error.message : null;
  const versionColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
    { id: 'lifecycle', label: 'Lifecycle', header: 'Lifecycle', initialSize: 220 },
    { id: 'footprint', label: 'Footprint', header: 'Footprint', initialSize: 180 },
    { id: 'exposure', label: 'Open Exposure', header: 'Open Exposure', initialSize: 180 },
    { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 }
  ], []);
  const assetColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 220 },
    { id: 'component', label: 'Component', header: 'Component', initialSize: 220 },
    { id: 'source', label: 'Source', header: 'Source', initialSize: 140 },
    { id: 'lifecycle', label: 'Lifecycle', header: 'Lifecycle', initialSize: 220 },
    { id: 'exposure', label: 'Open Exposure', header: 'Open Exposure', initialSize: 180 },
    { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 }
  ], []);
  const versionRows = React.useMemo<DataTableRow[]>(() => (
    (detail?.versions ?? []).map((versionRow, index) => ({
      id: `${versionRow.version || 'unknown'}-${index}`,
      cells: {
        version: { content: <span className="mono">{versionRow.version || '(unknown)'}</span> },
        lifecycle: {
          content: (
            <div className="software-identity-row-stack">
              <EolBadge
                isEol={versionRow.isEol}
                daysRemaining={versionRow.eolDaysRemaining}
                eolDate={versionRow.eolDate}
              />
              <span className="panel-caption mono">
                {(versionRow.eolSlug || '-')}{versionRow.eolCycle ? ` / ${versionRow.eolCycle}` : ''}
              </span>
            </div>
          )
        },
        footprint: {
          content: `${versionRow.assetCount} assets · ${versionRow.componentCount} components`
        },
        exposure: {
          content: `${versionRow.openVulnerabilityCount} CVEs · ${versionRow.openFindingCount} findings`
        },
        lastObserved: { content: formatInstant(versionRow.lastObservedAt) }
      }
    }))
  ), [detail?.versions]);
  const assetRows = React.useMemo<DataTableRow[]>(() => (
    (detail?.assets ?? []).map((assetRow) => ({
      id: assetRow.componentId,
      cells: {
        asset: {
          content: (
            <>
              <div>{assetRow.assetName}</div>
              <div className="panel-caption mono">{assetRow.assetIdentifier}</div>
              <div className="panel-caption">{assetRow.assetType}</div>
            </>
          )
        },
        component: {
          content: (
            <>
              <div>{assetRow.packageName}</div>
              <div className="panel-caption mono">
                {(assetRow.ecosystem || '-')}{assetRow.version ? `@${assetRow.version}` : ''}
              </div>
            </>
          )
        },
        source: { content: assetRow.sourceSystem || '-' },
        lifecycle: {
          content: (
            <div className="software-identity-row-stack">
              <EolBadge
                isEol={assetRow.isEol}
                daysRemaining={assetRow.eolDaysRemaining}
                eolDate={assetRow.eolDate}
              />
              <span className="panel-caption mono">
                {(assetRow.eolSlug || '-')}{assetRow.eolCycle ? ` / ${assetRow.eolCycle}` : ''}
              </span>
            </div>
          )
        },
        exposure: {
          content: `${assetRow.openVulnerabilityCount} CVEs · ${assetRow.openFindingCount} findings`
        },
        lastObserved: { content: formatInstant(assetRow.lastObservedAt) }
      }
    }))
  ), [detail?.assets]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide" onClick={(event) => event.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>Software Identity Detail</h3>
            {detail && (
              <>
                <div>{detail.displayName}</div>
                <div className="panel-caption mono">{detail.canonicalKey}</div>
              </>
            )}
          </div>
          <div className="button-row">
            {detail && detail.eolSlug && <span className="panel-caption mono">EOL: {detail.eolSlug}</span>}
            <button
              type="button"
              className="modal-close-btn"
              onClick={onClose}
              aria-label="Close software identity detail"
            >
              x
            </button>
          </div>
        </div>

        {error && <div className="notice error">Unable to load software identity detail: {error}</div>}
        {!detail && !error && <div className="notice">Loading software identity detail...</div>}

        {detail && (
          <>
            <div className="host-summary-grid">
              <div className="summary-card">
                <strong>Identity</strong>
                <span>{detail.displayName}</span>
                <span className="panel-caption">{detail.vendor || '-'} / {detail.product || '-'}</span>
              </div>
              <div className="summary-card">
                <strong>Identifiers</strong>
                <span className="mono">{detail.purl || '-'}</span>
                <span className="panel-caption mono">{detail.cpe23 || '-'}</span>
              </div>
              <div className="summary-card">
                <strong>Footprint</strong>
                <span>{detail.assetCount} assets</span>
                <span className="panel-caption">{detail.componentCount} components · {detail.versionCount} versions</span>
              </div>
              <div className="summary-card">
                <strong>Exposure</strong>
                <span>{detail.openVulnerabilityCount} open CVEs</span>
                <span className="panel-caption">{detail.openFindingCount} open findings</span>
              </div>
              <div className="summary-card">
                <strong>Lifecycle</strong>
                <span>{lifecycleLabel(detail)}</span>
                <span className="panel-caption">Mapped slug: {detail.eolSlug || 'None'}</span>
                <span className="panel-caption">
                  {detail.needsEolMapping
                    ? 'Needs EOL mapping review'
                    : detail.mappingConfirmed
                      ? 'Manual override confirmed'
                      : 'Mapping resolved'}
                </span>
              </div>
            </div>

            <div className="software-identity-drawer-meta">
              <div className="software-identity-drawer-meta-item">
                <strong>Asset Types</strong>
                <span>{joinValues(detail.assetTypes)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Ecosystems</strong>
                <span>{joinValues(detail.ecosystems)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Sources</strong>
                <span>{joinValues(detail.sourceSystems)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Last Observed</strong>
                <span>{formatInstant(detail.lastObservedAt)}</span>
              </div>
              <div className="software-identity-drawer-meta-item">
                <strong>Normalized Key</strong>
                <span className="mono">{detail.normalizedKey}</span>
              </div>
            </div>

            <section className="software-identity-drawer-section">
              <div className="panel-header">
                <h4>Observed Versions</h4>
                <span className="panel-caption">{detail.versions.length} version rows</span>
              </div>
              {detail.versions.length === 0 ? (
                <div className="panel-caption">No version rows available.</div>
              ) : (
                <div className="table-scroll">
                  <DataTable
                    storageKey={`software-identity-detail-versions:${softwareIdentityId}`}
                    columns={versionColumns}
                    rows={versionRows}
                  />
                </div>
              )}
            </section>

            <section className="software-identity-drawer-section">
              <div className="panel-header">
                <h4>Linked Inventory Components</h4>
                <span className="panel-caption">{detail.assets.length} rows shown</span>
              </div>
              {detail.assets.length === 0 ? (
                <div className="panel-caption">No linked inventory components available.</div>
              ) : (
                <div className="table-scroll">
                  <DataTable
                    storageKey={`software-identity-detail-assets:${softwareIdentityId}`}
                    columns={assetColumns}
                    rows={assetRows}
                  />
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </div>
  );
}
