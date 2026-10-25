import React from 'react';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from './DataTable';
import { useEolReleasesQuery } from '../features/eol/queries';
import type { EolProductCatalog } from '../features/eol/types';
import { EolBadge } from './EolBadge';

type EolDetailDrawerProps = {
  slug: string;
  catalogProduct?: EolProductCatalog;
  cycle?: string;
  packageName?: string;
  version?: string;
  isEol?: boolean;
  eolDate?: string;
  daysRemaining?: number;
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

function formatIdentifier(primary?: string, secondary?: string): string {
  if (!primary && !secondary) {
    return '-';
  }
  if (primary && secondary) {
    return `${primary}/${secondary}`;
  }
  return primary ?? secondary ?? '-';
}

export function EolDetailDrawer({
  slug,
  catalogProduct,
  cycle,
  packageName,
  version,
  isEol,
  eolDate,
  daysRemaining,
  onClose
}: EolDetailDrawerProps) {
  const stopPropagation = React.useCallback((e: React.MouseEvent) => e.stopPropagation(), []);
  const releasesQuery = useEolReleasesQuery(slug);
  const releases = releasesQuery.data;
  const error = releasesQuery.error instanceof Error ? releasesQuery.error.message : null;

  const thisRelease = releases?.find(r => r.cycle === cycle);
  const hasStatusContext = isEol != null || daysRemaining != null || eolDate != null;
  const hasCatalogReference = Boolean(catalogProduct);
  const catalogReleaseCount = catalogProduct?.releaseCount ?? releases?.length ?? 0;
  const hasLifecycleContext = Boolean(
    !catalogProduct
      || cycle
      || hasStatusContext
      || eolDate
      || thisRelease?.supportPhase
      || thisRelease?.supportEndDate
      || thisRelease?.extendedSupportDate
      || thisRelease?.securitySupportDate
      || thisRelease?.latestVersion
      || thisRelease?.lts
  );
  const releaseColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'cycle', label: 'Cycle', header: 'Cycle', initialSize: 120 },
    { id: 'eolDate', label: 'EOL Date', header: 'EOL Date', initialSize: 140 },
    { id: 'supportEnd', label: 'Support End', header: 'Support End', initialSize: 140 },
    { id: 'latest', label: 'Latest', header: 'Latest', initialSize: 140 },
    { id: 'lts', label: 'LTS', header: 'LTS', initialSize: 96 },
    { id: 'status', label: 'Status', header: 'Status', initialSize: 160 }
  ], []);
  const releaseRows = React.useMemo<DataTableRow[]>(() => (
    (releases ?? []).map((release) => ({
      id: release.cycle,
      rowProps: {
        className: release.cycle === cycle ? 'eol-drawer-row-highlight' : undefined
      },
      cells: {
        cycle: { content: <span className="mono">{release.cycle}</span> },
        eolDate: {
          content: release.eolDate ?? (
            release.eolBoolean === true ? 'EOL' : release.eolBoolean === false ? 'Not yet' : '-'
          )
        },
        supportEnd: { content: release.supportEndDate ?? '-' },
        latest: { content: <span className="mono">{release.latestVersion ?? '-'}</span> },
        lts: { content: release.lts ? 'LTS' : '-' },
        status: {
          content: (
            <EolBadge
              isEol={release.isEol}
              eolDate={release.eolDate}
            />
          )
        }
      }
    }))
  ), [cycle, releases]);

  return (
    <div className="eol-drawer-overlay" onClick={onClose}>
      <div className="eol-drawer" onClick={stopPropagation}>
        <div className="eol-drawer-header">
          <div>
            <h3 className="eol-drawer-title">End-of-Life Details</h3>
            {packageName && (
              <div className="panel-caption mono">{packageName}{version ? `@${version}` : ''}</div>
            )}
          </div>
          <button type="button" className="eol-drawer-close" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="eol-drawer-body">
          {hasCatalogReference && (
            <div className="eol-drawer-section">
              <div className="eol-drawer-section-title">Catalog Reference</div>
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Display Name</span>
                <span className="eol-drawer-value">{catalogProduct?.displayName || slug}</span>
              </div>
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Slug</span>
                <span className="eol-drawer-value mono">{slug}</span>
              </div>
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Coverage</span>
                <span className="eol-drawer-value">
                  {catalogReleaseCount > 0
                    ? `${catalogReleaseCount.toLocaleString()} ${catalogReleaseCount === 1 ? 'cycle' : 'cycles'} loaded`
                    : 'Reference-only entry'}
                </span>
              </div>
              {(catalogProduct?.aliases?.length ?? 0) > 0 && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Aliases</span>
                  <span className="eol-drawer-value eol-drawer-value--wrap">
                    {(catalogProduct?.aliases ?? []).join(', ')}
                  </span>
                </div>
              )}
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">CPE</span>
                <span className="eol-drawer-value mono">
                  {formatIdentifier(catalogProduct?.cpeVendor, catalogProduct?.cpeProduct)}
                </span>
              </div>
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">PURL</span>
                <span className="eol-drawer-value mono">
                  {formatIdentifier(catalogProduct?.purlType, catalogProduct?.purlNamespace)}
                </span>
              </div>
              {catalogProduct?.lastFetchedAt && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Last Fetched</span>
                  <span className="eol-drawer-value">{formatInstant(catalogProduct.lastFetchedAt)}</span>
                </div>
              )}
              {catalogProduct?.lastModified && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Last Modified</span>
                  <span className="eol-drawer-value mono">{catalogProduct.lastModified}</span>
                </div>
              )}
            </div>
          )}

          {hasLifecycleContext && (
            <div className="eol-drawer-section">
              <div className="eol-drawer-section-title">Lifecycle Context</div>
              <div className="eol-drawer-row">
                <span className="eol-drawer-label">Product</span>
                <span className="eol-drawer-value mono">{slug}</span>
              </div>
              {cycle && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Selected Cycle</span>
                  <span className="eol-drawer-value mono">{cycle}</span>
                </div>
              )}
              {hasStatusContext && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Status</span>
                  <span className="eol-drawer-value">
                    <EolBadge isEol={isEol} daysRemaining={daysRemaining} eolDate={eolDate} />
                  </span>
                </div>
              )}
              {eolDate && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">EOL Date</span>
                  <span className="eol-drawer-value">{eolDate}</span>
                </div>
              )}
              {thisRelease?.supportPhase && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Support Phase</span>
                  <span className="eol-drawer-value">{thisRelease.supportPhase}</span>
                </div>
              )}
              {thisRelease?.supportEndDate && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Active Support Ends</span>
                  <span className="eol-drawer-value">{thisRelease.supportEndDate}</span>
                </div>
              )}
              {thisRelease?.extendedSupportDate && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Extended Support Ends</span>
                  <span className="eol-drawer-value">{thisRelease.extendedSupportDate}</span>
                </div>
              )}
              {thisRelease?.securitySupportDate && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Security Support Ends</span>
                  <span className="eol-drawer-value">{thisRelease.securitySupportDate}</span>
                </div>
              )}
              {thisRelease?.latestVersion && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">Latest Version</span>
                  <span className="eol-drawer-value mono">{thisRelease.latestVersion}</span>
                </div>
              )}
              {thisRelease?.lts && (
                <div className="eol-drawer-row">
                  <span className="eol-drawer-label">LTS</span>
                  <span className="eol-drawer-value">Yes</span>
                </div>
              )}
            </div>
          )}

          <div className="eol-drawer-section">
            <div className="eol-drawer-section-title">All Release Cycles</div>
            {error && <div className="panel-caption">Failed to load cycles: {error}</div>}
            {!releases && !error && <div className="panel-caption">Loading...</div>}
            {releases && releases.length === 0 && (
              <div className="panel-caption">No release cycles available for this product.</div>
            )}
            {releases && releases.length > 0 && (
              <div className="table-scroll">
                <DataTable
                  storageKey={`eol-release-cycles:${slug}`}
                  columns={releaseColumns}
                  rows={releaseRows}
                />
              </div>
            )}
          </div>

          <div className="eol-drawer-footer">
            {thisRelease?.officialSourceUrl && (
              <a
                href={thisRelease.officialSourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-secondary eol-drawer-link"
              >
                Official Documentation ↗
              </a>
            )}
            <a
              href={`https://endoflife.date/${slug}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-secondary eol-drawer-link"
            >
              View on endoflife.date ↗
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
