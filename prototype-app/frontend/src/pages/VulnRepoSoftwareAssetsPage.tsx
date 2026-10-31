import React from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoHostAsset, pathForVulnRepoView } from '../app/routes';
import { usePageHeader } from '../app/pageHeaderState';
import { AsyncSection } from '../components/AsyncSection';
import { useVulnRepoSoftwareAssetsQuery } from '../features/software-identities/queries';

const SOFTWARE_ASSET_COLUMNS: DataTableColumn[] = [
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 260, minWidth: 200, priority: 'essential' },
  { id: 'assetType', label: 'Type', header: 'Type', initialSize: 110 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 120 },
  { id: 'openVulnerabilities', label: 'Open CVEs', header: 'Open CVEs', initialSize: 120, priority: 'essential' },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 140, priority: 'essential' },
  { id: 'lastObserved', label: 'Last Observed', header: 'Last Observed', initialSize: 180 },
];

function formatDateTime(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '-';
  }
  return parsed.toLocaleString();
}

export function VulnRepoSoftwareAssetsPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const softwareIdentityId = searchParams.get('softwareIdentityId')?.trim() ?? '';
  const softwareLabel = searchParams.get('software')?.trim() ?? '';
  const detailQuery = useVulnRepoSoftwareAssetsQuery(softwareIdentityId || null, Boolean(softwareIdentityId));

  const softwareName = detailQuery.data?.displayName || softwareLabel;
  usePageHeader(softwareName ? { title: `Assets running ${softwareName}` } : null);

  const impactedAssets = React.useMemo(
    () => detailQuery.data?.assets ?? [],
    [detailQuery.data?.assets]
  );

  const hostDetailPath = React.useCallback(
    (assetId: string, section?: 'applicable-cves' | 'host-findings') => {
      const returnTo = `${location.pathname}${location.search}${location.hash}`;
      return `${pathForVulnRepoHostAsset(assetId, returnTo)}${section ? `#${section}` : ''}`;
    },
    [location.hash, location.pathname, location.search]
  );

  const rows = React.useMemo<DataTableRow[]>(
    () =>
      impactedAssets.map((asset) => ({
        id: asset.componentId,
        cells: {
          asset: {
            content: (
              <>
                {(asset.assetType ?? '').toUpperCase() === 'HOST'
                  ? <Link to={hostDetailPath(asset.assetId)}>{asset.assetName}</Link>
                  : <div>{asset.assetName}</div>}
                <div className="panel-caption mono">{asset.assetIdentifier}</div>
              </>
            ),
          },
          assetType: { content: asset.assetType },
          version: { content: asset.version || '-' },
          source: { content: asset.sourceSystem || '-' },
          openVulnerabilities: {
            content: asset.openCveCount > 0 ? (
              <Link className="btn-link" to={hostDetailPath(asset.assetId, 'applicable-cves')}>
                {asset.openCveCount.toLocaleString()}
              </Link>
            ) : (
              '0'
            )
          },
          openFindings: {
            content: asset.openFindingCount > 0 ? (
              <Link className="btn-link" to={hostDetailPath(asset.assetId, 'host-findings')}>
                {asset.openFindingCount.toLocaleString()}
              </Link>
            ) : (
              '0'
            )
          },
          lastObserved: { content: formatDateTime(asset.lastObservedAt) },
        },
      })),
    [impactedAssets, hostDetailPath]
  );

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Impacted Assets</div>
          <h3>{detailQuery.data?.displayName || softwareLabel || 'Software Assets'}</h3>
          {detailQuery.data && (
            <span className="panel-caption">
              {detailQuery.data.impactedAssetCount.toLocaleString()} {detailQuery.data.impactedAssetCount === 1 ? 'asset is' : 'assets are'} currently associated with this software identity in the repository scope.
            </span>
          )}
        </div>
        <div className="button-row">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => navigate(pathForVulnRepoView('dashboard'))}
          >
            Back to Dashboard
          </button>
        </div>
      </div>

      {!softwareIdentityId ? (
        <div className="notice error" role="alert">
          Software identity is required. Open this list from a software row on the dashboard or the software identities inventory.
        </div>
      ) : detailQuery.isPending ? (
        <div className="notice" role="status">Loading impacted assets...</div>
      ) : detailQuery.error instanceof Error && !detailQuery.data ? (
        <AsyncSection
          state="error"
          errorMessage={detailQuery.error.message}
          onRetry={() => void detailQuery.refetch()}
          retrying={detailQuery.isFetching}
        />
      ) : impactedAssets.length === 0 ? (
        <div className="empty-state"><p>No assets were found for this software identity.</p></div>
      ) : (
        <div className="table-scroll">
          <DataTable
            storageKey={`vuln-repo-software-assets:${softwareIdentityId}`}
            columns={SOFTWARE_ASSET_COLUMNS}
            rows={rows}
          />
        </div>
      )}
    </section>
  );
}
