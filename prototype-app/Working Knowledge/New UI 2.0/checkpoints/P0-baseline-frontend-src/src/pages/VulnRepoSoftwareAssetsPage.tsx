import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { DataTable, type DataTableColumn, type DataTableRow } from '../components/DataTable';
import { pathForVulnRepoHostAsset, pathForVulnRepoView } from '../app/routes';
import { useVulnRepoSoftwareAssetsQuery } from '../features/software-identities/queries';

const SOFTWARE_ASSET_COLUMNS: DataTableColumn[] = [
  { id: 'asset', label: 'Asset', header: 'Asset', initialSize: 260 },
  { id: 'assetType', label: 'Type', header: 'Type', initialSize: 110 },
  { id: 'version', label: 'Version', header: 'Version', initialSize: 160 },
  { id: 'source', label: 'Source', header: 'Source', initialSize: 120 },
  { id: 'openVulnerabilities', label: 'Open CVEs', header: 'Open CVEs', initialSize: 120 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 140 },
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

  const impactedAssets = React.useMemo(
    () => detailQuery.data?.assets ?? [],
    [detailQuery.data?.assets]
  );

  const openHostDetailSection = React.useCallback(
    (assetId: string, section: 'applicable-cves' | 'host-findings') => {
      const returnTo = `${location.pathname}${location.search}${location.hash}`;
      navigate(`${pathForVulnRepoHostAsset(assetId, returnTo)}#${section}`);
    },
    [location.hash, location.pathname, location.search, navigate]
  );

  const rows = React.useMemo<DataTableRow[]>(
    () =>
      impactedAssets.map((asset) => ({
        id: asset.componentId,
        cells: {
          asset: {
            content: (
              <>
                <div>{asset.assetName}</div>
                <div className="panel-caption mono">{asset.assetIdentifier}</div>
              </>
            ),
          },
          assetType: { content: asset.assetType },
          version: { content: asset.version || '-' },
          source: { content: asset.sourceSystem || '-' },
          openVulnerabilities: {
            content: asset.openCveCount > 0 ? (
              <button
                type="button"
                className="btn-link"
                onClick={() => openHostDetailSection(asset.assetId, 'applicable-cves')}
              >
                {asset.openCveCount.toLocaleString()}
              </button>
            ) : (
              '0'
            )
          },
          openFindings: {
            content: asset.openFindingCount > 0 ? (
              <button
                type="button"
                className="btn-link"
                onClick={() => openHostDetailSection(asset.assetId, 'host-findings')}
              >
                {asset.openFindingCount.toLocaleString()}
              </button>
            ) : (
              '0'
            )
          },
          lastObserved: { content: formatDateTime(asset.lastObservedAt) },
        },
      })),
    [impactedAssets, openHostDetailSection]
  );

  return (
    <section className="panel vuln-repo-assets-shell">
      <div className="panel-header">
        <div>
          <div className="org-cve-back-link">Impacted Assets</div>
          <h3>{detailQuery.data?.displayName || softwareLabel || 'Software Assets'}</h3>
          <span className="panel-caption">
            {(detailQuery.data?.impactedAssetCount ?? impactedAssets.length).toLocaleString()} assets are currently associated with this software identity in the repository scope.
          </span>
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
        <div className="notice error">Software identity is required.</div>
      ) : detailQuery.isLoading || detailQuery.isFetching ? (
        <div className="notice">Loading impacted assets...</div>
      ) : detailQuery.error instanceof Error ? (
        <div className="notice error">{detailQuery.error.message}</div>
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
