import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import type { InventoryViewKey } from '../features/inventory/types';
import {
  defaultAssetTypeForView,
  formatInventoryLabel
} from '../features/inventory/helpers';
import { InventoryResultsPanel } from '../features/inventory/InventoryResultsPanel';
import { InventoryShell } from '../features/inventory/InventoryShell';
import { InventorySummaryStats } from '../features/inventory/InventorySummaryStats';
import {
  readHostAssetIdFromSearch,
  writeHostAssetIdToSearch
} from '../features/inventory/searchState';
import { useInventoryData } from '../features/inventory/useInventoryData';
import { HostAssetDetailPage } from './HostAssetDetailPage';

type Props = {
  selectedView: InventoryViewKey;
};

const VIEW_META: Partial<Record<InventoryViewKey, { title: string; description?: string }>> = {
  'container-images': {
    title: 'Container Images',
    description: 'Container images discovered across registries and clusters with their components and exposure.'
  },
  sbom: {
    title: 'SBOMs',
    description: 'Uploaded and ingested software bills of materials.'
  }
};

export function InventoryComponentViewsPage({ selectedView }: Props) {
  const [searchParams, setSearchParams] = useSearchParams();
  const scopedAssetType = defaultAssetTypeForView(selectedView);
  const [componentPage, setComponentPage] = React.useState(0);
  const [retiredOnly, setRetiredOnly] = React.useState(false);

  const selectedHostAssetId = React.useMemo(
    () => (selectedView === 'hosts' ? readHostAssetIdFromSearch(searchParams) : null),
    [searchParams, selectedView]
  );

  const {
    rows,
    componentTotalItems,
    componentTotalPages,
    loading,
    refreshing,
    latestDataUpdate,
    error
  } = useInventoryData({
    selectedView,
    scopedAssetType,
    componentActiveFilters: retiredOnly ? ['componentStatus'] : [],
    componentAssetTypes: [],
    componentStatuses: retiredOnly ? ['RETIRED'] : [],
    componentSourceSystems: [],
    componentEcosystems: [],
    componentReviewCategories: [],
    componentPage,
    debouncedComponentQuery: ''
  });

  const retiredCount = rows.filter((row) => row.componentStatus === 'RETIRED').length;
  const assetCount = new Set(rows.map((row) => row.assetId)).size;
  const needsReviewCount = rows.filter((row) => row.needsReview).length;

  const openHostDetail = React.useCallback((assetId: string): void => {
    if (selectedView !== 'hosts') return;
    const next = writeHostAssetIdToSearch(searchParams, assetId);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  const closeHostDetail = React.useCallback((): void => {
    if (selectedView !== 'hosts') return;
    const next = writeHostAssetIdToSearch(searchParams, null);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, selectedView, setSearchParams]);

  const viewMeta = VIEW_META[selectedView];
  const viewTitle = viewMeta?.title ?? formatInventoryLabel(selectedView);
  const viewDescription = viewMeta?.description;

  if (selectedView === 'hosts' && selectedHostAssetId) {
    return (
      <InventoryShell eyebrow="Inventory" title="Host Detail">
        <HostAssetDetailPage
          assetId={selectedHostAssetId}
          onClose={closeHostDetail}
        />
      </InventoryShell>
    );
  }

  return (
    <InventoryShell
      eyebrow="Inventory"
      title={viewTitle}
      description={viewDescription}
    >
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshing}
        refreshLabel="Refreshing component inventory while keeping current results visible…"
      />

      <InventorySummaryStats
        selectedView={selectedView}
        componentTotalItems={componentTotalItems}
        retiredCount={retiredCount}
        assetCount={assetCount}
        needsReviewCount={needsReviewCount}
        onRetiredClick={() => { setRetiredOnly((prev) => !prev); setComponentPage(0); }}
      />

      <InventoryResultsPanel
        selectedView={selectedView}
        error={error}
        loading={loading}
        rows={rows}
        componentPage={componentPage}
        componentTotalPages={componentTotalPages}
        selectedHostAssetId={selectedHostAssetId}
        onOpenHostDetail={openHostDetail}
        onPreviousComponentPage={() => setComponentPage((current) => Math.max(0, current - 1))}
        onNextComponentPage={() => setComponentPage((current) => (current + 1 < componentTotalPages ? current + 1 : current))}
      />
    </InventoryShell>
  );
}
