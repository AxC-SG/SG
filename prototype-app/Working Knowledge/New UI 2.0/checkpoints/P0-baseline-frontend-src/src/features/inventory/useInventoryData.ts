import React from 'react';
import { latestFreshnessValue } from '../../components/PageFreshnessStatus';
import type {
  InventoryComponentFilterValues,
  InventoryComponentRecord
} from './api-types';
import { DEFAULT_COMPONENT_FILTERS } from './config';
import {
  useInventoryComponentFiltersQuery,
  useInventoryComponentsQuery
} from './queries';

type UseInventoryDataArgs = {
  selectedView: string;
  scopedAssetType: 'ALL' | InventoryComponentRecord['assetType'];
  componentActiveFilters: string[];
  componentAssetTypes: string[];
  componentStatuses: string[];
  componentSourceSystems: string[];
  componentEcosystems: string[];
  componentReviewCategories: string[];
  componentPage: number;
  debouncedComponentQuery: string;
};

type UseInventoryDataResult = {
  rows: InventoryComponentRecord[];
  componentTotalItems: number;
  componentTotalPages: number;
  componentFilterValues: InventoryComponentFilterValues;
  loading: boolean;
  refreshing: boolean;
  latestDataUpdate: number | null;
  error: string;
  refreshInventory: () => Promise<void>;
};

export function useInventoryData({
  selectedView,
  scopedAssetType,
  componentActiveFilters,
  componentAssetTypes,
  componentStatuses,
  componentSourceSystems,
  componentEcosystems,
  componentReviewCategories,
  componentPage,
  debouncedComponentQuery
}: UseInventoryDataArgs): UseInventoryDataResult {
  const assetTypeParam = scopedAssetType === 'ALL'
    ? (
      componentActiveFilters.includes('assetType') && componentAssetTypes.length > 0
        ? componentAssetTypes.filter((value): value is InventoryComponentRecord['assetType'] => (
          value === 'APPLICATION' || value === 'HOST' || value === 'CONTAINER_IMAGE'
        ))
        : undefined
    )
    : [scopedAssetType as InventoryComponentRecord['assetType']];
  const componentStatusParam = componentActiveFilters.includes('componentStatus') && componentStatuses.length > 0
    ? componentStatuses.filter((value): value is InventoryComponentRecord['componentStatus'] => (
      value === 'ACTIVE' || value === 'RETIRED'
    ))
    : undefined;
  const inventoryQuery = useInventoryComponentsQuery({
    assetType: assetTypeParam,
    componentStatus: componentStatusParam,
    sourceSystem: componentActiveFilters.includes('sourceSystem') && componentSourceSystems.length > 0
      ? componentSourceSystems
      : undefined,
    ecosystem: componentActiveFilters.includes('ecosystem') && componentEcosystems.length > 0
      ? componentEcosystems
      : undefined,
    reviewCategory: selectedView === 'hosts'
      && componentActiveFilters.includes('reviewCategory')
      && componentReviewCategories.length > 0
      ? componentReviewCategories
      : undefined,
    query: componentActiveFilters.includes('query') ? debouncedComponentQuery.trim() : undefined,
    page: componentPage,
    size: 25
  });
  const componentFiltersQuery = useInventoryComponentFiltersQuery();

  const componentFilterValues: InventoryComponentFilterValues = React.useMemo(() => {
    const availableFilters = componentFiltersQuery.data;
    if (!availableFilters) {
      return DEFAULT_COMPONENT_FILTERS;
    }
    return {
      assetTypes: Array.from(new Set(
        (availableFilters.assetTypes || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      componentStatuses: Array.from(new Set(
        (availableFilters.componentStatuses || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toUpperCase())
      )),
      sourceSystems: Array.from(new Set(
        (availableFilters.sourceSystems || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toLowerCase())
      )),
      ecosystems: Array.from(new Set(
        (availableFilters.ecosystems || [])
          .filter((value) => value && value.trim().length > 0)
          .map((value) => value.trim().toLowerCase())
      ))
    };
  }, [componentFiltersQuery.data]);

  const refreshInventory = React.useCallback(async () => {
    await Promise.all([
      inventoryQuery.refetch(),
      componentFiltersQuery.refetch()
    ]);
  }, [componentFiltersQuery, inventoryQuery]);

  const rows = inventoryQuery.data?.items ?? [];
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    inventoryQuery.dataUpdatedAt,
    componentFiltersQuery.dataUpdatedAt
  ]), [
    componentFiltersQuery.dataUpdatedAt,
    inventoryQuery.dataUpdatedAt
  ]);

  return {
    rows,
    componentTotalItems: inventoryQuery.data?.totalItems ?? 0,
    componentTotalPages: inventoryQuery.data?.totalPages ?? 0,
    componentFilterValues,
    loading: inventoryQuery.isLoading || inventoryQuery.isFetching || componentFiltersQuery.isLoading,
    refreshing: (inventoryQuery.isFetching || componentFiltersQuery.isFetching) && rows.length > 0,
    latestDataUpdate,
    error: inventoryQuery.error instanceof Error ? String(inventoryQuery.error) : '',
    refreshInventory
  };
}
