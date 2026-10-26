import type { HostReviewCategory } from './types';
import { normalizeHostReviewCategory } from './helpers';

export const HOST_ASSET_QUERY_KEY = 'hostAssetId';
export const HOST_REVIEW_CATEGORY_QUERY_KEY = 'reviewCategory';
export const INVENTORY_QUERY_QUERY_KEY = 'query';
export const INVENTORY_SOURCE_SYSTEM_QUERY_KEY = 'sourceSystem';
export const INVENTORY_ECOSYSTEM_QUERY_KEY = 'ecosystem';
export const INVENTORY_COMPONENT_STATUS_QUERY_KEY = 'componentStatus';
export const INVENTORY_GROUP_BY_QUERY_KEY = 'groupBy';
export const SOFTWARE_LIFECYCLE_QUERY_KEY = 'lifecycle';
export const SOFTWARE_MAPPING_STATE_QUERY_KEY = 'mappingState';
export const HOST_QUICK_FILTER_QUERY_KEY = 'quickFilter';
export const HOST_ENVIRONMENT_QUERY_KEY = 'environment';
export const HOST_OPERATING_SYSTEM_QUERY_KEY = 'operatingSystem';

function normalizeSearchValues(values: string[]): string[] {
  return Array.from(new Set(
    values
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  ));
}

export function readSearchValueFromSearch(searchParams: URLSearchParams, key: string): string {
  return searchParams.get(key)?.trim() ?? '';
}

export function readSearchValuesFromSearch(searchParams: URLSearchParams, key: string): string[] {
  return normalizeSearchValues(searchParams.getAll(key));
}

export function writeSearchValueToSearch(
  searchParams: URLSearchParams,
  key: string,
  value: string | null | undefined
): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(key);
  const normalizedValue = value?.trim();
  if (normalizedValue) {
    nextSearchParams.set(key, normalizedValue);
  }
  return nextSearchParams;
}

export function writeSearchValuesToSearch(
  searchParams: URLSearchParams,
  key: string,
  values: string[]
): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(key);
  normalizeSearchValues(values).forEach((value) => nextSearchParams.append(key, value));
  return nextSearchParams;
}

export function readInventoryQueryFromSearch(searchParams: URLSearchParams): string {
  return readSearchValueFromSearch(searchParams, INVENTORY_QUERY_QUERY_KEY);
}

export function writeInventoryQueryToSearch(searchParams: URLSearchParams, query: string): URLSearchParams {
  return writeSearchValueToSearch(searchParams, INVENTORY_QUERY_QUERY_KEY, query);
}

export function readInventoryGroupByFromSearch(searchParams: URLSearchParams): string[] {
  return readSearchValuesFromSearch(searchParams, INVENTORY_GROUP_BY_QUERY_KEY);
}

export function writeInventoryGroupByToSearch(searchParams: URLSearchParams, values: string[]): URLSearchParams {
  return writeSearchValuesToSearch(searchParams, INVENTORY_GROUP_BY_QUERY_KEY, values);
}

export function readHostAssetIdFromSearch(searchParams: URLSearchParams): string | null {
  return searchParams.get(HOST_ASSET_QUERY_KEY);
}

export function readHostReviewCategoriesFromSearch(searchParams: URLSearchParams): HostReviewCategory[] {
  return Array.from(new Set(
    searchParams
      .getAll(HOST_REVIEW_CATEGORY_QUERY_KEY)
      .map(normalizeHostReviewCategory)
      .filter((value): value is HostReviewCategory => value !== null)
  ));
}

export function writeHostAssetIdToSearch(searchParams: URLSearchParams, assetId: string | null): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  if (assetId) {
    nextSearchParams.set(HOST_ASSET_QUERY_KEY, assetId);
  } else {
    nextSearchParams.delete(HOST_ASSET_QUERY_KEY);
  }
  return nextSearchParams;
}

export function writeHostReviewCategoriesToSearch(
  searchParams: URLSearchParams,
  categories: HostReviewCategory[]
): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(HOST_REVIEW_CATEGORY_QUERY_KEY);
  categories.forEach((category) => nextSearchParams.append(HOST_REVIEW_CATEGORY_QUERY_KEY, category));
  return nextSearchParams;
}

export function clearHostInventorySearchState(searchParams: URLSearchParams): URLSearchParams {
  const nextSearchParams = new URLSearchParams(searchParams);
  nextSearchParams.delete(HOST_ASSET_QUERY_KEY);
  nextSearchParams.delete(HOST_REVIEW_CATEGORY_QUERY_KEY);
  return nextSearchParams;
}
