import { describe, expect, it } from 'vitest';
import {
  clearHostInventorySearchState,
  readInventoryGroupByFromSearch,
  readInventoryQueryFromSearch,
  readHostAssetIdFromSearch,
  readHostReviewCategoriesFromSearch,
  readSearchValuesFromSearch,
  writeInventoryGroupByToSearch,
  writeInventoryQueryToSearch,
  writeHostAssetIdToSearch,
  writeHostReviewCategoriesToSearch,
  writeSearchValuesToSearch
} from './searchState';

describe('inventory searchState', () => {
  it('reads and normalizes host inventory search params', () => {
    const searchParams = new URLSearchParams(
      'hostAssetId=asset-123&reviewCategory=missing-version&reviewCategory=NEEDS_REVIEW&reviewCategory=invalid'
    );

    expect(readHostAssetIdFromSearch(searchParams)).toBe('asset-123');
    expect(readHostReviewCategoriesFromSearch(searchParams)).toEqual(['MISSING_VERSION', 'NEEDS_REVIEW']);
  });

  it('writes host detail and review-category params without dropping unrelated values', () => {
    const searchParams = new URLSearchParams('page=2');
    const withAssetId = writeHostAssetIdToSearch(searchParams, 'asset-456');
    const withCategories = writeHostReviewCategoriesToSearch(withAssetId, ['NEEDS_REVIEW', 'DISCOVERY_MODEL_REVIEW']);

    expect(withCategories.toString()).toBe(
      'page=2&hostAssetId=asset-456&reviewCategory=NEEDS_REVIEW&reviewCategory=DISCOVERY_MODEL_REVIEW'
    );
  });

  it('clears only host inventory search params', () => {
    const searchParams = new URLSearchParams(
      'page=1&hostAssetId=asset-789&reviewCategory=NEEDS_REVIEW&query=openssl'
    );

    expect(clearHostInventorySearchState(searchParams).toString()).toBe('page=1&query=openssl');
  });

  it('reads and writes shared inventory drilldown params', () => {
    const searchParams = new URLSearchParams(
      'query=log4j&sourceSystem=github&sourceSystem=api&groupBy=sourceSystem&groupBy=ecosystem'
    );

    expect(readInventoryQueryFromSearch(searchParams)).toBe('log4j');
    expect(readSearchValuesFromSearch(searchParams, 'sourceSystem')).toEqual(['github', 'api']);
    expect(readInventoryGroupByFromSearch(searchParams)).toEqual(['sourceSystem', 'ecosystem']);

    const withUpdates = writeInventoryGroupByToSearch(
      writeSearchValuesToSearch(
        writeInventoryQueryToSearch(searchParams, 'openssl'),
        'sourceSystem',
        ['servicenow', 'github']
      ),
      ['operatingSystem']
    );

    expect(withUpdates.toString()).toBe(
      'query=openssl&sourceSystem=servicenow&sourceSystem=github&groupBy=operatingSystem'
    );
  });
});
