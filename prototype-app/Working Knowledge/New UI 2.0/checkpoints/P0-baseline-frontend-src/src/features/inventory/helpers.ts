import type {
  InventoryComponentRecord
} from './api-types';
import {
  HOST_REVIEW_CATEGORIES,
  HostReviewCategory,
  InventoryScopedAssetType,
  InventoryViewKey
} from './types';

export function defaultAssetTypeForView(view: InventoryViewKey): InventoryScopedAssetType {
  if (view === 'container-images') {
    return 'CONTAINER_IMAGE';
  }
  if (view === 'sbom') {
    return 'APPLICATION';
  }
  if (view === 'hosts') {
    return 'HOST';
  }
  return 'ALL';
}

export function formatAssetType(value: InventoryComponentRecord['assetType']): string {
  if (value === 'CONTAINER_IMAGE') return 'Container Image';
  if (value === 'APPLICATION') return 'Application';
  return 'Host';
}

export function formatInventorySourceSystem(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'upload') return 'Legacy Upload';
  if (normalized === 'api') return 'API Endpoint';
  if (normalized === 'github') return 'GitHub Generated';
  if (normalized === 'servicenow') return 'ServiceNow';
  return value;
}

export function formatInventoryLabel(value: string): string {
  return value
    .trim()
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function formatHostReviewLabel(value: HostReviewCategory): string {
  if (value === 'NEEDS_REVIEW') return 'Needs Review';
  if (value === 'MISSING_VERSION') return 'Missing Version';
  if (value === 'UNMAPPED_SOFTWARE') return 'Unmapped Identity';
  if (value === 'LOW_CONFIDENCE_ALIAS') return 'Alias Review';
  return 'Discovery Review';
}

export function normalizeHostReviewCategory(value: string): HostReviewCategory | null {
  const normalized = value.trim().toUpperCase().replace(/[-\s]+/g, '_');
  return HOST_REVIEW_CATEGORIES.includes(normalized as HostReviewCategory)
    ? normalized as HostReviewCategory
    : null;
}

export function buildHostReviewLabels(row: InventoryComponentRecord): string[] {
  const labels: string[] = [];
  if (row.reviewMissingVersion) labels.push('Missing Version');
  if (row.reviewUnmappedSoftware) labels.push('Unmapped Identity');
  if (row.reviewLowConfidenceAlias) labels.push('Alias Review');
  if (row.reviewDiscoveryModel) labels.push('Discovery Review');
  return labels;
}
