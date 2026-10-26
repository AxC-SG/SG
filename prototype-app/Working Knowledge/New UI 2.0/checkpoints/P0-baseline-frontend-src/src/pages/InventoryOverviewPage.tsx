import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import {
  pathForInventoryHostAsset,
  pathForInventoryView,
  pathForInventoryViewWithSearch,
  pathForSoftwareIdentityDetail,
} from '../app/routes';
import { InventoryQualityWorkspace } from '../components/InventoryQualityWorkspace';
import { useDashboardSummaryQuery } from '../features/dashboard/queries';
import type { ApplicableSoftwareRecord } from '../features/dashboard/types';
import { useEolSummaryQuery, useEolUnresolvedMappingsQuery } from '../features/eol/queries';
import type { Asset, HostAssetDetail, HostSoftwareInstanceRecord, InventoryComponentRecord } from '../features/inventory/api-types';
import type { InventoryViewKey } from '../features/inventory/types';
import { useOperationalQualitySummaryQuery } from '../features/operations/queries';
import type { OperationalQualitySummary } from '../features/operations/types';
import { useSoftwareIdentitiesQuery } from '../features/software-identities/queries';
import type { SoftwareIdentitySummary } from '../features/software-identities/types';
import { AiInventoryOverviewStrip } from '../features/ai-security/AiInventoryOverviewStrip';

const HOST_STALE_DAYS = 30;
const HOST_AGING_DAYS = 7;
const INVENTORY_COMPONENT_PAGE_SIZE = 250;
const SOFTWARE_PAGE_SIZE = 200;
const SOFTWARE_TABLE_ROWS = 8;
const _HOST_TABLE_ROWS = 8;

const OS_MATCHERS: Array<{ label: string; test: (value: string) => boolean }> = [
  { label: 'Windows Server', test: (value) => value.includes('windows server') },
  { label: 'Windows', test: (value) => value.includes('windows') },
  { label: 'Ubuntu', test: (value) => value.includes('ubuntu') },
  { label: 'Debian', test: (value) => value.includes('debian') },
  { label: 'Amazon Linux', test: (value) => value.includes('amazon linux') },
  { label: 'RHEL', test: (value) => value.includes('red hat') || value.includes('rhel') },
  { label: 'CentOS', test: (value) => value.includes('centos') },
  { label: 'Rocky Linux', test: (value) => value.includes('rocky') },
  { label: 'SUSE Linux', test: (value) => value.includes('suse') },
  { label: 'macOS', test: (value) => value.includes('mac os') || value.includes('macos') || value.includes('os x') },
  { label: 'Linux', test: (value) => value.includes('linux') }
];

type SupportedAssetType = 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE';

type FreshnessState = {
  label: 'Fresh' | 'Aging' | 'Stale' | 'Unknown';
  className: string;
};

type NormalizationState = {
  label: 'Normalized' | 'Needs review' | 'No software';
  className: string;
};

type HostOverviewRecord = {
  asset: Asset;
  detail: HostAssetDetail;
  operatingSystem: string;
  deployedSoftwareCount: number;
  normalizedSoftwareCount: number;
  notNormalizedSoftwareCount: number;
  normalization: NormalizationState;
  openFindingCount: number;
  applicableCveCount: number;
  lastSeenAt?: string;
  freshness: FreshnessState;
  eolSoftwareCount: number;
  unknownLifecycleCount: number;
  reviewGapCount: number;
  attentionScore: number;
};

type AssetOverviewRecord = {
  asset: Asset;
  assetType: SupportedAssetType;
  operatingSystem?: string;
  deployedSoftwareCount: number;
  normalizedSoftwareCount: number;
  notNormalizedSoftwareCount: number;
  normalization: NormalizationState;
  openFindingCount: number;
  applicableCveCount: number;
  lastSeenAt?: string;
  freshness: FreshnessState;
  eolSoftwareCount: number;
  unknownLifecycleCount: number;
  reviewGapCount: number;
  attentionScore: number;
};

type AssetNormalizationSummary = {
  trackedAssetCount: number;
  normalizedAssetCount: number;
  notNormalizedAssetCount: number;
  normalizedComponentCount: number;
  notNormalizedComponentCount: number;
  normalizedAssetCoveragePercent: number;
};

type AssetTypePortfolioSummary = {
  type: SupportedAssetType;
  label: string;
  totalAssetCount: number;
  trackedAssetCount: number;
  normalizedAssetCount: number;
  notNormalizedAssetCount: number;
  componentCount: number;
};

type OverviewSoftwareSummary = SoftwareIdentitySummary & {
  collapsedIdentityCount: number;
  softwareFilterQuery: string;
};

type InventoryWidgetRow = {
  label: string;
  value: number;
  percent: number;
  caption?: string;
  className?: string;
  actionPath?: string;
};

type QualityInventoryWorkspaceTab = 'quality-normalization' | 'quality-correlation' | 'quality-eol' | 'quality-vex';
type InventoryWorkspaceTab = 'overview' | QualityInventoryWorkspaceTab;

const SUPPORTED_ASSET_TYPES: SupportedAssetType[] = ['APPLICATION', 'HOST', 'CONTAINER_IMAGE'];
const INVENTORY_TABS_PARAM = 'inventoryTabs';
const INVENTORY_ACTIVE_TAB_PARAM = 'inventoryActiveTab';
const INVENTORY_NORMALIZATION_TAB = 'quality-normalization';
const INVENTORY_CORRELATION_TAB = 'quality-correlation';
const INVENTORY_EOL_TAB = 'quality-eol';
const INVENTORY_VEX_TAB = 'quality-vex';
const QUALITY_INVENTORY_WORKSPACE_TABS: QualityInventoryWorkspaceTab[] = [
  INVENTORY_NORMALIZATION_TAB,
  INVENTORY_CORRELATION_TAB,
  INVENTORY_EOL_TAB,
  INVENTORY_VEX_TAB
];
const INVENTORY_WORKSPACE_TAB_CONFIG: Record<QualityInventoryWorkspaceTab, {
  label: string;
  domain: 'NORMALIZATION' | 'CORRELATION' | 'EOL' | 'VEX';
}> = {
  [INVENTORY_NORMALIZATION_TAB]: { label: 'Quality / Normalization', domain: 'NORMALIZATION' },
  [INVENTORY_CORRELATION_TAB]: { label: 'Quality / Correlation', domain: 'CORRELATION' },
  [INVENTORY_EOL_TAB]: { label: 'Quality / EOL', domain: 'EOL' },
  [INVENTORY_VEX_TAB]: { label: 'Quality / VEX', domain: 'VEX' }
};

function hasValue(value?: string | null): boolean {
  return Boolean(value && value.trim().length > 0);
}

function normalizeAssetType(value?: string | null): SupportedAssetType | null {
  const normalized = value?.trim().toUpperCase();
  if (normalized === 'APPLICATION' || normalized === 'HOST' || normalized === 'CONTAINER_IMAGE') {
    return normalized;
  }
  return null;
}

function formatAssetTypeLabel(value: SupportedAssetType): string {
  if (value === 'APPLICATION') {
    return 'Applications';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'Container Images';
  }
  return 'Hosts';
}

function _formatAssetTypeSingleLabel(value: SupportedAssetType): string {
  if (value === 'APPLICATION') {
    return 'Application';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'Container image';
  }
  return 'Host';
}

function inventoryViewForAssetType(value: SupportedAssetType): InventoryViewKey {
  if (value === 'APPLICATION') {
    return 'sbom';
  }
  if (value === 'CONTAINER_IMAGE') {
    return 'container-images';
  }
  return 'hosts';
}

function daysSince(value?: string): number | null {
  if (!value) {
    return null;
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  const diffMs = Date.now() - parsed.getTime();
  return Math.max(0, Math.floor(diffMs / (1000 * 60 * 60 * 24)));
}

function freshnessStateFor(value?: string): FreshnessState {
  const age = daysSince(value);
  if (age == null) {
    return { label: 'Unknown', className: 'status-pill status-unknown' };
  }
  if (age >= HOST_STALE_DAYS) {
    return { label: 'Stale', className: 'status-pill status-inactive' };
  }
  if (age >= HOST_AGING_DAYS) {
    return { label: 'Aging', className: 'status-pill status-warning' };
  }
  return { label: 'Fresh', className: 'status-pill status-success' };
}

function _summarizeAge(value?: string): string {
  const age = daysSince(value);
  if (age == null) {
    return 'Waiting for inventory signal';
  }
  if (age === 0) {
    return 'Updated today';
  }
  if (age === 1) {
    return 'Updated 1 day ago';
  }
  return `Updated ${age} days ago`;
}

function inferOperatingSystem(detail: HostAssetDetail): string {
  const candidates = detail.software.flatMap((software) => [
    software.displayName,
    software.publisher,
    software.normalizedProduct,
    software.normalizedPublisher
  ]);

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    const normalized = candidate.trim().toLowerCase();
    const match = OS_MATCHERS.find((matcher) => matcher.test(normalized));
    if (match) {
      return match.label;
    }
  }

  return 'Unknown';
}

function normalizedSoftwareIdentityText(identity: SoftwareIdentitySummary): string {
  return [
    identity.displayName,
    identity.canonicalKey,
    identity.vendor,
    identity.product,
    identity.normalizedKey
  ]
    .filter(hasValue)
    .join(' ')
    .replace(/[_-]/g, ' ')
    .toLowerCase();
}

function _softwareIdentityMatchesOperatingSystem(identity: SoftwareIdentitySummary, operatingSystem: string): boolean {
  const normalized = operatingSystem.trim().toLowerCase();
  const identityText = normalizedSoftwareIdentityText(identity);
  if (normalized === 'unknown') {
    return !OS_MATCHERS.some((matcher) => matcher.test(identityText));
  }
  if (normalized.includes('windows server')) {
    return identityText.includes('windows server');
  }
  const matcher = OS_MATCHERS.find((entry) => entry.label.toLowerCase() === normalized);
  return matcher ? matcher.test(identityText) : identityText.includes(normalized);
}

function hostLastSeen(asset: Asset, detail: HostAssetDetail): string | undefined {
  return detail.host.lastInventoryAt ?? detail.host.lastCmdbSyncAt ?? asset.lastInventoryAt ?? asset.lastCmdbSyncAt;
}

function assetLastSeen(asset: Asset): string | undefined {
  return asset.lastInventoryAt ?? asset.lastCmdbSyncAt;
}

function softwareNeedsReview(software: HostSoftwareInstanceRecord): boolean {
  return software.needsVersionReview || software.needsIdentityReview || software.needsDiscoveryModelReview;
}

function hostSoftwareIsNormalized(software: HostSoftwareInstanceRecord): boolean {
  return hasValue(software.normalizedPublisher)
    && hasValue(software.normalizedProduct)
    && hasValue(software.normalizedVersion)
    && hasValue(software.softwareIdentity)
    && !softwareNeedsReview(software);
}

function hostNormalizationStateFor(totalRows: number, notNormalizedRows: number): NormalizationState {
  if (totalRows === 0) {
    return { label: 'No software', className: 'status-pill status-unknown' };
  }
  if (notNormalizedRows === 0) {
    return { label: 'Normalized', className: 'status-pill status-success' };
  }
  return { label: 'Needs review', className: 'status-pill status-warning' };
}

function inventoryComponentIsNormalized(component: InventoryComponentRecord): boolean {
  return hasValue(component.normalizedName)
    && hasValue(component.normalizedVersion)
    && hasValue(component.softwareIdentity)
    && !component.needsReview;
}

async function loadAllActiveInventoryComponents(): Promise<InventoryComponentRecord[]> {
  const items: InventoryComponentRecord[] = [];
  let page = 0;

  while (true) {
    const response = await api.listInventoryComponents({
      componentStatus: ['ACTIVE'],
      page,
      size: INVENTORY_COMPONENT_PAGE_SIZE
    });
    items.push(...response.items);
    page += 1;
    if (page >= response.totalPages) {
      break;
    }
  }

  return items;
}

async function loadAllApplicableSoftware(): Promise<ApplicableSoftwareRecord[]> {
  const items: ApplicableSoftwareRecord[] = [];
  let page = 0;

  while (true) {
    const response = await api.listApplicableSoftware({
      page,
      size: INVENTORY_COMPONENT_PAGE_SIZE
    });
    items.push(...response.items);
    page += 1;
    if (page >= response.totalPages) {
      break;
    }
  }

  return items;
}

function buildAssetNormalizationSummary(components: InventoryComponentRecord[]): AssetNormalizationSummary {
  const assets = new Map<string, { componentCount: number; normalizedComponentCount: number }>();

  components.forEach((component) => {
    const current = assets.get(component.assetId) ?? { componentCount: 0, normalizedComponentCount: 0 };
    current.componentCount += 1;
    if (inventoryComponentIsNormalized(component)) {
      current.normalizedComponentCount += 1;
    }
    assets.set(component.assetId, current);
  });

  let normalizedAssetCount = 0;
  let normalizedComponentCount = 0;
  let notNormalizedComponentCount = 0;

  assets.forEach((asset) => {
    normalizedComponentCount += asset.normalizedComponentCount;
    notNormalizedComponentCount += asset.componentCount - asset.normalizedComponentCount;
    if (asset.componentCount > 0 && asset.componentCount === asset.normalizedComponentCount) {
      normalizedAssetCount += 1;
    }
  });

  const trackedAssetCount = assets.size;
  const notNormalizedAssetCount = trackedAssetCount - normalizedAssetCount;

  return {
    trackedAssetCount,
    normalizedAssetCount,
    notNormalizedAssetCount,
    normalizedComponentCount,
    notNormalizedComponentCount,
    normalizedAssetCoveragePercent: trackedAssetCount === 0 ? 0 : (normalizedAssetCount / trackedAssetCount) * 100
  };
}

function buildAssetTypePortfolioSummaries(
  assets: Asset[],
  components: InventoryComponentRecord[]
): AssetTypePortfolioSummary[] {
  const totalAssetIds = new Map<SupportedAssetType, Set<string>>();
  const trackedAssetIds = new Map<SupportedAssetType, Set<string>>();
  const normalizedAssetIds = new Map<SupportedAssetType, Set<string>>();
  const componentCountByType = new Map<SupportedAssetType, number>();
  const assetComponentStats = new Map<string, {
    type: SupportedAssetType;
    componentCount: number;
    normalizedComponentCount: number;
  }>();

  SUPPORTED_ASSET_TYPES.forEach((type) => {
    totalAssetIds.set(type, new Set());
    trackedAssetIds.set(type, new Set());
    normalizedAssetIds.set(type, new Set());
    componentCountByType.set(type, 0);
  });

  assets.forEach((asset) => {
    const assetType = normalizeAssetType(asset.type);
    if (!assetType) {
      return;
    }
    totalAssetIds.get(assetType)?.add(asset.id);
  });

  components.forEach((component) => {
    const assetType = normalizeAssetType(component.assetType);
    if (!assetType) {
      return;
    }
    const current = assetComponentStats.get(component.assetId) ?? {
      type: assetType,
      componentCount: 0,
      normalizedComponentCount: 0
    };
    current.componentCount += 1;
    if (inventoryComponentIsNormalized(component)) {
      current.normalizedComponentCount += 1;
    }
    assetComponentStats.set(component.assetId, current);
  });

  assetComponentStats.forEach((assetStats, assetId) => {
    trackedAssetIds.get(assetStats.type)?.add(assetId);
    componentCountByType.set(
      assetStats.type,
      (componentCountByType.get(assetStats.type) ?? 0) + assetStats.componentCount
    );
    if (assetStats.componentCount > 0 && assetStats.componentCount === assetStats.normalizedComponentCount) {
      normalizedAssetIds.get(assetStats.type)?.add(assetId);
    }
  });

  return SUPPORTED_ASSET_TYPES.map((type) => {
    const totalAssetCount = totalAssetIds.get(type)?.size ?? 0;
    const trackedAssetCount = trackedAssetIds.get(type)?.size ?? 0;
    const normalizedAssetCount = normalizedAssetIds.get(type)?.size ?? 0;
    return {
      type,
      label: formatAssetTypeLabel(type),
      totalAssetCount,
      trackedAssetCount,
      normalizedAssetCount,
      notNormalizedAssetCount: Math.max(0, trackedAssetCount - normalizedAssetCount),
      componentCount: componentCountByType.get(type) ?? 0
    };
  });
}

function toHostOverviewRecord(asset: Asset, detail: HostAssetDetail): HostOverviewRecord {
  const lastSeenAt = hostLastSeen(asset, detail);
  const freshness = freshnessStateFor(lastSeenAt);
  const openFindingCount = detail.findings.filter((finding) => (finding.status ?? '').toUpperCase() !== 'RESOLVED').length;
  const eolSoftwareCount = detail.software.filter((software) => software.isEol === true).length;
  const unknownLifecycleCount = detail.software.filter((software) => !software.eolSlug).length;
  const reviewGapCount = detail.software.filter(softwareNeedsReview).length;
  const applicableCveCount = detail.applicableCves.length;
  const deployedSoftwareCount = detail.software.length;
  const normalizedSoftwareCount = detail.software.filter(hostSoftwareIsNormalized).length;
  const notNormalizedSoftwareCount = Math.max(0, deployedSoftwareCount - normalizedSoftwareCount);
  const normalization = hostNormalizationStateFor(deployedSoftwareCount, notNormalizedSoftwareCount);
  const freshnessWeight = freshness.label === 'Stale' ? 8 : freshness.label === 'Aging' ? 4 : 0;
  const attentionScore = (openFindingCount * 5)
    + (applicableCveCount * 2)
    + (eolSoftwareCount * 4)
    + (unknownLifecycleCount * 2)
    + (reviewGapCount * 3)
    + (notNormalizedSoftwareCount * 2)
    + freshnessWeight;

  return {
    asset,
    detail,
    operatingSystem: inferOperatingSystem(detail),
    deployedSoftwareCount,
    normalizedSoftwareCount,
    notNormalizedSoftwareCount,
    normalization,
    openFindingCount,
    applicableCveCount,
    lastSeenAt,
    freshness,
    eolSoftwareCount,
    unknownLifecycleCount,
    reviewGapCount,
    attentionScore
  };
}

function _assetDrilldownPath(record: AssetOverviewRecord, returnTo: string): string {
  if (record.assetType === 'HOST') {
    return pathForInventoryHostAsset(record.asset.id, returnTo);
  }
  return pathForInventoryViewWithSearch(inventoryViewForAssetType(record.assetType), {
    query: record.asset.identifier || record.asset.name,
    groupBy: ['sourceSystem', 'ecosystem']
  });
}

function isExternalFacingAsset(record: AssetOverviewRecord): boolean {
  const searchable = [
    record.asset.name,
    record.asset.identifier,
    record.asset.serviceName,
    record.asset.environment,
    record.asset.businessCriticality
  ].join(' ').toLowerCase();
  return /\b(external|internet|public|dmz|edge|web)\b/.test(searchable);
}

function softwareLifecycleSummary(identity: SoftwareIdentitySummary): { label: string; className: string } {
  if (identity.eolComponentCount > 0) {
    return { label: `${identity.eolComponentCount} EOL`, className: 'status-pill status-failure' };
  }
  if (identity.nearEolComponentCount > 0) {
    return { label: `${identity.nearEolComponentCount} near EOL`, className: 'status-pill status-warning' };
  }
  if (identity.unknownEolComponentCount > 0) {
    return { label: `${identity.unknownEolComponentCount} unknown`, className: 'status-pill status-unknown' };
  }
  return { label: 'Supported', className: 'status-pill status-success' };
}

function normalizeSoftwareText(value?: string): string {
  return (value ?? '').trim().toLowerCase();
}

function overviewSoftwareGroup(identity: SoftwareIdentitySummary): {
  key: string;
  displayName: string;
  filterQuery: string;
  product?: string;
} {
  const vendor = normalizeSoftwareText(identity.vendor);
  const product = normalizeSoftwareText(identity.product);

  if (vendor === 'microsoft') {
    const officeMuiMatch = product.match(/^(access|excel|infopath|lync|office|onenote|outlook|powerpoint|project|publisher|visio|word)_mui_(\d{4})$/);
    if (officeMuiMatch) {
      const collapsedProduct = `office_${officeMuiMatch[2]}`;
      return {
        key: `${vendor}::${collapsedProduct}`,
        displayName: `${vendor}/${collapsedProduct}`,
        filterQuery: `_mui_${officeMuiMatch[2]}`,
        product: collapsedProduct
      };
    }
  }

  return {
    key: identity.normalizedKey || `${vendor}::${product}` || identity.canonicalKey || identity.id,
    displayName: identity.displayName,
    filterQuery: identity.displayName,
    product: identity.product
  };
}

function mergeStringValues(left: string[], right: string[]): string[] {
  return Array.from(new Set([...left, ...right])).sort((a, b) => a.localeCompare(b));
}

function latestObservedAt(left?: string, right?: string): string | undefined {
  if (!left) {
    return right;
  }
  if (!right) {
    return left;
  }
  return new Date(left).getTime() >= new Date(right).getTime() ? left : right;
}

function collapseOverviewSoftwareRows(rows: SoftwareIdentitySummary[]): OverviewSoftwareSummary[] {
  const grouped = new Map<string, OverviewSoftwareSummary>();

  rows.forEach((identity) => {
    const group = overviewSoftwareGroup(identity);
    const current = grouped.get(group.key);

    if (!current) {
      grouped.set(group.key, {
        ...identity,
        displayName: group.displayName,
        product: group.product,
        normalizedKey: group.key,
        collapsedIdentityCount: 1,
        softwareFilterQuery: group.filterQuery
      });
      return;
    }

    const representative = identity.assetCount > current.assetCount
      || (identity.assetCount === current.assetCount && identity.componentCount > current.componentCount)
      ? identity
      : current;

    grouped.set(group.key, {
      ...current,
      id: representative.id,
      canonicalKey: representative.canonicalKey,
      displayName: group.displayName,
      product: group.product,
      assetTypes: mergeStringValues(current.assetTypes, identity.assetTypes),
      ecosystems: mergeStringValues(current.ecosystems, identity.ecosystems),
      sourceSystems: mergeStringValues(current.sourceSystems, identity.sourceSystems),
      eolSlug: current.eolSlug === identity.eolSlug ? current.eolSlug : undefined,
      mappingConfirmed: current.mappingConfirmed && identity.mappingConfirmed,
      needsEolMapping: current.needsEolMapping || identity.needsEolMapping,
      assetCount: Math.max(current.assetCount, identity.assetCount),
      componentCount: Math.max(current.componentCount, identity.componentCount),
      versionCount: Math.max(current.versionCount, identity.versionCount),
      eolComponentCount: Math.max(current.eolComponentCount, identity.eolComponentCount),
      nearEolComponentCount: Math.max(current.nearEolComponentCount, identity.nearEolComponentCount),
      unknownEolComponentCount: Math.max(current.unknownEolComponentCount, identity.unknownEolComponentCount),
      openFindingCount: current.openFindingCount + identity.openFindingCount,
      openVulnerabilityCount: current.openVulnerabilityCount + identity.openVulnerabilityCount,
      lastObservedAt: latestObservedAt(current.lastObservedAt, identity.lastObservedAt),
      collapsedIdentityCount: current.collapsedIdentityCount + 1,
      softwareFilterQuery: group.filterQuery
    });
  });

  return Array.from(grouped.values()).sort((left, right) =>
    right.componentCount - left.componentCount
    || right.assetCount - left.assetCount
    || left.displayName.localeCompare(right.displayName)
  );
}

function firstErrorMessage(errors: Array<unknown>): string | null {
  for (const error of errors) {
    if (error instanceof Error) {
      return error.message;
    }
  }
  return null;
}

function softwareIdentityFilterPath(identity: OverviewSoftwareSummary): string {
  return pathForInventoryViewWithSearch('software-identities', {
    query: identity.softwareFilterQuery || identity.displayName
  });
}

function qualityDomainCount(summary: OperationalQualitySummary | null, domain: string): number {
  if (!summary) {
    return 0;
  }
  return summary.domainCounts.find((entry) => entry.domain === domain)?.issueCount ?? 0;
}

function formatNumber(value: number): string {
  return value.toLocaleString();
}

function percentOf(value: number, total: number): number {
  if (total <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round((value / total) * 100)));
}

function parseInventoryWorkspaceTabs(value: string | null): QualityInventoryWorkspaceTab[] {
  if (!value) {
    return [];
  }

  const seen = new Set<QualityInventoryWorkspaceTab>();
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry): entry is QualityInventoryWorkspaceTab =>
      QUALITY_INVENTORY_WORKSPACE_TABS.includes(entry as QualityInventoryWorkspaceTab))
    .filter((entry) => {
      if (seen.has(entry)) {
        return false;
      }
      seen.add(entry);
      return true;
    });
}

export function InventoryOverviewPage() {
  const navigate = useNavigate();
  const location = useLocation();

  const dashboardQuery = useDashboardSummaryQuery();
  const softwareQuery = useSoftwareIdentitiesQuery({ page: 0, size: SOFTWARE_PAGE_SIZE });
  const eolSummaryQuery = useEolSummaryQuery();
  const unresolvedMappingsQuery = useEolUnresolvedMappingsQuery({ page: 0, size: 1 });
  const qualitySummaryQuery = useOperationalQualitySummaryQuery();
  const inventoryComponentsQuery = useQuery({
    queryKey: ['inventory-overview-active-components'],
    queryFn: loadAllActiveInventoryComponents
  });
  const applicableSoftwareQuery = useQuery({
    queryKey: ['inventory-overview-applicable-software'],
    queryFn: loadAllApplicableSoftware
  });

  const assetsQuery = useQuery({
    queryKey: ['inventory-overview-assets'],
    queryFn: api.listAssets
  });

  const hostAssets = React.useMemo(
    () => (assetsQuery.data ?? []).filter((asset) => asset.type.toUpperCase() === 'HOST'),
    [assetsQuery.data]
  );

  const hostDetailsQuery = useQuery({
    queryKey: ['inventory-overview-host-detail', hostAssets.map((asset) => asset.id)],
    queryFn: async () => Promise.all(
      hostAssets.map(async (asset) => ({
        asset,
        detail: await api.getHostAssetDetail(asset.id)
      }))
    ),
    enabled: hostAssets.length > 0
  });
  const hostDetailsPending = hostAssets.length > 0 && hostDetailsQuery.isPending;

  const dashboard = dashboardQuery.data ?? null;
  const softwarePage = softwareQuery.data ?? null;
  const qualitySummary = qualitySummaryQuery.data ?? null;
  const locationSearchParams = React.useMemo(
    () => new URLSearchParams(location.search),
    [location.search]
  );
  const openWorkspaceTabs = React.useMemo(
    () => parseInventoryWorkspaceTabs(locationSearchParams.get(INVENTORY_TABS_PARAM)),
    [locationSearchParams]
  );
  const activeWorkspaceTab = React.useMemo<InventoryWorkspaceTab>(() => {
    const requested = locationSearchParams.get(INVENTORY_ACTIVE_TAB_PARAM);
    if (requested && openWorkspaceTabs.includes(requested as QualityInventoryWorkspaceTab)) {
      return requested as QualityInventoryWorkspaceTab;
    }
    return 'overview';
  }, [locationSearchParams, openWorkspaceTabs]);
  const updateOverviewSearch = React.useCallback((updates: Record<string, string | null>) => {
    const next = new URLSearchParams(location.search);
    Object.entries(updates).forEach(([key, value]) => {
      if (!value) {
        next.delete(key);
      } else {
        next.set(key, value);
      }
    });
    navigate(
      {
        pathname: location.pathname,
        search: next.toString() ? `?${next.toString()}` : ''
      },
      { replace: true }
    );
  }, [location.pathname, location.search, navigate]);
  const writeWorkspaceTabs = React.useCallback((
    tabs: QualityInventoryWorkspaceTab[],
    activeTab: InventoryWorkspaceTab
  ) => {
    updateOverviewSearch({
      [INVENTORY_TABS_PARAM]: tabs.length > 0 ? tabs.join(',') : null,
      [INVENTORY_ACTIVE_TAB_PARAM]: activeTab === 'overview' ? null : activeTab
    });
  }, [updateOverviewSearch]);
  const openWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    const nextTabs = openWorkspaceTabs.includes(tab) ? openWorkspaceTabs : [...openWorkspaceTabs, tab];
    writeWorkspaceTabs(nextTabs, tab);
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const activateOverviewTab = React.useCallback(() => {
    writeWorkspaceTabs(openWorkspaceTabs, 'overview');
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const activateWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    writeWorkspaceTabs(openWorkspaceTabs, tab);
  }, [openWorkspaceTabs, writeWorkspaceTabs]);
  const closeWorkspaceTab = React.useCallback((tab: QualityInventoryWorkspaceTab) => {
    const nextTabs = openWorkspaceTabs.filter((entry) => entry !== tab);
    const nextActive = activeWorkspaceTab === tab ? (nextTabs[nextTabs.length - 1] ?? 'overview') : activeWorkspaceTab;
    writeWorkspaceTabs(nextTabs, nextActive);
  }, [activeWorkspaceTab, openWorkspaceTabs, writeWorkspaceTabs]);
  const allAssets = React.useMemo(
    () => assetsQuery.data ?? [],
    [assetsQuery.data]
  );

  const softwareRows = React.useMemo(
    () => collapseOverviewSoftwareRows(softwarePage?.content ?? []),
    [softwarePage?.content]
  );
  const assetNormalizationSummary = React.useMemo(
    () => buildAssetNormalizationSummary(inventoryComponentsQuery.data ?? []),
    [inventoryComponentsQuery.data]
  );
  const componentStatsByAssetId = React.useMemo(() => {
    const stats = new Map<string, {
      componentCount: number;
      normalizedComponentCount: number;
      reviewGapCount: number;
      eolComponentCount: number;
      unknownLifecycleCount: number;
    }>();

    (inventoryComponentsQuery.data ?? []).forEach((component) => {
      const current = stats.get(component.assetId) ?? {
        componentCount: 0,
        normalizedComponentCount: 0,
        reviewGapCount: 0,
        eolComponentCount: 0,
        unknownLifecycleCount: 0
      };
      current.componentCount += 1;
      if (inventoryComponentIsNormalized(component)) {
        current.normalizedComponentCount += 1;
      }
      if (component.needsReview) {
        current.reviewGapCount += 1;
      }
      if (component.isEol) {
        current.eolComponentCount += 1;
      }
      if (!component.eolSlug) {
        current.unknownLifecycleCount += 1;
      }
      stats.set(component.assetId, current);
    });

    return stats;
  }, [inventoryComponentsQuery.data]);
  const applicableCvesByAssetId = React.useMemo(() => {
    const stats = new Map<string, number>();
    (applicableSoftwareQuery.data ?? []).forEach((record) => {
      stats.set(record.assetId, (stats.get(record.assetId) ?? 0) + record.applicableCveCount);
    });
    return stats;
  }, [applicableSoftwareQuery.data]);
  const assetTypeSummaries = React.useMemo(
    () => buildAssetTypePortfolioSummaries(allAssets, inventoryComponentsQuery.data ?? []),
    [allAssets, inventoryComponentsQuery.data]
  );
  const topSoftwareByDeployment = React.useMemo(
    () => [...softwareRows]
      .sort((left, right) =>
        (right.openVulnerabilityCount + right.openFindingCount) - (left.openVulnerabilityCount + left.openFindingCount)
        || right.assetCount - left.assetCount
        || left.displayName.localeCompare(right.displayName))
      .slice(0, SOFTWARE_TABLE_ROWS),
    [softwareRows]
  );
  const hostRecords = React.useMemo<HostOverviewRecord[]>(() => (
    (hostDetailsQuery.data ?? [])
      .map(({ asset, detail }) => toHostOverviewRecord(asset, detail))
      .sort((left, right) => right.attentionScore - left.attentionScore || left.asset.name.localeCompare(right.asset.name))
  ), [hostDetailsQuery.data]);
  const hostSignalsByAssetId = React.useMemo(() => {
    const stats = new Map<string, { openFindingCount: number; operatingSystem: string; lastSeenAt?: string }>();
    hostRecords.forEach((record) => {
      stats.set(record.asset.id, {
        openFindingCount: record.openFindingCount,
        operatingSystem: record.operatingSystem,
        lastSeenAt: record.lastSeenAt
      });
    });
    return stats;
  }, [hostRecords]);
  const assetRecords = React.useMemo<AssetOverviewRecord[]>(() => (
    allAssets
      .flatMap((asset) => {
        const assetType = normalizeAssetType(asset.type);
        if (!assetType) {
          return [];
        }
        const componentStats = componentStatsByAssetId.get(asset.id) ?? {
          componentCount: 0,
          normalizedComponentCount: 0,
          reviewGapCount: 0,
          eolComponentCount: 0,
          unknownLifecycleCount: 0
        };
        const applicableCveCount = applicableCvesByAssetId.get(asset.id) ?? 0;
        const hostSignals = hostSignalsByAssetId.get(asset.id);
        const lastSeenAt = hostSignals?.lastSeenAt ?? assetLastSeen(asset);
        const freshness = freshnessStateFor(lastSeenAt);
        const notNormalizedSoftwareCount = Math.max(0, componentStats.componentCount - componentStats.normalizedComponentCount);
        const freshnessWeight = freshness.label === 'Stale' ? 8 : freshness.label === 'Aging' ? 4 : 0;
        const openFindingCount = hostSignals?.openFindingCount ?? 0;
        return [{
          asset,
          assetType,
          operatingSystem: hostSignals?.operatingSystem,
          deployedSoftwareCount: componentStats.componentCount,
          normalizedSoftwareCount: componentStats.normalizedComponentCount,
          notNormalizedSoftwareCount,
          normalization: hostNormalizationStateFor(componentStats.componentCount, notNormalizedSoftwareCount),
          openFindingCount,
          applicableCveCount,
          lastSeenAt,
          freshness,
          eolSoftwareCount: componentStats.eolComponentCount,
          unknownLifecycleCount: componentStats.unknownLifecycleCount,
          reviewGapCount: componentStats.reviewGapCount,
          attentionScore: (openFindingCount * 5)
            + (applicableCveCount * 3)
            + (componentStats.eolComponentCount * 4)
            + (componentStats.unknownLifecycleCount * 2)
            + (componentStats.reviewGapCount * 3)
            + (notNormalizedSoftwareCount * 2)
            + freshnessWeight
        }];
      })
      .sort((left, right) => right.attentionScore - left.attentionScore || left.asset.name.localeCompare(right.asset.name))
  ), [allAssets, applicableCvesByAssetId, componentStatsByAssetId, hostSignalsByAssetId]);

  const softwareLoading = dashboardQuery.isPending
    || softwareQuery.isPending
    || eolSummaryQuery.isPending
    || unresolvedMappingsQuery.isPending
    || qualitySummaryQuery.isPending
    || applicableSoftwareQuery.isPending
    || inventoryComponentsQuery.isPending;
  const assetLoading = assetsQuery.isPending
    || hostDetailsPending
    || applicableSoftwareQuery.isPending
    || inventoryComponentsQuery.isPending;
  const softwareError = firstErrorMessage([
    dashboardQuery.error,
    softwareQuery.error,
    eolSummaryQuery.error,
    unresolvedMappingsQuery.error,
    qualitySummaryQuery.error,
    applicableSoftwareQuery.error,
    inventoryComponentsQuery.error
  ]);
  const assetError = firstErrorMessage([
    assetsQuery.error,
    hostDetailsQuery.error,
    applicableSoftwareQuery.error,
    inventoryComponentsQuery.error
  ]);

  const totalKnownAssets = assetTypeSummaries.reduce((sum, summary) => sum + summary.totalAssetCount, 0);
  const activeComponentCount = inventoryComponentsQuery.data?.length ?? dashboard?.components ?? 0;
  const overviewLoading = softwareLoading || assetLoading;
  const overviewHasData = totalKnownAssets > 0 || activeComponentCount > 0 || softwareRows.length > 0 || assetRecords.length > 0;
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    dashboardQuery.dataUpdatedAt,
    softwareQuery.dataUpdatedAt,
    eolSummaryQuery.dataUpdatedAt,
    unresolvedMappingsQuery.dataUpdatedAt,
    qualitySummaryQuery.dataUpdatedAt,
    applicableSoftwareQuery.dataUpdatedAt,
    inventoryComponentsQuery.dataUpdatedAt,
    assetsQuery.dataUpdatedAt,
    hostDetailsQuery.dataUpdatedAt
  ]), [
    applicableSoftwareQuery.dataUpdatedAt,
    assetsQuery.dataUpdatedAt,
    dashboardQuery.dataUpdatedAt,
    eolSummaryQuery.dataUpdatedAt,
    hostDetailsQuery.dataUpdatedAt,
    inventoryComponentsQuery.dataUpdatedAt,
    qualitySummaryQuery.dataUpdatedAt,
    softwareQuery.dataUpdatedAt,
    unresolvedMappingsQuery.dataUpdatedAt
  ]);
  const overviewRefreshing = overviewHasData && [
    dashboardQuery,
    softwareQuery,
    eolSummaryQuery,
    unresolvedMappingsQuery,
    qualitySummaryQuery,
    applicableSoftwareQuery,
    inventoryComponentsQuery,
    assetsQuery,
    hostDetailsQuery
  ].some((query) => query.isFetching);
  const normalizationIssueCount = qualityDomainCount(qualitySummary, 'NORMALIZATION');
  const correlationIssueCount = qualityDomainCount(qualitySummary, 'CORRELATION');
  const unmatchedEolCount = qualityDomainCount(qualitySummary, 'EOL');
  const vexIssueCount = qualityDomainCount(qualitySummary, 'VEX');
  const _totalOpenFindings = assetRecords.reduce((sum, record) => sum + record.openFindingCount, 0);
  const _totalApplicableCves = assetRecords.reduce((sum, record) => sum + record.applicableCveCount, 0);
  const eolComponentCount = eolSummaryQuery.data?.eolCount ?? assetRecords.reduce((sum, record) => sum + record.eolSoftwareCount, 0);
  const nearEolComponentCount = eolSummaryQuery.data?.nearEolCount ?? 0;
  const unknownLifecycleCount = eolSummaryQuery.data?.unknownCount ?? assetRecords.reduce((sum, record) => sum + record.unknownLifecycleCount, 0);
  const supportedLifecycleCount = eolSummaryQuery.data?.supportedCount ?? Math.max(0, activeComponentCount - eolComponentCount - nearEolComponentCount - unknownLifecycleCount);
  const _lifecycleRiskTotal = eolComponentCount + nearEolComponentCount + unknownLifecycleCount;
  const _normalizationCoverage = assetNormalizationSummary.trackedAssetCount > 0
    ? Math.round(assetNormalizationSummary.normalizedAssetCoveragePercent)
    : 0;
  const unknownPublisherCount = softwareRows.filter((identity) => {
    const vendor = identity.vendor?.trim().toLowerCase();
    return !vendor || vendor === 'unknown' || vendor === 'unknown vendor';
  }).length;
  const identifierMappedRows = (inventoryComponentsQuery.data ?? []).filter((component) =>
    hasValue(component.purl)
  ).length;
  const standardIdentifierMatchRate = percentOf(identifierMappedRows, activeComponentCount);
  const eolCoverageRows = (inventoryComponentsQuery.data ?? []).filter((component) =>
    hasValue(component.eolSlug)
  ).length;
  const eolCoverageRate = percentOf(eolCoverageRows, activeComponentCount);
  const licenseCoverageRate = 0;
  const lifecycleBreakdownRows = [
    { label: 'EOL', count: eolComponentCount, className: 'vuln-repo-inline-bar vuln-repo-inline-bar--critical' },
    { label: 'Near EOL', count: nearEolComponentCount, className: 'vuln-repo-inline-bar vuln-repo-inline-bar--high' },
    { label: 'Unknown', count: unknownLifecycleCount, className: 'vuln-repo-inline-bar vuln-repo-inline-bar--medium' },
    { label: 'Supported', count: supportedLifecycleCount, className: 'vuln-repo-inline-bar vuln-repo-inline-bar--low' }
  ];
  const lifecycleBreakdownMax = Math.max(1, ...lifecycleBreakdownRows.map((row) => row.count));
  const qualityBreakdownRows: Array<{ label: string; count: number; tab: QualityInventoryWorkspaceTab }> = [
    { label: 'Normalization', count: normalizationIssueCount, tab: INVENTORY_NORMALIZATION_TAB },
    { label: 'Correlation', count: correlationIssueCount, tab: INVENTORY_CORRELATION_TAB },
    { label: 'Lifecycle mapping', count: unmatchedEolCount, tab: INVENTORY_EOL_TAB },
    { label: 'VEX', count: vexIssueCount, tab: INVENTORY_VEX_TAB }
  ];
  const qualityBreakdownMax = Math.max(1, ...qualityBreakdownRows.map((row) => row.count));
  const assetsWithEolSoftware = assetRecords.filter((record) => record.eolSoftwareCount > 0).length;
  const assetsWithCveExposure = assetRecords.filter((record) => record.applicableCveCount > 0).length;
  const externalFacingWithCves = assetRecords.filter((record) => isExternalFacingAsset(record) && record.applicableCveCount > 0).length;
  const inventoryFunnelRows: InventoryWidgetRow[] = [
    {
      label: 'Total assets',
      value: totalKnownAssets,
      percent: 100,
      className: 'vuln-repo-inline-bar vuln-repo-inline-bar--low',
      actionPath: pathForInventoryView('hosts')
    },
    {
      label: 'Assets with EOL software',
      value: assetsWithEolSoftware,
      percent: percentOf(assetsWithEolSoftware, totalKnownAssets),
      className: 'vuln-repo-inline-bar vuln-repo-inline-bar--critical',
      actionPath: pathForInventoryViewWithSearch('hosts', { quickFilter: 'with-eol' })
    },
    {
      label: 'Assets with CVE exposure',
      value: assetsWithCveExposure,
      percent: percentOf(assetsWithCveExposure, totalKnownAssets),
      className: 'vuln-repo-inline-bar vuln-repo-inline-bar--high',
      actionPath: pathForInventoryViewWithSearch('hosts', { quickFilter: 'with-cves' })
    },
    {
      label: 'External facing with CVEs',
      value: externalFacingWithCves,
      percent: percentOf(externalFacingWithCves, totalKnownAssets),
      className: 'vuln-repo-inline-bar vuln-repo-inline-bar--critical',
      actionPath: pathForInventoryViewWithSearch('hosts', { quickFilter: 'external-with-cves' })
    },
    {
      label: 'Assets with findings',
      value: assetRecords.filter((record) => record.openFindingCount > 0).length,
      percent: percentOf(assetRecords.filter((record) => record.openFindingCount > 0).length, totalKnownAssets),
      className: 'vuln-repo-inline-bar vuln-repo-inline-bar--critical',
      actionPath: pathForInventoryViewWithSearch('hosts', { quickFilter: 'with-findings' })
    }
  ];
  const osRows: InventoryWidgetRow[] = React.useMemo(() => {
    const osStats = new Map<string, { assets: number; cves: number; eol: number }>();
    hostRecords.forEach((record) => {
      const os = record.operatingSystem || 'Unknown';
      const current = osStats.get(os) ?? { assets: 0, cves: 0, eol: 0 };
      current.assets += 1;
      current.cves += record.applicableCveCount;
      if (record.eolSoftwareCount > 0) {
        current.eol += 1;
      }
      osStats.set(os, current);
    });
    const maxAssets = Math.max(1, ...Array.from(osStats.values()).map((entry) => entry.assets));
    return Array.from(osStats.entries())
      .map(([label, entry]) => ({
        label,
        value: entry.assets,
        percent: percentOf(entry.assets, maxAssets),
        caption: `${formatNumber(entry.cves)} CVEs · ${formatNumber(entry.eol)} with EOL OS/software`,
        className: entry.cves > 0
          ? 'vuln-repo-inline-bar vuln-repo-inline-bar--high'
          : 'vuln-repo-inline-bar vuln-repo-inline-bar--low',
        actionPath: pathForInventoryViewWithSearch('software-identities', { operatingSystem: label })
      }))
      .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
      .slice(0, 4);
  }, [hostRecords]);
  const highRiskVendorRows: InventoryWidgetRow[] = React.useMemo(() => {
    const vendorStats = new Map<string, { cves: number; assets: number }>();
    softwareRows.forEach((identity) => {
      const vendor = identity.vendor?.trim() || 'Unknown vendor';
      const current = vendorStats.get(vendor) ?? { cves: 0, assets: 0 };
      current.cves += identity.openVulnerabilityCount;
      current.assets += identity.assetCount;
      vendorStats.set(vendor, current);
    });
    const maxCves = Math.max(1, ...Array.from(vendorStats.values()).map((entry) => entry.cves));
    return Array.from(vendorStats.entries())
      .map(([label, entry]) => ({
        label,
        value: entry.cves,
        percent: percentOf(entry.cves, maxCves),
        caption: `${formatNumber(entry.assets)} assets running vendor software`,
        className: entry.cves > 0
          ? 'vuln-repo-inline-bar vuln-repo-inline-bar--high'
          : 'vuln-repo-inline-bar vuln-repo-inline-bar--low',
        actionPath: pathForInventoryViewWithSearch('software-identities', { query: label })
      }))
      .filter((entry) => entry.value > 0 || entry.caption !== '0 assets running vendor software')
      .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
      .slice(0, 4);
  }, [softwareRows]);
  const eolSoftwareRows: InventoryWidgetRow[] = React.useMemo(() => {
    const riskySoftware = softwareRows
      .filter((identity) => identity.eolComponentCount > 0 || identity.nearEolComponentCount > 0)
      .map((identity) => ({
        label: identity.displayName,
        value: identity.eolComponentCount + identity.nearEolComponentCount,
        percent: 0,
        caption: `${formatNumber(identity.assetCount)} assets · ${formatNumber(identity.openVulnerabilityCount)} CVEs`,
        className: identity.eolComponentCount > 0
          ? 'vuln-repo-inline-bar vuln-repo-inline-bar--critical'
          : 'vuln-repo-inline-bar vuln-repo-inline-bar--high',
        actionPath: pathForSoftwareIdentityDetail(identity.id)
      }))
      .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
      .slice(0, 4);
    const maxLifecycle = Math.max(1, ...riskySoftware.map((entry) => entry.value));
    return riskySoftware.map((entry) => ({
      ...entry,
      percent: percentOf(entry.value, maxLifecycle)
    }));
  }, [softwareRows]);
  const _qualityIssueCount = qualitySummary?.totalIssues ?? (
    normalizationIssueCount + correlationIssueCount + unmatchedEolCount + vexIssueCount
  );
  const renderWidgetRows = (rows: InventoryWidgetRow[], emptyLabel: string): React.ReactNode => (
    <div className="vuln-repo-dashboard-funnel">
      {rows.length === 0 ? (
        <div className="empty-state">{emptyLabel}</div>
      ) : rows.map((item) => {
        const content = (
          <>
            <div className="vuln-repo-dashboard-funnel-copy">
              <span>{item.label}</span>
              <strong>{formatNumber(item.value)}</strong>
            </div>
            {item.caption ? <div className="panel-caption">{item.caption}</div> : null}
            <div className="vuln-repo-dashboard-funnel-track">
              <span className={item.className} style={{ width: `${Math.max(3, item.percent)}%` }} />
            </div>
          </>
        );
        return item.actionPath ? (
          <button
            key={item.label}
            type="button"
            className="vuln-repo-dashboard-funnel-row inventory-overview-funnel-action"
            onClick={() => navigate(item.actionPath ?? pathForInventoryView('hosts'))}
          >
            {content}
          </button>
        ) : (
          <div key={item.label} className="vuln-repo-dashboard-funnel-row">
            {content}
          </div>
        );
      })}
    </div>
  );

  return (
    <section className="inventory-overview-shell vuln-repo-dashboard-page">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={overviewRefreshing}
        refreshLabel="Refreshing inventory overview while keeping current signals visible…"
      />

      {(openWorkspaceTabs.length > 0 || activeWorkspaceTab !== 'overview') ? (
      <div className="inventory-workspace-tabs" role="tablist" aria-label="Inventory workspace tabs">
        <button
          type="button"
          className={`inventory-workspace-tab${activeWorkspaceTab === 'overview' ? ' active' : ''}`}
          onClick={activateOverviewTab}
          role="tab"
          aria-selected={activeWorkspaceTab === 'overview'}
        >
          Overview
        </button>
        {openWorkspaceTabs.map((tab) => (
          <div key={tab} className={`inventory-workspace-tab-shell${activeWorkspaceTab === tab ? ' active' : ''}`}>
            <button
              type="button"
              className={`inventory-workspace-tab${activeWorkspaceTab === tab ? ' active' : ''}`}
              onClick={() => activateWorkspaceTab(tab)}
              role="tab"
              aria-selected={activeWorkspaceTab === tab}
            >
              {INVENTORY_WORKSPACE_TAB_CONFIG[tab].label}
            </button>
            <button
              type="button"
              className="inventory-workspace-tab-close"
              onClick={() => closeWorkspaceTab(tab)}
              aria-label={`Close ${INVENTORY_WORKSPACE_TAB_CONFIG[tab].label} tab`}
            >
              ×
            </button>
          </div>
        ))}
      </div>
      ) : null}

      <section className="inventory-overview-section">
        {activeWorkspaceTab !== 'overview' ? (
          <InventoryQualityWorkspace
            embedded
            forcedDomain={INVENTORY_WORKSPACE_TAB_CONFIG[activeWorkspaceTab].domain}
            showPanelHeader={false}
            storageKeyPrefix={`inventory-${activeWorkspaceTab}`}
          />
        ) : (
          <>
            {softwareError ? (
              <div className="inventory-error-banner">Failed to load software summary: {softwareError}</div>
            ) : null}
            {assetError ? (
              <div className="inventory-error-banner">Failed to load asset summary: {assetError}</div>
            ) : null}

            {overviewLoading && !overviewHasData ? (
              <div className="empty-state"><p>Loading combined inventory overview…</p></div>
            ) : (
              <>
            <AiInventoryOverviewStrip />
            <div className="stats-grid vuln-repo-dashboard-stats-grid inventory-overview-dashboard-stats">
              <article className="vuln-repo-dashboard-stat-button vuln-repo-dashboard-funnel-card">
                <div className="stat-card">
                  <div className="stat-card-label">Inventory Funnel</div>
                  {renderWidgetRows(inventoryFunnelRows, 'No asset inventory is available yet.')}
                </div>
              </article>
              <article className="vuln-repo-dashboard-stat-button vuln-repo-dashboard-funnel-card">
                <div className="stat-card">
                  <div className="stat-card-label">Assets by OS</div>
                  {renderWidgetRows(osRows, 'No host operating system data is available yet.')}
                </div>
              </article>
              <article className="vuln-repo-dashboard-stat-button vuln-repo-dashboard-funnel-card">
                <div className="stat-card">
                  <div className="stat-card-label">High Risk Vendors</div>
                  {renderWidgetRows(highRiskVendorRows, 'No vendor CVE exposure is available yet.')}
                </div>
              </article>
              <article className="vuln-repo-dashboard-stat-button vuln-repo-dashboard-funnel-card">
                <div className="stat-card">
                  <div className="stat-card-label">Softwares with EOS/EOL</div>
                  {renderWidgetRows(eolSoftwareRows, 'No EOS/EOL software is currently detected.')}
                </div>
              </article>
            </div>

            <div className="dashboard-grid vuln-repo-dashboard-main-grid">
              <section className="panel vuln-repo-dashboard-panel">
                <div className="panel-header">
                  <div className="vuln-repo-dashboard-section-copy">
                    <h3>Lifecycle breakdown</h3>
                    <div className="panel-caption">Component lifecycle status</div>
                  </div>
                </div>
                <div className="vuln-repo-dashboard-breakdown-list">
                  {lifecycleBreakdownRows.map((item) => (
                    <div key={item.label} className="vuln-repo-dashboard-breakdown-row">
                      <span>{item.label}</span>
                      <div className="vuln-repo-dashboard-breakdown-bar">
                        <span className={item.className} style={{ width: `${(item.count / lifecycleBreakdownMax) * 100}%` }} />
                      </div>
                      <button
                        type="button"
                        className="btn-link vuln-repo-dashboard-count-link"
                        onClick={() => openWorkspaceTab(INVENTORY_EOL_TAB)}
                      >
                        {formatNumber(item.count)}
                      </button>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel vuln-repo-dashboard-panel">
                <div className="panel-header">
                  <div className="vuln-repo-dashboard-section-copy">
                    <h3>Quality gaps</h3>
                    <div className="panel-caption">Issues blocking reliable risk decisions</div>
                  </div>
                </div>
                <div className="vuln-repo-dashboard-breakdown-list">
                  {qualityBreakdownRows.map((item) => (
                    <div key={item.label} className="vuln-repo-dashboard-breakdown-row">
                      <span>{item.label}</span>
                      <div className="vuln-repo-dashboard-breakdown-bar">
                        <span className="vuln-repo-inline-bar vuln-repo-inline-bar--medium" style={{ width: `${(item.count / qualityBreakdownMax) * 100}%` }} />
                      </div>
                      <button
                        type="button"
                        className="btn-link vuln-repo-dashboard-count-link"
                        onClick={() => openWorkspaceTab(item.tab)}
                      >
                        {formatNumber(item.count)}
                      </button>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <section className="panel vuln-repo-dashboard-panel">
              <div className="panel-header">
                <div className="vuln-repo-dashboard-section-copy">
                  <h3>Software and inventory context</h3>
                  <div className="panel-caption">Software identities driving footprint, vulnerabilities, lifecycle exposure, and remediation workload.</div>
                </div>
              </div>
              <div className="vuln-repo-dashboard-context-grid">
                <div className="vuln-repo-dashboard-context-section">
                  <div className="vuln-repo-dashboard-panel-block-header">
                    <h4>Top risky software</h4>
                    <div className="panel-caption">Sorted by open CVEs, findings, and deployment count</div>
                  </div>
                  <button type="button" className="btn-link vuln-repo-dashboard-inline-link" onClick={() => navigate(pathForInventoryView('software-identities'))}>Show all</button>
                  <div className="vuln-repo-dashboard-software-list">
                    {topSoftwareByDeployment.length === 0 ? (
                      <div className="empty-state">No software inventory is available yet.</div>
                    ) : (
                      <>
                        <div className="vuln-repo-dashboard-software-row vuln-repo-dashboard-software-row--header">
                          <span>Software</span>
                          <span>CVEs</span>
                          <span>Assets</span>
                          <span>Findings</span>
                          <span>Lifecycle</span>
                        </div>
                        {topSoftwareByDeployment.slice(0, 5).map((identity) => {
                          const lifecycle = softwareLifecycleSummary(identity);
                          return (
                            <div key={identity.id} className="vuln-repo-dashboard-software-row">
                              <div className="vuln-repo-dashboard-software-copy">
                                <button
                                  type="button"
                                  className="btn-link inventory-primary-text vuln-repo-dashboard-software-link"
                                  onClick={() => navigate(pathForSoftwareIdentityDetail(identity.id))}
                                >
                                  <strong>{identity.displayName}</strong>
                                </button>
                                <span>{identity.vendor || 'Unknown vendor'}</span>
                              </div>
                              <button
                                type="button"
                                className="btn-link vuln-repo-dashboard-count-link"
                                onClick={() => navigate(softwareIdentityFilterPath(identity))}
                              >
                                {formatNumber(identity.openVulnerabilityCount)}
                              </button>
                              <button
                                type="button"
                                className="btn-link vuln-repo-dashboard-count-link"
                                onClick={() => navigate(softwareIdentityFilterPath(identity))}
                              >
                                {formatNumber(identity.assetCount)}
                              </button>
                              <button
                                type="button"
                                className="btn-link vuln-repo-dashboard-count-link"
                                onClick={() => navigate(softwareIdentityFilterPath(identity))}
                              >
                                {formatNumber(identity.openFindingCount)}
                              </button>
                              <span className={lifecycle.className}>{lifecycle.label}</span>
                            </div>
                          );
                        })}
                      </>
                    )}
                  </div>
                </div>

                <div className="vuln-repo-dashboard-context-section">
                  <div className="vuln-repo-dashboard-panel-block-header">
                    <h4>Coverage signals</h4>
                    <div className="panel-caption">How much inventory can support risk analysis</div>
                  </div>
                  <div className="vuln-repo-dashboard-resolution-grid inventory-overview-coverage-grid">
                    <button type="button" className="vuln-repo-dashboard-resolution-card" onClick={() => navigate(pathForInventoryView('software-identities'))}>
                      <strong>{formatNumber(softwarePage?.totalElements ?? 0)}</strong>
                      <span>Software identities</span>
                    </button>
                    <button type="button" className="vuln-repo-dashboard-resolution-card" onClick={() => navigate(pathForInventoryView('hosts'))}>
                      <strong>{formatNumber(activeComponentCount)}</strong>
                      <span>Active software rows</span>
                    </button>
                    <button type="button" className="vuln-repo-dashboard-resolution-card vuln-repo-dashboard-resolution-card--info" onClick={() => navigate(pathForInventoryViewWithSearch('software-identities', { query: 'unknown' }))}>
                      <strong>{formatNumber(unknownPublisherCount)}</strong>
                      <span>Unknown publisher</span>
                    </button>
                    <button type="button" className="vuln-repo-dashboard-resolution-card vuln-repo-dashboard-resolution-card--success" onClick={() => navigate(pathForInventoryView('software-identities'))}>
                      <strong>{standardIdentifierMatchRate}%</strong>
                      <span>CPE/PURL match rate</span>
                    </button>
                    <button type="button" className="vuln-repo-dashboard-resolution-card vuln-repo-dashboard-resolution-card--success" onClick={() => openWorkspaceTab(INVENTORY_EOL_TAB)}>
                      <strong>{eolCoverageRate}%</strong>
                      <span>EOL/EOS coverage</span>
                    </button>
                    <button type="button" className="vuln-repo-dashboard-resolution-card" onClick={() => navigate(pathForInventoryView('software-identities'))}>
                      <strong>{licenseCoverageRate}%</strong>
                      <span>License coverage</span>
                    </button>
                  </div>
                </div>
              </div>
            </section>

              </>
            )}
          </>
        )}
      </section>
    </section>
  );
}
