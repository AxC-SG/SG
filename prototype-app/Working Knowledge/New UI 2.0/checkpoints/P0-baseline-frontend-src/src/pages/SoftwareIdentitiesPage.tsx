import React from 'react';
import '../styles/findings-list.css';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { MultiGroupBy, type MultiGroupByOption } from '../components/MultiGroupBy';
import { DonutChart, HBarChart, WidgetCard } from '../features/widgets/FplWidgets';
import { pathForInventoryHostAsset, pathForInventoryViewWithSearch, pathForSoftwareIdentityDetail } from '../app/routes';
import {
  formatAssetType,
  formatInventoryLabel,
  formatInventorySourceSystem
} from '../features/inventory/helpers';
import {
  INVENTORY_ECOSYSTEM_QUERY_KEY,
  INVENTORY_SOURCE_SYSTEM_QUERY_KEY,
  HOST_OPERATING_SYSTEM_QUERY_KEY,
  SOFTWARE_LIFECYCLE_QUERY_KEY,
  SOFTWARE_MAPPING_STATE_QUERY_KEY,
  readInventoryGroupByFromSearch,
  readInventoryQueryFromSearch,
  readSearchValueFromSearch,
  readSearchValuesFromSearch,
  writeInventoryGroupByToSearch,
  writeInventoryQueryToSearch,
  writeSearchValueToSearch,
  writeSearchValuesToSearch
} from '../features/inventory/searchState';
import {
  useSoftwareIdentitiesQuery,
  useSoftwareIdentityDetailQuery,
  useSoftwareIdentityFunnelQuery
} from '../features/software-identities/queries';
import { EolBadge } from '../components/EolBadge';
import { FindingSeverityChips } from '../features/findings/components/FindingSeverityChips';
import { InventoryShell } from '../features/inventory/InventoryShell';
import type {
  SoftwareIdentityCoverage,
  SoftwareIdentitySummary
} from '../features/software-identities/types';

const COL_SPAN = 7;
const SOFTWARE_COVERAGE_QUERY_KEY = 'coverage';
const SOFTWARE_GROUP_BY_OPTIONS: MultiGroupByOption[] = [
  { key: 'sourceSystem', label: 'Source System' },
  { key: 'ecosystem', label: 'Ecosystem' },
  { key: 'lifecycle', label: 'Lifecycle' },
  { key: 'mappingState', label: 'Mapping State' },
  { key: 'vendor', label: 'Vendor' },
  { key: 'assetType', label: 'Asset Type' }
];
const LIFECYCLE_OPTIONS = [
  { value: '', label: 'Any lifecycle' },
  { value: 'eol', label: 'EOL' },
  { value: 'near-eol', label: 'Near EOL' },
  { value: 'unknown', label: 'Unknown' },
  { value: 'supported', label: 'Supported' }
] as const;
const MAPPING_STATE_OPTIONS = [
  { value: '', label: 'Any mapping state' },
  { value: 'needs-review', label: 'Needs review' },
  { value: 'mapped', label: 'Mapped' },
  { value: 'manual', label: 'Manual mapping' },
  { value: 'automatic', label: 'Automatic mapping' }
] as const;
const SOFTWARE_IDENTITIES_PAGE_SIZE = 200;

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function formatDate(value?: string | null): string {
  if (!value) return '—';
  return value;
}

function identityLifecycle(identity: SoftwareIdentitySummary): string {
  if (identity.eolComponentCount > 0) return 'EOL';
  if (identity.nearEolComponentCount > 0) return 'Near EOL';
  if (identity.unknownEolComponentCount > 0) return 'Unknown';
  return 'Supported';
}

function identityMappingState(identity: SoftwareIdentitySummary): string {
  if (identity.needsEolMapping) return 'Needs review';
  if (!identity.eolSlug) return 'Unmapped';
  return identity.mappingConfirmed ? 'Manual mapping' : 'Automatic mapping';
}

function softwareIdentityGroupValues(identity: SoftwareIdentitySummary, key: string): string[] {
  if (key === 'sourceSystem') {
    return identity.sourceSystems.length > 0
      ? identity.sourceSystems.map((value) => formatInventorySourceSystem(value))
      : ['Unspecified source'];
  }
  if (key === 'ecosystem') {
    return identity.ecosystems.length > 0 ? identity.ecosystems : ['Unspecified ecosystem'];
  }
  if (key === 'lifecycle') {
    return [identityLifecycle(identity)];
  }
  if (key === 'mappingState') {
    return [identityMappingState(identity)];
  }
  if (key === 'vendor') {
    return [identity.vendor || identity.product || 'Unknown vendor'];
  }
  if (key === 'assetType') {
    return identity.assetTypes.length > 0
      ? identity.assetTypes.map((value) => formatAssetType(value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'))
      : ['Unknown asset type'];
  }
  return ['Unknown'];
}

function eolSummaryLabel(identity: SoftwareIdentitySummary): string {
  if (identity.eolComponentCount > 0) return `${identity.eolComponentCount} EOL`;
  if (identity.nearEolComponentCount > 0) return `${identity.nearEolComponentCount} near EOL`;
  if (identity.unknownEolComponentCount > 0) return 'Unknown';
  return 'Supported';
}

function eolSummaryClass(identity: SoftwareIdentitySummary): string {
  if (identity.eolComponentCount > 0) return 'si-eol-summary si-eol-summary-risk';
  if (identity.nearEolComponentCount > 0) return 'si-eol-summary si-eol-summary-warn';
  return 'si-eol-summary';
}

function readCoverageFromSearch(searchParams: URLSearchParams): SoftwareIdentityCoverage | '' {
  const value = searchParams.get(SOFTWARE_COVERAGE_QUERY_KEY);
  if (
    value === 'records-found'
    || value === 'unique-software'
    || value === 'with-vulnerabilities'
    || value === 'with-findings'
  ) {
    return value;
  }
  return '';
}

function writeCoverageToSearch(searchParams: URLSearchParams, coverage: SoftwareIdentityCoverage | ''): URLSearchParams {
  const next = new URLSearchParams(searchParams);
  if (coverage) {
    next.set(SOFTWARE_COVERAGE_QUERY_KEY, coverage);
  } else {
    next.delete(SOFTWARE_COVERAGE_QUERY_KEY);
  }
  return next;
}

// ─── Active panel state ────────────────────────────────────────────────────

type ActivePanel = {
  type: 'assets' | 'cves';
  identityId: string;
  identityName: string;
  versionFilter?: string;
} | null;

function inventoryViewForAssetType(assetType?: string): 'hosts' | 'sbom' | 'container-images' {
  const normalized = assetType?.trim().toUpperCase();
  if (normalized === 'APPLICATION') {
    return 'sbom';
  }
  if (normalized === 'CONTAINER_IMAGE') {
    return 'container-images';
  }
  return 'hosts';
}

// ─── Entity list panel ─────────────────────────────────────────────────────

function EntityListPanel({ panel, onClose }: { panel: NonNullable<ActivePanel>; onClose: () => void }) {
  const navigate = useNavigate();
  const location = useLocation();
  const detailQuery = useSoftwareIdentityDetailQuery(panel.identityId, true);
  const detail = detailQuery.data;

  const assets = React.useMemo(() => {
    if (!detail) return [];
    let list = detail.assets;
    if (panel.versionFilter) {
      list = list.filter(a => a.version === panel.versionFilter);
    }
    if (panel.type === 'cves') {
      list = list.filter(a => a.openVulnerabilityCount > 0);
      return [...list].sort((a, b) => b.openVulnerabilityCount - a.openVulnerabilityCount);
    }
    return list;
  }, [detail, panel.type, panel.versionFilter]);

  const versionSuffix = panel.versionFilter ? ` @ ${panel.versionFilter}` : '';
  const title = panel.type === 'assets'
    ? `Assets — ${panel.identityName}${versionSuffix}`
    : `CVE Exposure — ${panel.identityName}${versionSuffix}`;
  const subtitle = panel.type === 'assets'
    ? `Enterprise assets running this software identity.${panel.versionFilter ? ` Filtered to version ${panel.versionFilter}.` : ''}`
    : `Assets with open CVE exposure.${panel.versionFilter ? ` Filtered to version ${panel.versionFilter}.` : ''}`;

  const cveColCount = panel.type === 'cves' ? COL_SPAN : COL_SPAN - 1;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel modal-panel-wide" onClick={e => e.stopPropagation()}>
        <div className="panel-header">
          <div>
            <h3>{title}</h3>
            <p className="panel-caption">{subtitle}</p>
          </div>
          <button
            type="button"
            className="modal-close-btn"
            aria-label="Close panel"
            onClick={onClose}
          >
            ×
          </button>
        </div>

        {detailQuery.isPending && !detail && (
          <div className="empty-state"><p>Loading…</p></div>
        )}

        {detail && (
          <div className="inventory-table-shell si-panel-table-shell">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Version</th>
                  <th>Type</th>
                  {panel.type === 'cves' && <th>Open CVEs</th>}
                  <th>Open Findings</th>
                  <th>EOL Status</th>
                  <th>EOL Date</th>
                </tr>
              </thead>
              <tbody>
                {assets.length === 0 ? (
                  <tr>
                    <td colSpan={cveColCount}>
                      <div className="empty-state">
                        <p>No {panel.type === 'cves' ? 'CVE exposure' : 'assets'} found
                          {panel.versionFilter ? ` for version ${panel.versionFilter}` : ''}.
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : assets.map(asset => (
                  <tr
                    key={asset.componentId}
                    className="inventory-table-row-clickable"
                    onClick={() => {
                      if ((asset.assetType ?? '').toUpperCase() === 'HOST') {
                        navigate(pathForInventoryHostAsset(asset.assetId, `${location.pathname}${location.search}`));
                        return;
                      }
                      navigate(pathForInventoryViewWithSearch(inventoryViewForAssetType(asset.assetType), {
                        query: asset.assetIdentifier || asset.assetName,
                        groupBy: ['sourceSystem', 'ecosystem']
                      }));
                    }}
                  >
                    <td>
                      <div className="inventory-primary-text">{asset.assetName}</div>
                      <div className="panel-caption mono">{asset.assetIdentifier}</div>
                    </td>
                    <td><span className="mono">{asset.version || '—'}</span></td>
                    <td>{asset.assetType || '—'}</td>
                    {panel.type === 'cves' && (
                      <td>
                        <span className="si-cve-count-pill">{asset.openVulnerabilityCount}</span>
                      </td>
                    )}
                    <td>{asset.openFindingCount}</td>
                    <td>
                      <EolBadge
                        isEol={asset.isEol}
                        daysRemaining={asset.eolDaysRemaining}
                        eolDate={asset.eolDate}
                      />
                    </td>
                    <td className="mono panel-caption">{formatDate(asset.eolDate)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Expanded version rows ─────────────────────────────────────────────────

type ExpandedVersionRowsProps = {
  identityId: string;
  vendor?: string;
  onAssetsClick: (version?: string) => void;
  onCvesClick: (version?: string) => void;
};

function ExpandedVersionRows({ identityId, vendor, onAssetsClick, onCvesClick }: ExpandedVersionRowsProps) {
  const detailQuery = useSoftwareIdentityDetailQuery(identityId, true);
  const detail = detailQuery.data;

  if (detailQuery.isPending && !detail) {
    return (
      <tr>
        <td colSpan={COL_SPAN} className="si-version-state-row">
          Loading versions…
        </td>
      </tr>
    );
  }

  if (!detail?.versions.length) {
    return (
      <tr>
        <td colSpan={COL_SPAN} className="si-version-state-row">
          No version data available.
        </td>
      </tr>
    );
  }

  return (
    <>
      {detail.versions.map((v, i) => (
        <tr key={`${v.version}-${i}`} className="si-version-row">
          <td>
            <span className="si-version-indent">↳</span>
          </td>
          <td>
            <span className="mono si-version-tag">{v.version || '(unknown)'}</span>
          </td>
          <td className="panel-caption">{vendor || '—'}</td>
          <td>
            {v.assetCount > 0 ? (
              <button
                type="button"
                className="si-count-link"
                onClick={e => { e.stopPropagation(); onAssetsClick(v.version); }}
              >
                {v.assetCount.toLocaleString()}
              </button>
            ) : (
              <span className="panel-caption">0</span>
            )}
          </td>
          <td>
            {v.openVulnerabilityCount > 0 ? (
              <button
                type="button"
                className="si-count-link si-count-link-cve"
                onClick={e => { e.stopPropagation(); onCvesClick(v.version); }}
              >
                {v.openVulnerabilityCount.toLocaleString()}
              </button>
            ) : (
              <span className="panel-caption">0</span>
            )}
          </td>
          <td>
            <FindingSeverityChips
              critical={v.criticalFindingCount}
              high={v.highFindingCount}
              other={Math.max(0, v.openFindingCount - v.criticalFindingCount - v.highFindingCount)}
            />
          </td>
          <td>
            <div className="si-eol-cell">
              <EolBadge isEol={v.isEol} daysRemaining={v.eolDaysRemaining} eolDate={v.eolDate} />
              <div className="si-eol-dates">
                {v.eolDate && (
                  <span className="panel-caption">
                    EOL: <span className="mono">{v.eolDate}</span>
                  </span>
                )}
                {v.supportEndDate && (
                  <span className="panel-caption">
                    EOS: <span className="mono">{v.supportEndDate}</span>
                  </span>
                )}
              </div>
            </div>
          </td>
        </tr>
      ))}
    </>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────

export function SoftwareIdentitiesPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialQuery = React.useMemo(() => readInventoryQueryFromSearch(searchParams), [searchParams]);
  const initialSourceSystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialEcosystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, INVENTORY_ECOSYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialLifecycle = React.useMemo(
    () => readSearchValueFromSearch(searchParams, SOFTWARE_LIFECYCLE_QUERY_KEY),
    [searchParams]
  );
  const initialMappingState = React.useMemo(
    () => readSearchValueFromSearch(searchParams, SOFTWARE_MAPPING_STATE_QUERY_KEY),
    [searchParams]
  );
  const initialCoverage = React.useMemo(
    () => readCoverageFromSearch(searchParams),
    [searchParams]
  );
  const initialOperatingSystem = React.useMemo(
    () => readSearchValueFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialGroupBy = React.useMemo(
    () => readInventoryGroupByFromSearch(searchParams),
    [searchParams]
  );
  const [query, setQuery] = React.useState(initialQuery);
  const [sourceSystems, setSourceSystems] = React.useState<string[]>(initialSourceSystems);
  const [ecosystems, setEcosystems] = React.useState<string[]>(initialEcosystems);
  const [lifecycle, setLifecycle] = React.useState(initialLifecycle);
  const [mappingState, setMappingState] = React.useState(initialMappingState);
  const [coverage, setCoverage] = React.useState<SoftwareIdentityCoverage | ''>(initialCoverage);
  const [operatingSystem, setOperatingSystem] = React.useState(initialOperatingSystem);
  const [groupBy, setGroupBy] = React.useState<string[]>(initialGroupBy);
  const [page, setPage] = React.useState(0);
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());
  const [activePanel, setActivePanel] = React.useState<ActivePanel>(null);

  const identitiesQuery = useSoftwareIdentitiesQuery({
    page,
    size: SOFTWARE_IDENTITIES_PAGE_SIZE,
    query: query.trim() || undefined,
    sourceSystem: sourceSystems.length > 0 ? sourceSystems : undefined,
    ecosystem: ecosystems.length > 0 ? ecosystems : undefined,
    lifecycle: lifecycle ? lifecycle as 'eol' | 'near-eol' | 'unknown' | 'supported' : undefined,
    mappingState: mappingState ? mappingState as 'needs-review' | 'mapped' | 'manual' | 'automatic' : undefined,
    coverage: coverage || undefined,
    operatingSystem: operatingSystem || undefined
  });
  const funnelQuery = useSoftwareIdentityFunnelQuery();

  const identities = React.useMemo(() => (
    (identitiesQuery.data?.content ?? [])
      .filter(identity => identity.assetCount > 0)
      .sort((a, b) => {
        if (b.openVulnerabilityCount !== a.openVulnerabilityCount) return b.openVulnerabilityCount - a.openVulnerabilityCount;
        if (b.assetCount !== a.assetCount) return b.assetCount - a.assetCount;
        return a.displayName.localeCompare(b.displayName);
      })
  ), [identitiesQuery.data?.content]);

  const totalIdentityCount = identitiesQuery.data?.totalElements ?? identities.length;
  const totalPages = identitiesQuery.data?.totalPages ?? 0;
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    identitiesQuery.dataUpdatedAt,
    funnelQuery.dataUpdatedAt
  ]), [
    funnelQuery.dataUpdatedAt,
    identitiesQuery.dataUpdatedAt
  ]);
  const currentSoftwareStats = React.useMemo(() => {
    const sourceValues = new Set<string>();
    let softwareRows = 0;
    let withCves = 0;
    identities.forEach((identity) => {
      softwareRows += identity.componentCount;
      if (identity.openVulnerabilityCount > 0) {
        withCves += 1;
      }
      identity.sourceSystems.forEach((value) => {
        const normalized = value?.trim();
        if (normalized) {
          sourceValues.add(normalized);
        }
      });
    });
    return {
      softwareRows,
      uniqueSoftware: totalIdentityCount,
      withCves,
      clean: Math.max(0, totalIdentityCount - withCves),
      sourceCount: sourceValues.size
    };
  }, [identities, totalIdentityCount]);
  const lifecycleBreakdown = React.useMemo(() => {
    const values = [
      { label: 'EOL', count: 0 },
      { label: 'Near EOL', count: 0 },
      { label: 'Unknown', count: 0 },
      { label: 'Supported', count: 0 }
    ];
    identities.forEach((identity) => {
      const lifecycleValue = identityLifecycle(identity);
      const entry = values.find((item) => item.label === lifecycleValue);
      if (entry) {
        entry.count += 1;
      }
    });
    return values;
  }, [identities]);
  const ecosystemBreakdown = React.useMemo(() => {
    const counts = new Map<string, { value: string; label: string; count: number }>();
    identities.forEach((identity) => {
      const values = identity.ecosystems.length > 0 ? identity.ecosystems : ['Unknown'];
      values.forEach((value) => {
        const normalized = value?.trim() || 'Unknown';
        const current = counts.get(normalized) ?? {
          value: normalized,
          label: formatInventoryLabel(normalized),
          count: 0
        };
        current.count += 1;
        counts.set(normalized, current);
      });
    });
    return Array.from(counts.values())
      .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
      .slice(0, 5);
  }, [identities]);
  const activeFilterChips = React.useMemo(() => {
    const chips: Array<{ key: string; label: string; onRemove: () => void }> = [];
    const trimmedQuery = query.trim();
    if (trimmedQuery) {
      chips.push({ key: 'search', label: `Search: ${trimmedQuery}`, onRemove: () => setQuery('') });
    }
    sourceSystems.forEach((value) => {
      chips.push({
        key: `source:${value}`,
        label: `Source: ${formatInventorySourceSystem(value)}`,
        onRemove: () => setSourceSystems((current) => current.filter((entry) => entry !== value))
      });
    });
    ecosystems.forEach((value) => {
      chips.push({
        key: `ecosystem:${value}`,
        label: `Ecosystem: ${formatInventoryLabel(value)}`,
        onRemove: () => setEcosystems((current) => current.filter((entry) => entry !== value))
      });
    });
    if (lifecycle) {
      const label = LIFECYCLE_OPTIONS.find((option) => option.value === lifecycle)?.label ?? lifecycle;
      chips.push({ key: 'lifecycle', label: `Lifecycle: ${label}`, onRemove: () => setLifecycle('') });
    }
    if (mappingState) {
      const label = MAPPING_STATE_OPTIONS.find((option) => option.value === mappingState)?.label ?? mappingState;
      chips.push({ key: 'mapping', label: `Mapping: ${label}`, onRemove: () => setMappingState('') });
    }
    if (coverage === 'with-vulnerabilities') {
      chips.push({ key: 'coverage', label: 'Coverage: Software with CVEs', onRemove: () => setCoverage('') });
    }
    if (operatingSystem) {
      chips.push({
        key: 'operating-system',
        label: `OS: ${operatingSystem}`,
        onRemove: () => setOperatingSystem('')
      });
    }
    return chips;
  }, [coverage, ecosystems, lifecycle, mappingState, operatingSystem, query, sourceSystems]);
  const groupedCards = React.useMemo(() => (
    groupBy
      .map((key) => {
        const option = SOFTWARE_GROUP_BY_OPTIONS.find((entry) => entry.key === key);
        if (!option) {
          return null;
        }
        const counts = new Map<string, number>();
        identities.forEach((identity) => {
          softwareIdentityGroupValues(identity, key).forEach((value) => {
            counts.set(value, (counts.get(value) ?? 0) + 1);
          });
        });
        return {
          key,
          label: option.label,
          items: Array.from(counts.entries())
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .slice(0, 5)
        };
      })
      .filter((entry): entry is { key: string; label: string; items: Array<[string, number]> } => entry != null)
  ), [groupBy, identities]);

  React.useEffect(() => {
    const nextQuery = readInventoryQueryFromSearch(searchParams);
    const nextSourceSystems = readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY);
    const nextEcosystems = readSearchValuesFromSearch(searchParams, INVENTORY_ECOSYSTEM_QUERY_KEY);
    const nextLifecycle = readSearchValueFromSearch(searchParams, SOFTWARE_LIFECYCLE_QUERY_KEY);
    const nextMappingState = readSearchValueFromSearch(searchParams, SOFTWARE_MAPPING_STATE_QUERY_KEY);
    const nextCoverage = readCoverageFromSearch(searchParams);
    const nextOperatingSystem = readSearchValueFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY);
    const nextGroupBy = readInventoryGroupByFromSearch(searchParams);

    setQuery((current) => (current === nextQuery ? current : nextQuery));
    setSourceSystems((current) => (sameValues(current, nextSourceSystems) ? current : nextSourceSystems));
    setEcosystems((current) => (sameValues(current, nextEcosystems) ? current : nextEcosystems));
    setLifecycle((current) => (current === nextLifecycle ? current : nextLifecycle));
    setMappingState((current) => (current === nextMappingState ? current : nextMappingState));
    setCoverage((current) => (current === nextCoverage ? current : nextCoverage));
    setOperatingSystem((current) => (current === nextOperatingSystem ? current : nextOperatingSystem));
    setGroupBy((current) => (sameValues(current, nextGroupBy) ? current : nextGroupBy));
  }, [searchParams]);

  React.useEffect(() => {
    let nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams = writeInventoryQueryToSearch(nextSearchParams, query);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY, sourceSystems);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, INVENTORY_ECOSYSTEM_QUERY_KEY, ecosystems);
    nextSearchParams = writeSearchValueToSearch(nextSearchParams, SOFTWARE_LIFECYCLE_QUERY_KEY, lifecycle);
    nextSearchParams = writeSearchValueToSearch(nextSearchParams, SOFTWARE_MAPPING_STATE_QUERY_KEY, mappingState);
    nextSearchParams = writeCoverageToSearch(nextSearchParams, coverage);
    nextSearchParams = writeSearchValueToSearch(nextSearchParams, HOST_OPERATING_SYSTEM_QUERY_KEY, operatingSystem);
    nextSearchParams = writeInventoryGroupByToSearch(nextSearchParams, groupBy);

    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [coverage, ecosystems, groupBy, lifecycle, mappingState, operatingSystem, query, searchParams, setSearchParams, sourceSystems]);

  React.useEffect(() => {
    setPage(0);
    setExpandedIds(new Set());
    setActivePanel(null);
  }, [query, sourceSystems, ecosystems, lifecycle, mappingState, coverage, operatingSystem]);

  React.useEffect(() => {
    setExpandedIds(new Set());
    setActivePanel(null);
  }, [page]);

  React.useEffect(() => {
    if (totalPages === 0) {
      if (page !== 0) {
        setPage(0);
      }
      return;
    }
    if (page >= totalPages) {
      setPage(totalPages - 1);
    }
  }, [page, totalPages]);

  const toggleExpand = (id: string) => {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const _openAssetsPanel = (identityId: string, identityName: string, versionFilter?: string) => {
    setActivePanel({ type: 'assets', identityId, identityName, versionFilter });
  };

  const openCvesPanel = (identityId: string, identityName: string, versionFilter?: string) => {
    setActivePanel({ type: 'cves', identityId, identityName, versionFilter });
  };

  const loading = identitiesQuery.isPending && identities.length === 0;
  const refreshing = (identitiesQuery.isFetching || funnelQuery.isFetching)
    && (identities.length > 0 || currentSoftwareStats.softwareRows > 0);
  const errorMessage = identitiesQuery.error instanceof Error ? identitiesQuery.error.message : null;
  const clearFilters = React.useCallback(() => {
    setQuery('');
    setSourceSystems([]);
    setEcosystems([]);
    setLifecycle('');
    setMappingState('');
    setCoverage('');
    setOperatingSystem('');
  }, []);
  const toggleCoverage = React.useCallback((nextCoverage: SoftwareIdentityCoverage) => {
    setCoverage((current) => current === nextCoverage || nextCoverage !== 'with-vulnerabilities' ? '' : nextCoverage);
  }, []);

  return (
    <InventoryShell
      eyebrow="Inventory"
      title="Software Identities"
      description="Distinct software products derived from inventory components, with deployment, coverage, and lifecycle posture."
      legacyClassName="inventory-page-shell"
    >
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshing}
        refreshLabel="Refreshing software identities while keeping current results visible…"
      />

      <div className="inventory-fpl-toolbar">
        <div className="findings-groupby-shell">
          <MultiGroupBy
            options={SOFTWARE_GROUP_BY_OPTIONS}
            value={groupBy}
            onChange={setGroupBy}
            label="GROUP BY"
            placeholder="No secondary grouping"
            allowEmptyPrimary
            emptyPrimaryLabel="None"
            showSelectorsByDefault={false}
          />
        </div>
        {activeFilterChips.length > 0 && (
          <div className="fpl-active-chips inventory-active-chips">
            {activeFilterChips.map((chip) => (
              <span key={chip.key} className="fpl-chip">
                {chip.label}
                <button type="button" onClick={chip.onRemove} aria-label={`Remove ${chip.label}`}>x</button>
              </span>
            ))}
            <button type="button" className="fpl-chip-clear" onClick={clearFilters}>
              Clear all
            </button>
          </div>
        )}
        <label className="findings-filter-chip inventory-fpl-search">
          <span className="panel-caption">Search software</span>
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="software, vendor, product..."
          />
        </label>
        <button
          type="button"
          className="btn btn-secondary inventory-refresh-btn"
          onClick={() => {
            void identitiesQuery.refetch();
            void funnelQuery.refetch();
          }}
          disabled={identitiesQuery.isFetching}
        >
          {identitiesQuery.isFetching ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      <div className="fpl-widgets">

        <WidgetCard title="Software Exposure" active={coverage === 'with-vulnerabilities'}>
          <div className="fpl-widget-donut-layout">
            <DonutChart
              size={90}
              sw={16}
              centerLabel="software"
              segs={[
                {
                  key: 'with-cves',
                  label: 'With CVEs',
                  value: currentSoftwareStats.withCves,
                  color: '#ef4444',
                  onClick: () => toggleCoverage('with-vulnerabilities')
                },
                {
                  key: 'clean',
                  label: 'Clean',
                  value: currentSoftwareStats.clean,
                  color: '#22c55e',
                  onClick: () => setCoverage('')
                }
              ]}
            />
            <div className="fpl-widget-legend">
              <div
                className={`fpl-legend-row${coverage === 'with-vulnerabilities' ? ' fpl-legend-row--active' : ''}`}
                onClick={() => toggleCoverage('with-vulnerabilities')}
              >
                <span className="fpl-legend-dot" style={{ background: '#ef4444' }} />
                <span className="fpl-legend-label">With CVEs</span>
                <strong className="fpl-legend-val">{currentSoftwareStats.withCves.toLocaleString()}</strong>
              </div>
              <div className="fpl-legend-row" onClick={() => setCoverage('')}>
                <span className="fpl-legend-dot" style={{ background: '#22c55e' }} />
                <span className="fpl-legend-label">Clean</span>
                <strong className="fpl-legend-val">{currentSoftwareStats.clean.toLocaleString()}</strong>
              </div>
            </div>
          </div>
        </WidgetCard>

        <WidgetCard title="Lifecycle Status" active={!!lifecycle}>
          <HBarChart
            activeKey={lifecycle ? (
              lifecycle === 'eol' ? 'EOL' :
                lifecycle === 'near-eol' ? 'Near EOL' :
                  lifecycle === 'unknown' ? 'Unknown' : 'Supported'
            ) : undefined}
            items={[
              { key: 'EOL',       label: 'EOL',       value: lifecycleBreakdown.find(b => b.label === 'EOL')?.count ?? 0,       color: '#f97316', onClick: () => setLifecycle('eol') },
              { key: 'Near EOL',  label: 'Near EOL',  value: lifecycleBreakdown.find(b => b.label === 'Near EOL')?.count ?? 0,  color: '#facc15', onClick: () => setLifecycle('near-eol') },
              { key: 'Unknown',   label: 'Unknown',   value: lifecycleBreakdown.find(b => b.label === 'Unknown')?.count ?? 0,   color: '#9ca3af', onClick: () => setLifecycle('unknown') },
              { key: 'Supported', label: 'Supported', value: lifecycleBreakdown.find(b => b.label === 'Supported')?.count ?? 0, color: '#22c55e', onClick: () => setLifecycle('supported') }
            ]}
          />
        </WidgetCard>

        <WidgetCard title="Ecosystems" active={ecosystems.length > 0}>
          {ecosystemBreakdown.length === 0 ? (
            <div className="fpl-widget-empty">No ecosystems in this view</div>
          ) : (
            <HBarChart
              activeKey={ecosystems.length === 1 ? ecosystems[0] : undefined}
              items={ecosystemBreakdown.map((item, i) => ({
                key: item.value,
                label: item.label.length > 18 ? item.label.slice(0, 16) + '…' : item.label,
                value: item.count,
                color: ['#6366f1', '#8b5cf6', '#a78bfa', '#c4b5fd', '#ddd6fe'][i] ?? '#6366f1',
                onClick: () => setEcosystems(item.value === 'Unknown' ? [] : [item.value])
              }))}
            />
          )}
        </WidgetCard>

        <WidgetCard title="Software Indicators">
          <div className="fpl-kpi-grid">
            {[
              {
                label: 'Software Rows',
                value: currentSoftwareStats.softwareRows,
                color: '#3b82f6',
                onClick: () => clearFilters()
              },
              {
                label: 'Unique Software',
                value: currentSoftwareStats.uniqueSoftware,
                color: '#6366f1',
                onClick: () => clearFilters()
              },
              {
                label: 'With CVEs',
                value: currentSoftwareStats.withCves,
                color: '#ef4444',
                onClick: () => toggleCoverage('with-vulnerabilities')
              },
              {
                label: 'Sources',
                value: currentSoftwareStats.sourceCount,
                color: '#22c55e'
              }
            ].map((kpi) => (
              <div
                key={kpi.label}
                className="fpl-kpi-card"
                onClick={kpi.onClick}
                style={{ '--kpi-color': kpi.color } as React.CSSProperties}
              >
                <div className="fpl-kpi-num">{kpi.value.toLocaleString()}</div>
                <div className="fpl-kpi-label">{kpi.label}</div>
              </div>
            ))}
          </div>
        </WidgetCard>

      </div>

      {errorMessage && (
        <div className="inventory-error-banner">
          Failed to load software identities: {errorMessage}
        </div>
      )}

      {groupedCards.length > 0 && (
        <section className="inventory-section-card">
          <div className="inventory-section-header findings-title-row">
            <div>
              <h2>Grouped Breakdown</h2>
              <p className="panel-caption">Top values in the current filtered software identity result set.</p>
            </div>
          </div>
          <div className="findings-widget-grid">
            {groupedCards.map((group) => (
              <div className="findings-widget-card" key={group.key}>
                <div className="findings-widget-title">{group.label}</div>
                <div className="findings-widget-list">
                  {group.items.length === 0 ? (
                    <div className="panel-caption">No rows in the current result set.</div>
                  ) : (
                    group.items.map(([value, count]) => (
                      <div className="findings-widget-row" key={`${group.key}:${value}`}>
                        <span>{value}</span>
                        <strong>{count.toLocaleString()}</strong>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="inventory-section-card">
        <div className="inventory-section-header">
          <div>
            <h2>Deployed software identities</h2>
            <p className="panel-caption">
              Click a row to expand version-level breakdown with EOL and CVE exposure.
            </p>
          </div>
          <span className="panel-caption">{totalIdentityCount.toLocaleString()} identities</span>
        </div>

        {loading ? (
          <div className="empty-state"><p>Loading software identities…</p></div>
        ) : (
          <div className="inventory-table-shell">
            <table className="inventory-table si-identities-table">
              <thead>
                <tr>
                  <th>Software</th>
                  <th>Version</th>
                  <th>Vendor</th>
                  <th>Assets</th>
                  <th>CVEs</th>
                  <th>Open Findings</th>
                  <th>EOL</th>
                </tr>
              </thead>
              <tbody>
                {identities.length === 0 ? (
                  <tr>
                    <td colSpan={COL_SPAN}>
                      <div className="empty-state">
                        <p>No deployed software identities matched the current search.</p>
                      </div>
                    </td>
                  </tr>
                ) : identities.map(identity => {
                  const isExpanded = expandedIds.has(identity.id);
                  return (
                    <React.Fragment key={identity.id}>
                      <tr
                        className={`inventory-table-row-clickable si-identity-row${isExpanded ? ' si-identity-row-expanded' : ''}`}
                        onClick={() => toggleExpand(identity.id)}
                      >
                        <td>
                          <div className="si-identity-name-cell">
                            <span className={`si-expand-toggle${isExpanded ? ' si-expand-toggle-open' : ''}`}>▶</span>
                            <button
                              type="button"
                              className="btn-link inventory-primary-text"
                              onClick={(event) => {
                                event.stopPropagation();
                                navigate(pathForSoftwareIdentityDetail(identity.id));
                              }}
                            >
                              {identity.displayName}
                            </button>
                          </div>
                        </td>
                        <td>
                          <span className="si-version-count">
                            {identity.versionCount.toLocaleString()} version{identity.versionCount !== 1 ? 's' : ''}
                          </span>
                        </td>
                        <td>{identity.vendor || identity.product || '—'}</td>
                        <td>
                          {identity.assetCount > 0 ? (
                            <button
                              type="button"
                              className="si-count-link"
                              onClick={e => {
                                e.stopPropagation();
                                const primaryType = identity.assetTypes.find(t => t.toUpperCase() === 'HOST') ?? identity.assetTypes[0] ?? 'HOST';
                                const view = inventoryViewForAssetType(primaryType);
                                const groupBy = view === 'hosts'
                                  ? ['operatingSystem', 'environment']
                                  : ['sourceSystem', 'ecosystem'];
                                navigate(pathForInventoryViewWithSearch(view, { query: identity.displayName, groupBy }));
                              }}
                            >
                              {identity.assetCount.toLocaleString()}
                            </button>
                          ) : (
                            <span className="panel-caption">0</span>
                          )}
                        </td>
                        <td>
                          {identity.openVulnerabilityCount > 0 ? (
                            <button
                              type="button"
                              className="si-count-link si-count-link-cve"
                              onClick={e => {
                                e.stopPropagation();
                                openCvesPanel(identity.id, identity.displayName);
                              }}
                            >
                              {identity.openVulnerabilityCount.toLocaleString()}
                            </button>
                          ) : (
                            <span className="panel-caption">0</span>
                          )}
                        </td>
                        <td>
                          <FindingSeverityChips
                            critical={identity.criticalFindingCount}
                            high={identity.highFindingCount}
                            other={Math.max(0, identity.openFindingCount - identity.criticalFindingCount - identity.highFindingCount)}
                          />
                        </td>
                        <td>
                          <span className={eolSummaryClass(identity)}>
                            {eolSummaryLabel(identity)}
                          </span>
                        </td>
                      </tr>

                      {isExpanded && (
                        <ExpandedVersionRows
                          identityId={identity.id}
                          vendor={identity.vendor || identity.product}
                          onAssetsClick={() => {
                            const primaryType = identity.assetTypes.find(t => t.toUpperCase() === 'HOST') ?? identity.assetTypes[0] ?? 'HOST';
                            const view = inventoryViewForAssetType(primaryType);
                            const groupBy = view === 'hosts'
                              ? ['operatingSystem', 'environment']
                              : ['sourceSystem', 'ecosystem'];
                            navigate(pathForInventoryViewWithSearch(view, { query: identity.displayName, groupBy }));
                          }}
                          onCvesClick={vf => openCvesPanel(identity.id, identity.displayName, vf)}
                        />
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {totalPages > 1 && (
          <div className="pagination-row">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setPage((current) => Math.max(0, current - 1))}
              disabled={page === 0 || identitiesQuery.isFetching}
            >
              Previous
            </button>
            <span className="panel-caption pagination-caption">
              {`Page ${page + 1} of ${totalPages}`}
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setPage((current) => (current + 1 < totalPages ? current + 1 : current))}
              disabled={identitiesQuery.isFetching || page + 1 >= totalPages}
            >
              Next
            </button>
          </div>
        )}
      </div>

      {activePanel && (
        <EntityListPanel
          panel={activePanel}
          onClose={() => setActivePanel(null)}
        />
      )}
    </InventoryShell>
  );
}
