import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { MultiGroupBy, type MultiGroupByOption } from '../components/MultiGroupBy';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { api } from '../api/client';
import { FindingSeverityChips } from '../features/findings/components/FindingSeverityChips';
import { pathForInventoryHostAsset, pathForConnectView } from '../app/routes';
import type { Asset, HostAssetDetail } from '../features/inventory/api-types';
import { formatInventorySourceSystem } from '../features/inventory/helpers';
import { InventoryShell } from '../features/inventory/InventoryShell';
import {
  HOST_ENVIRONMENT_QUERY_KEY,
  HOST_OPERATING_SYSTEM_QUERY_KEY,
  HOST_QUICK_FILTER_QUERY_KEY,
  INVENTORY_SOURCE_SYSTEM_QUERY_KEY,
  readInventoryGroupByFromSearch,
  readInventoryQueryFromSearch,
  readSearchValueFromSearch,
  readSearchValuesFromSearch,
  writeInventoryGroupByToSearch,
  writeInventoryQueryToSearch,
  writeSearchValueToSearch,
  writeSearchValuesToSearch
} from '../features/inventory/searchState';
import type { InventoryViewKey } from '../features/inventory/types';

const PAGE_SIZE = 50;

type Props = {
  selectedView: InventoryViewKey;
};

type HostInventoryRecord = {
  asset: Asset;
  detail: HostAssetDetail;
  operatingSystem: string;
  deployedSoftwareCount: number;
  eolSoftwareCount: number;
  openFindingCount: number;
  criticalFindingCount: number;
  highFindingCount: number;
  applicableCveCount: number;
  isOnline: boolean;
};

type HostOsSummary = {
  os: string;
  hostCount: number;
  activeCount: number;
  totalApplicableCves: number;
  totalOpenFindings: number;
  totalSoftware: number;
};

type HostQuickFilter = 'all' | 'online' | 'with-findings' | 'with-cves' | 'with-eol' | 'external-with-cves' | 'linux' | 'windows';
const HOST_GROUP_BY_OPTIONS: MultiGroupByOption[] = [
  { key: 'operatingSystem', label: 'Operating System' },
  { key: 'environment', label: 'Environment' },
  { key: 'status', label: 'Status' },
  { key: 'owner', label: 'Owner' },
  { key: 'sourceSystem', label: 'Source System' }
];

const OS_MATCHERS: Array<{ label: string; test: (value: string) => boolean }> = [
  { label: 'Windows Server 2022', test: (value) => value.includes('windows server 2022') },
  { label: 'Windows Server 2019', test: (value) => value.includes('windows server 2019') },
  { label: 'Windows', test: (value) => value.includes('windows') },
  { label: 'Ubuntu 24.04', test: (value) => value.includes('ubuntu 24.04') },
  { label: 'Ubuntu 22.04', test: (value) => value.includes('ubuntu 22.04') },
  { label: 'Ubuntu 20.04', test: (value) => value.includes('ubuntu 20.04') },
  { label: 'Ubuntu', test: (value) => value.includes('ubuntu') },
  { label: 'Debian 12', test: (value) => value.includes('debian 12') },
  { label: 'Debian 11', test: (value) => value.includes('debian 11') },
  { label: 'Debian 10', test: (value) => value.includes('debian 10') },
  { label: 'Debian', test: (value) => value.includes('debian') },
  { label: 'Amazon Linux 2023', test: (value) => value.includes('amazon linux 2023') },
  { label: 'Amazon Linux 2', test: (value) => value.includes('amazon linux 2') },
  { label: 'Amazon Linux', test: (value) => value.includes('amazon linux') },
  { label: 'RHEL', test: (value) => value.includes('red hat') || value.includes('rhel') },
  { label: 'CentOS', test: (value) => value.includes('centos') },
  { label: 'Rocky Linux', test: (value) => value.includes('rocky') },
  { label: 'AlmaLinux', test: (value) => value.includes('alma') },
  { label: 'SUSE Linux', test: (value) => value.includes('suse') },
  { label: 'macOS', test: (value) => value.includes('mac os') || value.includes('macos') || value.includes('os x') },
  { label: 'Linux', test: (value) => value.includes('linux') }
];

function formatTimestamp(value?: string): string {
  if (!value) {
    return '-';
  }
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatHostState(value?: string): string {
  if (!value) {
    return 'Unknown';
  }
  return value
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
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

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function hostEnvironment(record: HostInventoryRecord): string {
  return record.detail.host.environment ?? record.asset.environment ?? 'Unknown';
}

function hostOwner(record: HostInventoryRecord): string {
  return record.detail.host.ownerEmail ?? record.asset.ownerTeam ?? record.asset.ownerEmail ?? 'Unassigned';
}

function hostSourceSystems(record: HostInventoryRecord): string[] {
  return Array.from(new Set(
    record.detail.software
      .map((software) => software.sourceSystem?.trim())
      .filter((value): value is string => Boolean(value))
  ));
}

function hostGroupValues(record: HostInventoryRecord, key: string): string[] {
  if (key === 'operatingSystem') {
    return [record.operatingSystem];
  }
  if (key === 'environment') {
    return [hostEnvironment(record)];
  }
  if (key === 'status') {
    return [record.isOnline ? 'Online' : formatHostState(record.detail.host.state)];
  }
  if (key === 'owner') {
    return [hostOwner(record)];
  }
  if (key === 'sourceSystem') {
    const values = hostSourceSystems(record);
    return values.length > 0
      ? values.map((value) => formatInventorySourceSystem(value))
      : ['Unspecified source'];
  }
  return ['Unknown'];
}

function toInventoryRecord(asset: Asset, detail: HostAssetDetail): HostInventoryRecord {
  const openFindings = detail.findings.filter((finding) => (finding.status ?? '').toUpperCase() !== 'RESOLVED');
  const isOnline = (detail.host.state ?? asset.state ?? '').toUpperCase() === 'ACTIVE';
  return {
    asset,
    detail,
    operatingSystem: inferOperatingSystem(detail),
    deployedSoftwareCount: detail.software.length,
    eolSoftwareCount: detail.software.filter((software) => software.isEol === true).length,
    openFindingCount: openFindings.length,
    criticalFindingCount: openFindings.filter((finding) => (finding.severity ?? '').toUpperCase() === 'CRITICAL').length,
    highFindingCount: openFindings.filter((finding) => (finding.severity ?? '').toUpperCase() === 'HIGH').length,
    applicableCveCount: detail.applicableCves.length,
    isOnline
  };
}

function isExternalFacingHost(record: HostInventoryRecord): boolean {
  const searchable = [
    record.asset.name,
    record.asset.identifier,
    record.asset.serviceName,
    record.asset.environment,
    record.asset.businessCriticality,
    record.detail.host.environment,
    record.detail.host.supportGroup
  ].join(' ').toLowerCase();
  return /\b(external|internet|public|dmz|edge|web)\b/.test(searchable);
}

function buildOsSummary(records: HostInventoryRecord[]): HostOsSummary[] {
  const grouped = new Map<string, HostOsSummary>();

  records.forEach((record) => {
    const current = grouped.get(record.operatingSystem) ?? {
      os: record.operatingSystem,
      hostCount: 0,
      activeCount: 0,
      totalApplicableCves: 0,
      totalOpenFindings: 0,
      totalSoftware: 0
    };

    current.hostCount += 1;
    current.activeCount += record.isOnline ? 1 : 0;
    current.totalApplicableCves += record.applicableCveCount;
    current.totalOpenFindings += record.openFindingCount;
    current.totalSoftware += record.deployedSoftwareCount;
    grouped.set(record.operatingSystem, current);
  });

  return Array.from(grouped.values()).sort((left, right) => {
    if (right.hostCount !== left.hostCount) {
      return right.hostCount - left.hostCount;
    }
    return left.os.localeCompare(right.os);
  });
}

function matchesQuickFilter(record: HostInventoryRecord, filter: HostQuickFilter): boolean {
  switch (filter) {
    case 'online':
      return record.isOnline;
    case 'with-findings':
      return record.openFindingCount > 0;
    case 'with-cves':
      return record.applicableCveCount > 0;
    case 'with-eol':
      return record.eolSoftwareCount > 0;
    case 'external-with-cves':
      return isExternalFacingHost(record) && record.applicableCveCount > 0;
    case 'linux':
      return record.operatingSystem.toLowerCase().includes('linux')
        || record.operatingSystem.toLowerCase().includes('ubuntu')
        || record.operatingSystem.toLowerCase().includes('debian')
        || record.operatingSystem.toLowerCase().includes('rhel')
        || record.operatingSystem.toLowerCase().includes('centos')
        || record.operatingSystem.toLowerCase().includes('amazon linux');
    case 'windows':
      return record.operatingSystem.toLowerCase().includes('windows');
    case 'all':
    default:
      return true;
  }
}

function matchesSearch(record: HostInventoryRecord, query: string): boolean {
  if (!query) {
    return true;
  }
  const normalizedQuery = query.toLowerCase();
  const haystack = [
    record.asset.name,
    record.asset.identifier,
    record.detail.host.environment ?? record.asset.environment,
    record.asset.ownerTeam,
    record.detail.host.ownerEmail ?? record.asset.ownerEmail,
    record.detail.host.supportGroup,
    record.operatingSystem,
    ...record.detail.software.map((software) => software.displayName),
    ...record.detail.software.map((software) => software.publisher ?? ''),
    ...record.detail.software.map((software) => software.discoveryModelPrimaryKey ?? ''),
    ...record.detail.software.map((software) => software.softwareIdentity ?? '')
  ]
    .join(' ')
    .toLowerCase();

  return haystack.includes(normalizedQuery);
}

function HostRow({
  record,
  onOpen
}: {
  record: HostInventoryRecord;
  onOpen: (assetId: string) => void;
}) {
  return (
    <tr className="inventory-table-row-clickable" onClick={() => onOpen(record.asset.id)}>
      <td>
        <button
          type="button"
          className="inventory-link-button inventory-link-button-primary"
          onClick={(event) => {
            event.stopPropagation();
            onOpen(record.asset.id);
          }}
        >
          {record.asset.name}
        </button>
        <div className="panel-caption mono">{record.asset.identifier}</div>
      </td>
      <td>{record.detail.host.environment ?? record.asset.environment ?? '-'}</td>
      <td>{record.operatingSystem}</td>
      <td>
        {record.detail.host.ownerEmail ?? record.asset.ownerTeam ?? record.asset.ownerEmail ?? '-'}
      </td>
      <td>{record.detail.host.supportGroup ?? '-'}</td>
      <td>{record.deployedSoftwareCount.toLocaleString()}</td>
      <td>{record.applicableCveCount.toLocaleString()}</td>
      <td>
        <FindingSeverityChips
          critical={record.criticalFindingCount}
          high={record.highFindingCount}
          other={Math.max(0, record.openFindingCount - record.criticalFindingCount - record.highFindingCount)}
        />
      </td>
      <td>
        <span className={`status-pill ${record.isOnline ? 'status-active' : 'status-inactive'}`}>
          {record.isOnline ? 'Online' : formatHostState(record.detail.host.state)}
        </span>
      </td>
      <td>{formatTimestamp(record.detail.host.lastInventoryAt ?? record.detail.host.lastCmdbSyncAt)}</td>
    </tr>
  );
}

export function InventoryPage(_: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const initialSearchValue = React.useMemo(() => readInventoryQueryFromSearch(searchParams), [searchParams]);
  const initialQuickFilter = React.useMemo<HostQuickFilter>(() => {
    const value = readSearchValueFromSearch(searchParams, HOST_QUICK_FILTER_QUERY_KEY);
    return value === 'online'
      || value === 'with-findings'
      || value === 'with-cves'
      || value === 'with-eol'
      || value === 'external-with-cves'
      || value === 'linux'
      || value === 'windows'
      ? value
      : 'all';
  }, [searchParams]);
  const initialEnvironments = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, HOST_ENVIRONMENT_QUERY_KEY),
    [searchParams]
  );
  const initialOperatingSystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialSourceSystems = React.useMemo(
    () => readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY),
    [searchParams]
  );
  const initialGroupBy = React.useMemo(
    () => readInventoryGroupByFromSearch(searchParams),
    [searchParams]
  );
  const [searchValue, setSearchValue] = React.useState(initialSearchValue);
  const [quickFilter, setQuickFilter] = React.useState<HostQuickFilter>(initialQuickFilter);
  const [selectedEnvironments, setSelectedEnvironments] = React.useState<string[]>(initialEnvironments);
  const [selectedOperatingSystems, setSelectedOperatingSystems] = React.useState<string[]>(initialOperatingSystems);
  const [selectedSourceSystems, setSelectedSourceSystems] = React.useState<string[]>(initialSourceSystems);
  const [groupBy, setGroupBy] = React.useState<string[]>(initialGroupBy);
  const [page, setPage] = React.useState(0);

  const assetsQuery = useQuery({
    queryKey: ['inventory-host-assets'],
    queryFn: api.listAssets
  });

  const hostAssets = React.useMemo(
    () => (assetsQuery.data ?? []).filter((asset) => asset.type.toUpperCase() === 'HOST'),
    [assetsQuery.data]
  );

  const hostDetailsQuery = useQuery({
    queryKey: ['inventory-host-assets-detail', hostAssets.map((asset) => asset.id)],
    queryFn: async () => {
      const results = await Promise.allSettled(
        hostAssets.map(async (asset) => ({
          asset,
          detail: await api.getHostAssetDetail(asset.id)
        }))
      );
      return results
        .filter((r): r is PromiseFulfilledResult<{ asset: Asset; detail: HostAssetDetail }> => r.status === 'fulfilled')
        .map((r) => r.value);
    },
    enabled: hostAssets.length > 0
  });

  const hostRecords = React.useMemo<HostInventoryRecord[]>(() => (
    (hostDetailsQuery.data ?? []).map(({ asset, detail }) => toInventoryRecord(asset, detail))
      .sort((left, right) => left.asset.name.localeCompare(right.asset.name))
  ), [hostDetailsQuery.data]);

  React.useEffect(() => {
    const nextSearchValue = readInventoryQueryFromSearch(searchParams);
    const nextQuickFilterValue = readSearchValueFromSearch(searchParams, HOST_QUICK_FILTER_QUERY_KEY);
    const nextQuickFilter = nextQuickFilterValue === 'online'
      || nextQuickFilterValue === 'with-findings'
      || nextQuickFilterValue === 'with-cves'
      || nextQuickFilterValue === 'with-eol'
      || nextQuickFilterValue === 'external-with-cves'
      || nextQuickFilterValue === 'linux'
      || nextQuickFilterValue === 'windows'
      ? nextQuickFilterValue
      : 'all';
    const nextEnvironments = readSearchValuesFromSearch(searchParams, HOST_ENVIRONMENT_QUERY_KEY);
    const nextOperatingSystems = readSearchValuesFromSearch(searchParams, HOST_OPERATING_SYSTEM_QUERY_KEY);
    const nextSourceSystems = readSearchValuesFromSearch(searchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY);
    const nextGroupBy = readInventoryGroupByFromSearch(searchParams);

    setSearchValue((current) => (current === nextSearchValue ? current : nextSearchValue));
    setQuickFilter((current) => (current === nextQuickFilter ? current : nextQuickFilter));
    setSelectedEnvironments((current) => (sameValues(current, nextEnvironments) ? current : nextEnvironments));
    setSelectedOperatingSystems((current) => (sameValues(current, nextOperatingSystems) ? current : nextOperatingSystems));
    setSelectedSourceSystems((current) => (sameValues(current, nextSourceSystems) ? current : nextSourceSystems));
    setGroupBy((current) => (sameValues(current, nextGroupBy) ? current : nextGroupBy));
  }, [searchParams]);

  React.useEffect(() => {
    let nextSearchParams = new URLSearchParams(searchParams);
    nextSearchParams = writeInventoryQueryToSearch(nextSearchParams, searchValue);
    nextSearchParams = writeSearchValueToSearch(nextSearchParams, HOST_QUICK_FILTER_QUERY_KEY, quickFilter === 'all' ? '' : quickFilter);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, HOST_ENVIRONMENT_QUERY_KEY, selectedEnvironments);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, HOST_OPERATING_SYSTEM_QUERY_KEY, selectedOperatingSystems);
    nextSearchParams = writeSearchValuesToSearch(nextSearchParams, INVENTORY_SOURCE_SYSTEM_QUERY_KEY, selectedSourceSystems);
    nextSearchParams = writeInventoryGroupByToSearch(nextSearchParams, groupBy);

    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [
    groupBy,
    quickFilter,
    searchParams,
    searchValue,
    selectedEnvironments,
    selectedOperatingSystems,
    selectedSourceSystems,
    setSearchParams
  ]);

  const filteredRecords = React.useMemo(
    () => hostRecords.filter((record) => {
      if (!matchesQuickFilter(record, quickFilter) || !matchesSearch(record, searchValue.trim())) {
        return false;
      }
      if (selectedEnvironments.length > 0 && !selectedEnvironments.includes(hostEnvironment(record))) {
        return false;
      }
      if (selectedOperatingSystems.length > 0 && !selectedOperatingSystems.includes(record.operatingSystem)) {
        return false;
      }
      if (selectedSourceSystems.length > 0) {
        const sources = hostSourceSystems(record);
        if (!selectedSourceSystems.some((value) => sources.includes(value))) {
          return false;
        }
      }
      return true;
    }),
    [
      hostRecords,
      quickFilter,
      searchValue,
      selectedEnvironments,
      selectedOperatingSystems,
      selectedSourceSystems
    ]
  );

  React.useEffect(() => {
    setPage(0);
  }, [quickFilter, searchValue, selectedEnvironments, selectedOperatingSystems, selectedSourceSystems]);

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / PAGE_SIZE));
  const paginatedRecords = React.useMemo(
    () => filteredRecords.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [filteredRecords, page]
  );

  const osSummaries = React.useMemo(() => buildOsSummary(filteredRecords), [filteredRecords]);
  const groupedCards = React.useMemo(() => (
    groupBy
      .map((key) => {
        const option = HOST_GROUP_BY_OPTIONS.find((entry) => entry.key === key);
        if (!option) {
          return null;
        }
        const counts = new Map<string, number>();
        filteredRecords.forEach((record) => {
          hostGroupValues(record, key).forEach((value) => {
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
  ), [filteredRecords, groupBy]);

  const totalSoftware = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.deployedSoftwareCount, 0),
    [filteredRecords]
  );

  const totalCves = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.applicableCveCount, 0),
    [filteredRecords]
  );

  const totalFindings = React.useMemo(
    () => filteredRecords.reduce((sum, record) => sum + record.openFindingCount, 0),
    [filteredRecords]
  );

  const onlineHosts = React.useMemo(
    () => filteredRecords.filter((record) => record.isOnline).length,
    [filteredRecords]
  );
  const assetsWithExposure = React.useMemo(
    () => filteredRecords.filter((record) => record.openFindingCount > 0 || record.applicableCveCount > 0).length,
    [filteredRecords]
  );
  const topOperatingSystems = React.useMemo(
    () => osSummaries.slice(0, 5),
    [osSummaries]
  );
  const statusBreakdown = React.useMemo(() => {
    const online = filteredRecords.filter((record) => record.isOnline).length;
    return [
      { label: 'Online', count: online, tone: 'success' },
      { label: 'Offline / inactive', count: Math.max(0, filteredRecords.length - online), tone: 'muted' },
      { label: 'With findings', count: filteredRecords.filter((record) => record.openFindingCount > 0).length, tone: 'warning' },
      { label: 'With CVEs', count: filteredRecords.filter((record) => record.applicableCveCount > 0).length, tone: 'accent' }
    ];
  }, [filteredRecords]);
  const topRiskAssets = React.useMemo(
    () => [...filteredRecords]
      .sort((left, right) => (
        right.openFindingCount - left.openFindingCount
        || right.applicableCveCount - left.applicableCveCount
        || right.deployedSoftwareCount - left.deployedSoftwareCount
        || left.asset.name.localeCompare(right.asset.name)
      ))
      .slice(0, 5),
    [filteredRecords]
  );
  const inventoryHealth = React.useMemo(() => {
    const noSoftware = filteredRecords.filter((record) => record.deployedSoftwareCount === 0).length;
    const unknownOs = filteredRecords.filter((record) => record.operatingSystem === 'Unknown').length;
    const missingOwner = filteredRecords.filter((record) => hostOwner(record) === 'Unassigned').length;
    const highExposure = filteredRecords.filter((record) => record.applicableCveCount > 0 || record.openFindingCount > 0).length;
    return [
      { label: 'No software', count: noSoftware, tone: 'muted' },
      { label: 'Unknown OS', count: unknownOs, tone: 'warning' },
      { label: 'Missing owner', count: missingOwner, tone: 'warning' },
      { label: 'Exposed', count: highExposure, tone: 'accent' }
    ];
  }, [filteredRecords]);
  const osMax = React.useMemo(
    () => Math.max(1, ...topOperatingSystems.map((item) => item.hostCount)),
    [topOperatingSystems]
  );
  const statusMax = React.useMemo(
    () => Math.max(1, ...statusBreakdown.map((item) => item.count)),
    [statusBreakdown]
  );
  const activeFilterChips = React.useMemo<Array<{ key: string; label: string; onRemove: () => void }>>(() => {
    const chips: Array<{ key: string; label: string; onRemove: () => void }> = [];
    if (quickFilter !== 'all') {
      const quickFilterLabels: Record<Exclude<HostQuickFilter, 'all'>, string> = {
        online: 'Online',
        'with-findings': 'Assets with findings',
        'with-cves': 'Assets with CVE exposure',
        'with-eol': 'Assets with EOL software',
        'external-with-cves': 'External facing with CVEs',
        linux: 'Linux',
        windows: 'Windows'
      };
      chips.push({
        key: 'quick',
        label: `View: ${quickFilterLabels[quickFilter]}`,
        onRemove: () => setQuickFilter('all')
      });
    }
    if (searchValue.trim()) {
      chips.push({
        key: 'search',
        label: `Search: ${searchValue.trim()}`,
        onRemove: () => setSearchValue('')
      });
    }
    selectedEnvironments.forEach((value) => chips.push({
      key: `environment:${value}`,
      label: `Environment: ${value}`,
      onRemove: () => setSelectedEnvironments((current) => current.filter((entry) => entry !== value))
    }));
    selectedOperatingSystems.forEach((value) => chips.push({
      key: `os:${value}`,
      label: `OS: ${value}`,
      onRemove: () => setSelectedOperatingSystems((current) => current.filter((entry) => entry !== value))
    }));
    selectedSourceSystems.forEach((value) => chips.push({
      key: `source:${value}`,
      label: `Source: ${formatInventorySourceSystem(value)}`,
      onRemove: () => setSelectedSourceSystems((current) => current.filter((entry) => entry !== value))
    }));
    return chips;
  }, [quickFilter, searchValue, selectedEnvironments, selectedOperatingSystems, selectedSourceSystems]);

  const loading = assetsQuery.isPending || hostDetailsQuery.isPending;
  const refreshing = (assetsQuery.isFetching || hostDetailsQuery.isFetching) && hostRecords.length > 0;
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    assetsQuery.dataUpdatedAt,
    hostDetailsQuery.dataUpdatedAt
  ]), [
    assetsQuery.dataUpdatedAt,
    hostDetailsQuery.dataUpdatedAt
  ]);
  const errorMessage = assetsQuery.error instanceof Error
    ? assetsQuery.error.message
    : hostDetailsQuery.error instanceof Error
      ? hostDetailsQuery.error.message
      : null;

  const handleOpenHost = React.useCallback((assetId: string) => {
    navigate(pathForInventoryHostAsset(assetId, `${location.pathname}${location.search}`));
  }, [location.pathname, location.search, navigate]);
  const clearFilters = React.useCallback(() => {
    setSearchValue('');
    setQuickFilter('all');
    setSelectedEnvironments([]);
    setSelectedOperatingSystems([]);
    setSelectedSourceSystems([]);
  }, []);

  return (
    <InventoryShell
      eyebrow="Inventory"
      title="Hosts"
      description="Discovered hosts, their installed software, and current exposure."
      legacyClassName="inventory-page-shell"
    >
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshing}
        refreshLabel="Refreshing host inventory while keeping current results visible…"
      />

      <div className="inventory-fpl-toolbar">
        <div className="findings-groupby-shell">
          <MultiGroupBy
            options={HOST_GROUP_BY_OPTIONS}
            value={groupBy}
            onChange={setGroupBy}
            label="GROUP BY"
            placeholder="No secondary grouping"
            allowEmptyPrimary
            emptyPrimaryLabel="None"
            showSelectorsByDefault={false}
          />
        </div>
        {activeFilterChips.length > 0 ? (
          <div className="fpl-active-chips inventory-active-chips">
            {activeFilterChips.map((chip) => (
              <span key={chip.key} className="fpl-chip">
                {chip.label}
                <button type="button" onClick={chip.onRemove} aria-label={`Remove ${chip.label}`}>x</button>
              </span>
            ))}
            <button type="button" className="fpl-chip-clear" onClick={clearFilters}>Clear all</button>
          </div>
        ) : null}
        <label className="findings-filter-chip inventory-fpl-search">
          <span className="panel-caption">Search hosts</span>
          <input
            value={searchValue}
            onChange={(event) => setSearchValue(event.target.value)}
            placeholder="hostname, OS, software..."
          />
        </label>
        <button
          type="button"
          className="btn btn-secondary inventory-refresh-btn"
          onClick={() => {
            void assetsQuery.refetch();
            void hostDetailsQuery.refetch();
          }}
        >
          Refresh
        </button>
      </div>

      <div className="fpl-widgets">
        <button type="button" className="fpl-widget" onClick={() => setQuickFilter('all')}>
          <div className="fpl-widget-title">Host Exposure</div>
          <div className="inventory-donut-widget">
            <div className="inventory-donut" style={{ '--donut-fill': `${filteredRecords.length > 0 ? Math.round((assetsWithExposure / filteredRecords.length) * 100) : 0}%` } as React.CSSProperties}>
              <strong>{assetsWithExposure.toLocaleString()}</strong>
              <span>exposed</span>
            </div>
            <div className="fpl-widget-body">
              <div className="fpl-legend-row">
                <span className="fpl-legend-label">Total hosts</span>
                <strong className="fpl-legend-val">{filteredRecords.length.toLocaleString()}</strong>
              </div>
              <div className="fpl-legend-row">
                <span className="fpl-legend-label">Applicable CVEs</span>
                <strong className="fpl-legend-val">{totalCves.toLocaleString()}</strong>
              </div>
              <div className="fpl-legend-row">
                <span className="fpl-legend-label">Open findings</span>
                <strong className="fpl-legend-val">{totalFindings.toLocaleString()}</strong>
              </div>
            </div>
          </div>
        </button>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Hosts By Status</div>
          <div className="fpl-widget-body">
            {statusBreakdown.map((item) => (
              <button
                key={item.label}
                type="button"
                className="fpl-hbar-row"
                onClick={() => {
                  if (item.label === 'Online') setQuickFilter('online');
                  if (item.label === 'With findings') setQuickFilter('with-findings');
                  if (item.label === 'With CVEs') setQuickFilter('with-cves');
                }}
              >
                <span className="fpl-hbar-label">{item.label}</span>
                <span className="fpl-hbar-track">
                  <span className={`fpl-hbar-fill inventory-hbar-${item.tone}`} style={{ width: `${(item.count / statusMax) * 100}%` }} />
                </span>
                <strong className="fpl-hbar-val">{item.count.toLocaleString()}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Top Assets At Risk</div>
          <div className="fpl-widget-body">
            {topRiskAssets.map((record) => (
              <button
                key={record.asset.id}
                type="button"
                className="fpl-hbar-row"
                onClick={() => handleOpenHost(record.asset.id)}
              >
                <span className="fpl-hbar-label">{record.asset.name}</span>
                <span className="fpl-hbar-track">
                  <span className="fpl-hbar-fill" style={{ width: `${Math.max(8, Math.min(100, (record.applicableCveCount + record.openFindingCount) * 12))}%` }} />
                </span>
                <strong className="fpl-hbar-val">{(record.applicableCveCount + record.openFindingCount).toLocaleString()}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Operating Systems</div>
          <div className="fpl-widget-body">
            {topOperatingSystems.map((item) => (
              <button
                key={item.os}
                type="button"
                className="fpl-hbar-row"
                onClick={() => setSelectedOperatingSystems([item.os])}
              >
                <span className="fpl-hbar-label">{item.os}</span>
                <span className="fpl-hbar-track">
                  <span className="fpl-hbar-fill inventory-hbar-accent" style={{ width: `${(item.hostCount / osMax) * 100}%` }} />
                </span>
                <strong className="fpl-hbar-val">{item.hostCount.toLocaleString()}</strong>
              </button>
            ))}
          </div>
        </div>

        <div className="fpl-widget">
          <div className="fpl-widget-title">Asset Indicators</div>
          <div className="fpl-kpi-grid">
            <button type="button" className="fpl-kpi-card" onClick={() => setQuickFilter('with-findings')}>
              <strong className="fpl-kpi-num">{totalFindings.toLocaleString()}</strong>
              <span className="fpl-kpi-label">Open findings</span>
            </button>
            <button type="button" className="fpl-kpi-card" onClick={() => setQuickFilter('online')}>
              <strong className="fpl-kpi-num">{onlineHosts.toLocaleString()}</strong>
              <span className="fpl-kpi-label">Online</span>
            </button>
            <button type="button" className="fpl-kpi-card" onClick={() => setSelectedOperatingSystems(['Unknown'])}>
              <strong className="fpl-kpi-num">{inventoryHealth.find((item) => item.label === 'Unknown OS')?.count.toLocaleString()}</strong>
              <span className="fpl-kpi-label">Unknown OS</span>
            </button>
            <button type="button" className="fpl-kpi-card" onClick={() => setQuickFilter('all')}>
              <strong className="fpl-kpi-num">{totalSoftware.toLocaleString()}</strong>
              <span className="fpl-kpi-label">Software rows</span>
            </button>
          </div>
        </div>
      </div>

      {errorMessage ? (
        <div className="inventory-error-banner">
          Failed to load hosts inventory: {errorMessage}
        </div>
      ) : null}

      {groupedCards.length > 0 && (
        <div className="inventory-section-card">
          <div className="inventory-section-header findings-title-row">
            <div>
              <h2>Grouped Breakdown</h2>
              <p className="panel-caption">Top host segments in the current filtered inventory result set.</p>
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
        </div>
      )}

      {loading ? (
        <div className="empty-state"><p>Loading host inventory…</p></div>
      ) : (
        <div className="inventory-section-card">
          <div className="inventory-section-header">
            <div>
              <h2>Host inventory</h2>
              <p className="panel-caption">Each host is correlated to its deployed software, findings, and applicable CVEs.</p>
            </div>
            <span className="panel-caption">{filteredRecords.length.toLocaleString()} hosts</span>
          </div>

          <div className="inventory-table-shell">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Environment</th>
                  <th>OS</th>
                  <th>Owner</th>
                  <th>Support Group</th>
                  <th>Software</th>
                  <th>Applicable CVEs</th>
                  <th>Open Findings</th>
                  <th>Status</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.length === 0 ? (
                  <tr>
                    <td colSpan={10}>
                      {hostRecords.length === 0 ? (
                        <div className="empty-state">
                          <strong>No hosts discovered yet</strong>
                          <p>Connect an inventory source such as SCCM, ServiceNow CMDB, or AWS Cloud Discovery to populate host data.</p>
                          <Link to={pathForConnectView('sources')} className="btn btn-secondary btn-inline">Configure Sources</Link>
                        </div>
                      ) : (
                        <div className="empty-state"><p>No hosts matched the current filters.</p></div>
                      )}
                    </td>
                  </tr>
                ) : paginatedRecords.map((record) => (
                  <HostRow key={record.asset.id} record={record} onOpen={handleOpenHost} />
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="pagination">
              <button
                type="button"
                onClick={() => setPage((current) => Math.max(0, current - 1))}
                disabled={page === 0}
              >
                Previous
              </button>
              <span>Page {page + 1} of {totalPages}</span>
              <button
                type="button"
                onClick={() => setPage((current) => (current + 1 < totalPages ? current + 1 : current))}
                disabled={page + 1 >= totalPages}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </InventoryShell>
  );
}
