import React from 'react';
import ReactDOM from 'react-dom';
import '../styles/findings-list.css';
import { Link, useSearchParams } from 'react-router-dom';
import { pathForFindingDetail, pathForConnectView } from '../app/routes';
import type {
  Finding,
  FindingBulkWorkflowRequest,
  FindingQueueDefinition,
  FindingQueueUpsertRequest,
  FindingsFilterModel
} from '../features/findings/types';
import type { CreateServiceNowIncidentRequest } from '../features/cve-workbench/types';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { MultiGroupBy, type MultiGroupByOption } from '../components/MultiGroupBy';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import {
  useFindingBacklogHealthQuery,
  useFindingDistributionsQuery,
  useFindingFiltersQuery,
  useFindingGroupsQueries,
  useFindingQueuesQuery,
  useFindingsQuery,
  useFindingSummaryQuery
} from '../features/findings/queries';
import { useFindingsCursorPaging, useFindingsQueryContext } from '../features/findings/hooks';
import { FindingsSummaryWidgets } from '../features/findings/components/FindingsSummaryWidgets';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { useActor } from '../features/auth/context';
import { canRunSecurityWorkflow } from '../features/auth/roles';
import { api } from '../api/client';
import { computeFindingPriorityScore, riskScoreLabel } from '../lib/riskScoring';

// ─── constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;
const COL_VIS_KEY = 'findings-col-vis-v2';

const ALL_COLUMNS = [
  { key: 'findingId',      label: 'Finding ID',    alwaysVisible: true  },
  { key: 'cveId',          label: 'CVE ID',         alwaysVisible: true  },
  { key: 'asset',          label: 'Asset',          alwaysVisible: false },
  { key: 'owner',          label: 'Owner',          alwaysVisible: false },
  { key: 'supportGroup',   label: 'Support Group',  alwaysVisible: false },
  { key: 'package',        label: 'Package',        alwaysVisible: false },
  { key: 'severity',       label: 'Severity',       alwaysVisible: false },
  { key: 'status',         label: 'Status',         alwaysVisible: false },
  { key: 'creationSource', label: 'Created By',     alwaysVisible: false },
  { key: 'risk',           label: 'Risk',           alwaysVisible: false },
  { key: 'priority',      label: 'S.AI Priority',  alwaysVisible: false },
  { key: 'ownerGroup',     label: 'Owner Group',    alwaysVisible: false },
  { key: 'assignedTo',     label: 'Assigned To',    alwaysVisible: false },
  { key: 'dueDate',        label: 'Due Date',       alwaysVisible: false },
  { key: 'incidentId',       label: 'Incident ID',       alwaysVisible: false },
  { key: 'incidentStatus',   label: 'Inc. Status',       alwaysVisible: false },
  { key: 'suppressionRule',  label: 'Suppression Rule',  alwaysVisible: false },
  { key: 'firstObserved',    label: 'First Observed',    alwaysVisible: false },
  { key: 'lastObserved',     label: 'Last Observed',     alwaysVisible: false },
] as const;

type ColKey = typeof ALL_COLUMNS[number]['key'];

const DEFAULT_VISIBLE: ColKey[] = [
  'findingId', 'cveId', 'asset', 'owner', 'supportGroup', 'package',
  'severity', 'status', 'creationSource', 'risk', 'priority', 'ownerGroup', 'assignedTo', 'dueDate', 'incidentId',
];

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#22c55e',
  NONE:     '#9ca3af',
  UNKNOWN:  '#d1d5db',
};

const STATUS_COLORS: Record<string, string> = {
  OPEN:        '#3b82f6',
  RESOLVED:    '#22c55e',
  SUPPRESSED:  '#f59e0b',
  AUTO_CLOSED: '#9ca3af',
};

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, NONE: 4, UNKNOWN: 5,
};

const GROUP_OPTIONS: MultiGroupByOption[] = [
  { key: 'severity',        label: 'Severity'          },
  { key: 'status',          label: 'Status'            },
  { key: 'owner',           label: 'Owner'             },
  { key: 'assetName',       label: 'Asset'             },
  { key: 'packageName',     label: 'Package'           },
  { key: 'vulnerabilityId', label: 'Vulnerability ID'  },
];

// ─── column filter types ──────────────────────────────────────────────────────

type DueDateBand = 'overdue' | 'due-soon' | 'on-track' | 'no-sla' | null;

export type ColFilters = {
  findingId:  string;
  cveId:      string;
  asset:      string;
  owner:      string;
  supportGroup: string;
  package:    string;
  severity:   string[];
  status:     string[];
  creationSource: Array<'MANUAL' | 'AUTOMATIC'>;
  risk:       string;
  assignedTo: string;
  dueDate:    string;
  incidentId: string;
};

const DEFAULT_COL_FILTERS: ColFilters = {
  findingId: '', cveId: '', asset: '', owner: '', supportGroup: '', package: '',
  severity: [],
  status: [],
  creationSource: [],
  risk: '', assignedTo: '', dueDate: '', incidentId: '',
};

// ─── helpers ──────────────────────────────────────────────────────────────────

function fmt(v: string): string {
  return v.replace(/[_-]+/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
}
function severityClass(s: string) { return `severity-pill severity-${s.toLowerCase()}`; }
function statusClass(s: string)   { return `status-pill status-${s.toLowerCase()}`; }
function statusLabel(row: Finding): string {
  if (row.status === 'SUPPRESSED') {
    if (row.suppressedByRuleId) return 'Suppressed';
    const r = (row.suppressionReason ?? '').toUpperCase();
    if (r.includes('FALSE_POSITIVE')) return 'False Positive';
    if (r.includes('DUPLICATE')) return 'Duplicate';
    return 'Deferred';
  }
  if (row.status === 'AUTO_CLOSED') return 'Closed';
  return fmt(row.status);
}

function loadVis(): Set<ColKey> {
  try {
    const raw = localStorage.getItem(COL_VIS_KEY);
    if (raw) { const p = JSON.parse(raw); if (Array.isArray(p)) return new Set(p as ColKey[]); }
  } catch { /**/ }
  return new Set(DEFAULT_VISIBLE);
}

function ownershipDisplayName(row: Finding): string {
  return row.ownership?.displayName || 'Unassigned';
}

function ownershipSupportGroup(row: Finding): string {
  return row.ownership?.supportGroup || '';
}

function applyColFilters(rows: Finding[], f: ColFilters, dueDateBand: DueDateBand): Finding[] {
  const now = Date.now();
  const sevenDays = 7 * 24 * 3600 * 1000;
  return rows.filter(r => {
    if (f.findingId && !(r.displayId || r.id).toLowerCase().includes(f.findingId.toLowerCase())) return false;
    if (f.cveId && !r.vulnerabilityId.toLowerCase().includes(f.cveId.toLowerCase())) return false;
    if (f.asset && !r.assetName.toLowerCase().includes(f.asset.toLowerCase())) return false;
    if (f.owner && !ownershipDisplayName(r).toLowerCase().includes(f.owner.toLowerCase())) return false;
    if (f.supportGroup && !ownershipSupportGroup(r).toLowerCase().includes(f.supportGroup.toLowerCase())) return false;
    if (f.package && !r.packageName.toLowerCase().includes(f.package.toLowerCase())) return false;
    if (f.severity.length > 0 && !f.severity.includes(r.severity)) return false;
    if (f.status.length > 0 && !f.status.includes(r.status)) return false;
    if (f.creationSource.length > 0 && !f.creationSource.includes(r.creationSource)) return false;
    if (f.assignedTo && !(r.assignedTo ?? '').toLowerCase().includes(f.assignedTo.toLowerCase())) return false;
    if (f.incidentId && !(r.incidentId ?? '').toLowerCase().includes(f.incidentId.toLowerCase())) return false;
    if (f.risk) { const min = parseFloat(f.risk); if (!isNaN(min) && r.riskScore < min) return false; }
    if (dueDateBand) {
      const due = r.dueAt ? new Date(r.dueAt).getTime() : null;
      if (dueDateBand === 'overdue')  return r.status === 'OPEN' && !!due && due < now;
      if (dueDateBand === 'due-soon') return r.status === 'OPEN' && !!due && due >= now && due < now + sevenDays;
      if (dueDateBand === 'on-track') return r.status === 'OPEN' && !!due && due >= now + sevenDays;
      if (dueDateBand === 'no-sla')   return r.status === 'OPEN' && !due;
    }
    return true;
  });
}

// ─── main component ───────────────────────────────────────────────────────────

type FindingsPageProps = { onOpenCveWorkbench?: (vulnerabilityId: string) => void };

export function FindingsPage({ onOpenCveWorkbench }: FindingsPageProps = {}) {
  const actor = useActor();
  const canMutateFindings = canRunSecurityWorkflow(actor);
  const [searchParams, setSearchParams] = useSearchParams();

  // ── filter state ───────────────────────────────────────────────────────────
  const [colFilters, setColFilters] = React.useState<ColFilters>(() => ({
    ...DEFAULT_COL_FILTERS,
    severity: searchParams.getAll('severity').length ? searchParams.getAll('severity') : DEFAULT_COL_FILTERS.severity,
    status:   searchParams.getAll('status').length   ? searchParams.getAll('status')   : DEFAULT_COL_FILTERS.status,
    creationSource: searchParams.getAll('creationSource').length
      ? searchParams.getAll('creationSource').filter((value): value is 'MANUAL' | 'AUTOMATIC' => value === 'MANUAL' || value === 'AUTOMATIC')
      : DEFAULT_COL_FILTERS.creationSource,
    cveId:    searchParams.get('vulnerabilityId') ?? '',
    package:  searchParams.get('packageName') ?? '',
    asset:    searchParams.get('assetName') ?? '',
  }));
  const [dueDateBand, setDueDateBand] = React.useState<DueDateBand>(null);
  const [assetTypeFilter, setAssetTypeFilter] = React.useState<string[]>(() => searchParams.getAll('assetType'));
  const [openColFilter, setOpenColFilter] = React.useState<ColKey | null>(null);
  const [filterAnchorPos, setFilterAnchorPos] = React.useState<{ top: number; left: number } | null>(null);
  const colFilterRef = React.useRef<HTMLDivElement | null>(null);

  // ── ui state ───────────────────────────────────────────────────────────────
  const [visibleCols, setVisibleCols] = React.useState<Set<ColKey>>(loadVis);
  const [showColVis, setShowColVis] = React.useState(false);
  const colVisRef = React.useRef<HTMLDivElement | null>(null);
  const [groupFilter, setGroupFilter] = React.useState<{ field: string; value: string } | null>(null);
  const [unassignedOnly, setUnassignedOnly] = React.useState(false);
  const [incidentLinked, setIncidentLinked] = React.useState(false);
  const [groupBy, setGroupBy] = React.useState<string[]>([]);
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(new Set());
  const [actionModal, setActionModal] = React.useState<ActionType | null>(null);
  const [actionLoading, setActionLoading] = React.useState(false);
  const [actionError, setActionError] = React.useState('');
  const [actionNotice, setActionNotice] = React.useState<{ tone: 'info' | 'success'; message: string } | null>(null);
  const [showMoreActions, setShowMoreActions] = React.useState(false);
  const moreActionsRef = React.useRef<HTMLDivElement | null>(null);

  // action form
  const [deferReason, setDeferReason] = React.useState('');
  const [deferExpiry, setDeferExpiry] = React.useState('');
  const [fpJustification, setFpJustification] = React.useState('');
  const [duplicateOf, setDuplicateOf] = React.useState('');
  const [incidentNotes, setIncidentNotes] = React.useState('');
  const [incidentPriority, setIncidentPriority] = React.useState('3');
  const [incidentAssignedTo, setIncidentAssignedTo] = React.useState('');
  const [incidentAssignmentGroup, setIncidentAssignmentGroup] = React.useState('');
  const [incidentDueDate, setIncidentDueDate] = React.useState('');
  const [assignGroupTarget, setAssignGroupTarget] = React.useState('');
  const [queueDialogMode, setQueueDialogMode] = React.useState<'create' | 'edit' | null>(null);
  const [queueDialogTarget, setQueueDialogTarget] = React.useState<FindingQueueDefinition | null>(null);
  const [queueTitle, setQueueTitle] = React.useState('');
  const [queueDescription, setQueueDescription] = React.useState('');
  const [queueSetAsDefault, setQueueSetAsDefault] = React.useState(false);
  const [queueActionLoading, setQueueActionLoading] = React.useState(false);
  const [queueActionError, setQueueActionError] = React.useState('');

  // ── queries ────────────────────────────────────────────────────────────────
  const policyQuery = useRiskPolicyQuery();
  const filtersQuery = useFindingFiltersQuery();
  const queuesQuery = useFindingQueuesQuery();
  const filterValues = filtersQuery.data;

  const adHocFilterModel = React.useMemo<FindingsFilterModel>(() => ({
    groupField: groupFilter?.field,
    groupValue: groupFilter?.value,
    unassignedOnly: unassignedOnly || undefined,
    severity: colFilters.severity.length > 0 ? colFilters.severity : undefined,
    status: colFilters.status.length > 0 ? colFilters.status : undefined,
    creationSource: colFilters.creationSource.length > 0 ? colFilters.creationSource : undefined,
    vulnerabilityId: colFilters.cveId.trim() || undefined,
    packageName: colFilters.package.trim() || undefined,
    assignedTo: colFilters.assignedTo.trim() || undefined,
    dueDateBand: dueDateBand ?? undefined,
    assetName: colFilters.asset.trim() || undefined,
    supportGroup: colFilters.supportGroup.trim() || undefined,
    incidentLinked: incidentLinked || colFilters.incidentId.trim().length > 0 || undefined,
    assetType: assetTypeFilter.length > 0 ? assetTypeFilter : undefined,
  }), [colFilters, dueDateBand, assetTypeFilter, groupFilter, unassignedOnly, incidentLinked]);

  const availableQueues = queuesQuery.data ?? [];
  const {
    activeQueueKey,
    setActiveQueueKey,
    personalQueues,
    defaultQueue,
    activeQueryContext,
  } = useFindingsQueryContext({
    searchParams,
    setSearchParams,
    availableQueues,
    adHocFilterModel,
  });
  const {
    page,
    setPage,
    setPageCursors,
    effectiveServerFilterModel,
  } = useFindingsCursorPaging(activeQueryContext.queueKey, adHocFilterModel, PAGE_SIZE);

  // main table query — uses active column filters
  const findingsQuery = useFindingsQuery({
    ...effectiveServerFilterModel,
  });
  // Widgets describe the selected queue; list drill-downs must not erase its totals.
  const widgetFilters = React.useMemo(() => ({ queueKey: activeQueryContext.queueKey }), [activeQueryContext.queueKey]);
  const summaryQuery = useFindingSummaryQuery(widgetFilters);
  const distributionsQuery = useFindingDistributionsQuery(widgetFilters);
  const backlogHealthQuery = useFindingBacklogHealthQuery(widgetFilters);

  const allRows  = React.useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data]);
  const totalItems = findingsQuery.data?.totalItems ?? 0;
  const totalPages = findingsQuery.data?.totalPages ?? 0;
  const nextCursor = findingsQuery.data?.nextCursor ?? null;
  const initialLoading = findingsQuery.isLoading && !findingsQuery.data;
  const refreshingResults = findingsQuery.isFetching && !!findingsQuery.data;
  const loading = initialLoading || refreshingResults;
  const latestDataUpdate = latestFreshnessValue([
    findingsQuery.dataUpdatedAt,
    summaryQuery.dataUpdatedAt,
    distributionsQuery.dataUpdatedAt,
    backlogHealthQuery.dataUpdatedAt,
  ]);
  const rows = React.useMemo(
    () => applyColFilters(allRows, colFilters, dueDateBand),
    [allRows, colFilters, dueDateBand]
  );

  const groupQueries = useFindingGroupsQueries(groupBy, widgetFilters);
  const groupCards = groupBy.map((key, index) => ({
    key,
    label: GROUP_OPTIONS.find(option => option.key === key)?.label ?? key,
    items: groupQueries[index]?.data ?? [],
  }));

  // ── widget data computations ───────────────────────────────────────────────

  const severityCounts = React.useMemo(() => {
    const map = new Map<string, number>();
    (distributionsQuery.data?.severityCounts ?? []).forEach((bucket) => map.set(bucket.key, bucket.count));
    return map;
  }, [distributionsQuery.data]);

  const statusCounts = React.useMemo(() => {
    const map = new Map<string, number>();
    (distributionsQuery.data?.statusCounts ?? []).forEach((bucket) => map.set(bucket.key, bucket.count));
    return map;
  }, [distributionsQuery.data]);

  const assetCounts = React.useMemo(
    () => (distributionsQuery.data?.topAssets ?? []).map((item) => [item.assetName, item.count] as const),
    [distributionsQuery.data]
  );

  const dueDateCounts = backlogHealthQuery.data ?? { overdue: 0, dueSoon: 0, onTrack: 0, noSla: 0 };
  const editableActiveQueue = React.useMemo(
    () => personalQueues.find((queue) => queue.key === activeQueryContext.queueKey) ?? null,
    [activeQueryContext.queueKey, personalQueues]
  );
  const queueActionTarget = React.useMemo(
    () => editableActiveQueue
      ?? (defaultQueue?.editable ? defaultQueue : null)
      ?? personalQueues.find((queue) => queue.editable) ?? null,
    [defaultQueue, editableActiveQueue, personalQueues]
  );
  const workspaceError = findingsQuery.error instanceof Error ? findingsQuery.error
    : summaryQuery.error instanceof Error ? summaryQuery.error
    : distributionsQuery.error instanceof Error ? distributionsQuery.error
    : backlogHealthQuery.error instanceof Error ? backlogHealthQuery.error
    : null;

  // ── outside click ──────────────────────────────────────────────────────────
  React.useEffect(() => {
    function onDown(e: MouseEvent) {
      if (colFilterRef.current && !colFilterRef.current.contains(e.target as Node)) { setOpenColFilter(null); setFilterAnchorPos(null); }
      if (colVisRef.current && !colVisRef.current.contains(e.target as Node)) setShowColVis(false);
      if (moreActionsRef.current && !moreActionsRef.current.contains(e.target as Node)) setShowMoreActions(false);
    }
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, []);

  // ── widget click helpers ───────────────────────────────────────────────────
  function filterBySeverity(sev: string) {
    if (activeQueryContext.baseFilter.severity && !activeQueryContext.baseFilter.severity.includes(sev)) return;
    const toggled = colFilters.severity.length===1 && colFilters.severity[0]===sev;
    setColFilters(p=>({...p, severity: toggled ? [] : [sev], status: []}));
    setDueDateBand(null);
    setPage(0);
  }
  function filterByStatus(s: string) {
    if (activeQueryContext.baseFilter.status && !activeQueryContext.baseFilter.status.includes(s)) return;
    const toggled = colFilters.status.length===1 && colFilters.status[0]===s;
    setColFilters(p=>({...p, status: toggled ? [] : [s], severity: []}));
    setDueDateBand(null);
    setPage(0);
  }
  function filterByAsset(name: string) {
    setColFilters(p=>({...p, asset: p.asset===name ? '' : name}));
    setDueDateBand(null);
    setPage(0);
  }
  function filterByDueBand(band: DueDateBand) {
    if (band && activeQueryContext.baseFilter.dueDateBand && activeQueryContext.baseFilter.dueDateBand !== band) return;
    setDueDateBand(prev => prev===band ? null : band);
    setPage(0);
  }

  function mergeQueueFilter(baseFilter: FindingsFilterModel, adHocFilters: FindingsFilterModel): FindingsFilterModel {
    return {
      severity: adHocFilters.severity && adHocFilters.severity.length > 0 ? adHocFilters.severity : baseFilter.severity,
      status: adHocFilters.status && adHocFilters.status.length > 0 ? adHocFilters.status : baseFilter.status,
      decisionState: adHocFilters.decisionState && adHocFilters.decisionState.length > 0 ? adHocFilters.decisionState : baseFilter.decisionState,
      creationSource: adHocFilters.creationSource && adHocFilters.creationSource.length > 0 ? adHocFilters.creationSource : baseFilter.creationSource,
      matchMethod: adHocFilters.matchMethod && adHocFilters.matchMethod.length > 0 ? adHocFilters.matchMethod : baseFilter.matchMethod,
      vexStatus: adHocFilters.vexStatus && adHocFilters.vexStatus.length > 0 ? adHocFilters.vexStatus : baseFilter.vexStatus,
      vexFreshness: adHocFilters.vexFreshness && adHocFilters.vexFreshness.length > 0 ? adHocFilters.vexFreshness : baseFilter.vexFreshness,
      vexProvider: adHocFilters.vexProvider && adHocFilters.vexProvider.length > 0 ? adHocFilters.vexProvider : baseFilter.vexProvider,
      minConfidence: adHocFilters.minConfidence ?? baseFilter.minConfidence,
      vulnerabilityId: adHocFilters.vulnerabilityId ?? baseFilter.vulnerabilityId,
      packageName: adHocFilters.packageName ?? baseFilter.packageName,
      ecosystem: adHocFilters.ecosystem ?? baseFilter.ecosystem,
      ownerGroup: adHocFilters.ownerGroup ?? baseFilter.ownerGroup,
      assignedTo: adHocFilters.assignedTo ?? baseFilter.assignedTo,
      unassignedOnly: adHocFilters.unassignedOnly ?? baseFilter.unassignedOnly,
      incidentLinked: adHocFilters.incidentLinked ?? baseFilter.incidentLinked,
      dueDateBand: adHocFilters.dueDateBand ?? baseFilter.dueDateBand,
      assetName: adHocFilters.assetName ?? baseFilter.assetName,
      supportGroup: adHocFilters.supportGroup ?? baseFilter.supportGroup,
      patchAvailable: adHocFilters.patchAvailable ?? baseFilter.patchAvailable,
      suppressedUntilBand: adHocFilters.suppressedUntilBand ?? baseFilter.suppressedUntilBand,
    };
  }

  function openCreateQueueDialog() {
    setQueueDialogMode('create');
    setQueueDialogTarget(null);
    setQueueTitle(activeQueryContext.title === 'All Findings' ? 'My Queue' : activeQueryContext.title);
    setQueueDescription('');
    setQueueSetAsDefault(false);
    setQueueActionError('');
  }

  function openEditQueueDialog(queue: FindingQueueDefinition) {
    setQueueDialogMode('edit');
    setQueueDialogTarget(queue);
    setQueueTitle(queue.title);
    setQueueDescription(queue.description ?? '');
    setQueueSetAsDefault(queue.isDefault);
    setQueueActionError('');
  }

  function closeQueueDialog() {
    setQueueDialogMode(null);
    setQueueDialogTarget(null);
    setQueueTitle('');
    setQueueDescription('');
    setQueueSetAsDefault(false);
    setQueueActionError('');
  }

  async function refreshQueueWorkspace(nextQueueKey?: string | null) {
    const refreshed = await queuesQuery.refetch();
    const refreshedQueues = refreshed.data ?? [];
    if (nextQueueKey) {
      setActiveQueueKey(nextQueueKey);
    } else if (!refreshedQueues.some((queue) => queue.key === activeQueueKey)) {
      setActiveQueueKey(refreshedQueues.find((queue) => queue.isDefault)?.key ?? 'all-findings');
    }
      await Promise.all([
        findingsQuery.refetch(),
        summaryQuery.refetch(),
        distributionsQuery.refetch(),
        backlogHealthQuery.refetch(),
      ]);
  }

  async function saveQueue() {
    const effectiveFilter = queueDialogMode === 'edit' && queueDialogTarget
      ? queueDialogTarget.filter
      : mergeQueueFilter(activeQueryContext.baseFilter, activeQueryContext.adHocFilters);
    const payload: FindingQueueUpsertRequest = {
      title: queueTitle.trim(),
      description: queueDescription.trim() || undefined,
      filter: effectiveFilter,
      sourceQueueKey: activeQueryContext.queueKey,
      setAsDefault: queueSetAsDefault,
    };
    setQueueActionLoading(true);
    setQueueActionError('');
    try {
      const saved = queueDialogMode === 'edit' && queueDialogTarget
        ? await api.updateFindingQueue(queueDialogTarget.key, payload)
        : await api.createFindingQueue(payload);
      closeQueueDialog();
      await refreshQueueWorkspace(saved.key);
    } catch (error) {
      setQueueActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setQueueActionLoading(false);
    }
  }

  async function duplicateQueue(queue: FindingQueueDefinition) {
    setQueueActionLoading(true);
    setQueueActionError('');
    try {
      const duplicated = await api.duplicateFindingQueue(queue.key);
      await refreshQueueWorkspace(duplicated.key);
    } catch (error) {
      setQueueActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setQueueActionLoading(false);
    }
  }

  async function setDefaultQueue(queue: FindingQueueDefinition) {
    setQueueActionLoading(true);
    setQueueActionError('');
    try {
      await api.setDefaultFindingQueue(queue.key);
      await refreshQueueWorkspace(queue.key);
    } catch (error) {
      setQueueActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setQueueActionLoading(false);
    }
  }

  async function deleteQueue(queue: FindingQueueDefinition) {
    if (!window.confirm(`Delete saved queue "${queue.title}"?`)) return;
    setQueueActionLoading(true);
    setQueueActionError('');
    try {
      await api.deleteFindingQueue(queue.key);
      const fallbackQueue = defaultQueue?.key === queue.key ? 'all-findings' : activeQueueKey === queue.key
        ? (availableQueues.find((candidate) => candidate.isDefault && candidate.key !== queue.key)?.key ?? 'all-findings')
        : null;
      await refreshQueueWorkspace(fallbackQueue);
    } catch (error) {
      setQueueActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setQueueActionLoading(false);
    }
  }

  // ── filter helpers ─────────────────────────────────────────────────────────
  function setColFilter<K extends keyof ColFilters>(key: K, val: ColFilters[K]) {
    setColFilters(prev=>({...prev,[key]:val}));
    setPage(0);
  }
  function toggleSeverityFilter(v: string) {
    setColFilters(prev=>({ ...prev, severity: prev.severity.includes(v) ? prev.severity.filter(s=>s!==v) : [...prev.severity,v] }));
    setPage(0);
  }
  function toggleStatusFilter(v: string) {
    setColFilters(prev=>({ ...prev, status: prev.status.includes(v) ? prev.status.filter(s=>s!==v) : [...prev.status,v] }));
    setPage(0);
  }
  function toggleCreationSourceFilter(v: 'MANUAL' | 'AUTOMATIC') {
    setColFilters(prev=>({
      ...prev,
      creationSource: prev.creationSource.includes(v)
        ? prev.creationSource.filter(source=>source!==v)
        : [...prev.creationSource, v]
    }));
    setPage(0);
  }
  function hasColFilter(key: ColKey): boolean {
    if (key==='severity') return colFilters.severity.length>0;
    if (key==='status')   return colFilters.status.length>0;
    if (key==='creationSource') return colFilters.creationSource.length>0;
    if (key==='findingId') return !!colFilters.findingId;
    if (key==='cveId')    return !!colFilters.cveId;
    if (key==='asset')    return !!colFilters.asset;
    if (key==='owner')    return !!colFilters.owner;
    if (key==='supportGroup') return !!colFilters.supportGroup;
    if (key==='package')  return !!colFilters.package;
    if (key==='risk')     return !!colFilters.risk;
    if (key==='assignedTo') return !!colFilters.assignedTo;
    if (key==='dueDate')  return !!dueDateBand || !!colFilters.dueDate;
    if (key==='incidentId') return !!colFilters.incidentId;
    return false;
  }
  function clearColFilter(key: ColKey) {
    if (key==='severity')   setColFilter('severity',[]);
    else if (key==='status') setColFilter('status',[]);
    else if (key==='creationSource') setColFilter('creationSource',[]);
    else if (key==='findingId') setColFilter('findingId','');
    else if (key==='cveId')  setColFilter('cveId','');
    else if (key==='asset')  setColFilter('asset','');
    else if (key==='owner') setColFilter('owner','');
    else if (key==='supportGroup') setColFilter('supportGroup','');
    else if (key==='package') setColFilter('package','');
    else if (key==='risk')   setColFilter('risk','');
    else if (key==='assignedTo') setColFilter('assignedTo','');
    else if (key==='dueDate') { setColFilter('dueDate',''); setDueDateBand(null); }
    else if (key==='incidentId') setColFilter('incidentId','');
  }
  function clearAllFilters() {
    setColFilters(DEFAULT_COL_FILTERS);
    setGroupFilter(null);
    setUnassignedOnly(false);
    setIncidentLinked(false);
    setAssetTypeFilter([]);
    setDueDateBand(null);
    setPage(0);
  }

  // active filter chips (server-side only for now)
  const activeChips: Array<{ label: string; onRemove: ()=>void }> = [];
  if (groupFilter) activeChips.push({ label: `${GROUP_OPTIONS.find(option => option.key === groupFilter.field)?.label}: ${groupFilter.value}`, onRemove: () => setGroupFilter(null) });
  if (unassignedOnly) activeChips.push({ label: 'Unassigned remediation', onRemove: () => setUnassignedOnly(false) });
  if (incidentLinked) activeChips.push({ label: 'Linked incident', onRemove: () => setIncidentLinked(false) });
  if (colFilters.severity.length>0) activeChips.push({ label:`Severity: ${colFilters.severity.join(', ')}`, onRemove:()=>setColFilter('severity',[]) });
  if (colFilters.status.length>0)   activeChips.push({ label:`Status: ${colFilters.status.map(fmt).join(', ')}`, onRemove:()=>setColFilter('status',[]) });
  if (colFilters.creationSource.length>0) activeChips.push({ label:`Created By: ${colFilters.creationSource.map(fmt).join(', ')}`, onRemove:()=>setColFilter('creationSource',[]) });
  if (colFilters.cveId)    activeChips.push({ label:`CVE: ${colFilters.cveId}`,  onRemove:()=>setColFilter('cveId','') });
  if (colFilters.package)  activeChips.push({ label:`Package: ${colFilters.package}`, onRemove:()=>setColFilter('package','') });
  if (colFilters.asset)    activeChips.push({ label:`Asset: ${colFilters.asset}`, onRemove:()=>setColFilter('asset','') });
  if (colFilters.owner)    activeChips.push({ label:`Owner: ${colFilters.owner}`, onRemove:()=>setColFilter('owner','') });
  if (colFilters.supportGroup) activeChips.push({ label:`Support Group: ${colFilters.supportGroup}`, onRemove:()=>setColFilter('supportGroup','') });
  if (colFilters.assignedTo) activeChips.push({ label:`Assigned: ${colFilters.assignedTo}`, onRemove:()=>setColFilter('assignedTo','') });
  if (dueDateBand)         activeChips.push({ label:`SLA: ${fmt(dueDateBand)}`, onRemove:()=>setDueDateBand(null) });
  if (assetTypeFilter.length>0) activeChips.push({ label:`Asset Type: ${assetTypeFilter.map(fmt).join(', ')}`, onRemove:()=>setAssetTypeFilter([]) });

  // ── selection ──────────────────────────────────────────────────────────────
  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const n = new Set(prev);
      if (n.has(id)) {
        n.delete(id);
      } else {
        n.add(id);
      }
      return n;
    });
  }
  function toggleSelectAll() {
    setSelectedIds(selectedIds.size===rows.length ? new Set() : new Set(rows.map(r=>r.id)));
  }
  function saveColVis(next: Set<ColKey>) {
    setVisibleCols(next);
    localStorage.setItem(COL_VIS_KEY, JSON.stringify(Array.from(next)));
  }

  const selectedFindings = rows.filter(r=>selectedIds.has(r.id));
  const hasSelection = selectedIds.size>0;
  const allSelected = rows.length>0 && selectedIds.size===rows.length;

  // ── actions ────────────────────────────────────────────────────────────────
  type ActionType = 'create-incident'|'defer'|'resolve'|'false-positive'|'duplicate'|'delete'|'assign';
  function openAction(t: ActionType) { if (!hasSelection) return; setShowMoreActions(false); setActionError(''); setActionNotice(null); setActionModal(t); }
  function closeModal() {
    setActionModal(null); setActionError('');
    setDeferReason(''); setDeferExpiry(''); setFpJustification(''); setDuplicateOf('');
    setIncidentNotes(''); setIncidentPriority('3'); setIncidentAssignedTo('');
    setIncidentAssignmentGroup(''); setIncidentDueDate('');
    setAssignGroupTarget('');
  }
  function publishActionNotice(message: string, tone: 'info' | 'success' = 'success') {
    setActionNotice({ message, tone });
  }
  async function execAll(payload: Record<string,unknown>) {
    await api.bulkUpdateFindingWorkflow({
      findingIds: selectedFindings.map(f => f.id),
      workflowStatus: payload.status as FindingBulkWorkflowRequest['workflowStatus'],
      assignedTo: payload.assignedTo as string | undefined,
      dueAt: payload.dueAt as string | undefined,
      suppressionReason: payload.suppressionReason as string | undefined,
      suppressedUntil: payload.suppressedUntil as string | undefined,
      actor: payload.actor as string | undefined,
    });
    await Promise.all([
      findingsQuery.refetch(),
      summaryQuery.refetch(),
      distributionsQuery.refetch(),
      backlogHealthQuery.refetch(),
    ]);
    setSelectedIds(new Set());
  }
  async function handleResolve()     { setActionLoading(true); try { const count = selectedFindings.length; await execAll({status:'RESOLVED',actor:actor?.principal}); publishActionNotice(`Resolved ${count.toLocaleString()} finding${count === 1 ? '' : 's'}.`); closeModal(); } catch(e){setActionError(String(e));} finally{setActionLoading(false);} }
  async function handleReopen()      { if (!hasSelection) return; setActionLoading(true); try { const count = selectedFindings.length; await execAll({status:'OPEN',actor:actor?.principal}); publishActionNotice(`Reopened ${count.toLocaleString()} finding${count === 1 ? '' : 's'}.`); } catch(e){console.error(e);} finally{setActionLoading(false); setShowMoreActions(false);} }
  async function handleDefer()       { setActionLoading(true); try { const count = selectedFindings.length; await execAll({status:'SUPPRESSED',suppressionReason:deferReason||'DEFERRED',suppressedUntil:deferExpiry?new Date(deferExpiry).toISOString():undefined,actor:actor?.principal}); publishActionNotice(`Deferred ${count.toLocaleString()} finding${count === 1 ? '' : 's'}.`); closeModal(); } catch(e){setActionError(String(e));} finally{setActionLoading(false);} }
  async function handleFalsePos()    { setActionLoading(true); try { const count = selectedFindings.length; await execAll({status:'SUPPRESSED',suppressionReason:`FALSE_POSITIVE${fpJustification?': '+fpJustification:''}`,actor:actor?.principal}); publishActionNotice(`Marked ${count.toLocaleString()} finding${count === 1 ? '' : 's'} as false positive.`); closeModal(); } catch(e){setActionError(String(e));} finally{setActionLoading(false);} }
  async function handleDuplicate()   { setActionLoading(true); try { const count = selectedFindings.length; await execAll({status:'SUPPRESSED',suppressionReason:`DUPLICATE${duplicateOf?': '+duplicateOf:''}`,actor:actor?.principal}); publishActionNotice(`Marked ${count.toLocaleString()} finding${count === 1 ? '' : 's'} as duplicate.`); closeModal(); } catch(e){setActionError(String(e));} finally{setActionLoading(false);} }
  async function handleAssign()      { setActionLoading(true); try { const count = selectedFindings.length; await execAll({assignedTo:assignGroupTarget,actor:actor?.principal}); publishActionNotice(`Assigned ${count.toLocaleString()} finding${count === 1 ? '' : 's'}${assignGroupTarget ? ` to ${assignGroupTarget}` : ''}.`); closeModal(); } catch(e){setActionError(String(e));} finally{setActionLoading(false);} }
  async function handleDelete() {
    setActionLoading(true);
    try {
      const count = selectedFindings.length;
      await api.bulkDeleteFindings(selectedFindings.map(f => f.id));
      void findingsQuery.refetch();
      void summaryQuery.refetch();
      void distributionsQuery.refetch();
      void backlogHealthQuery.refetch();
      setSelectedIds(new Set());
      publishActionNotice(`Deleted ${count.toLocaleString()} finding${count === 1 ? '' : 's'}.`);
      closeModal();
    } catch(e) { setActionError(String(e)); } finally { setActionLoading(false); }
  }
  async function handleCreateIncident() {
    setActionLoading(true);
    try {
      const byCve = new Map<string,Finding[]>();
      for (const f of selectedFindings) { const l=byCve.get(f.vulnerabilityId)??[]; l.push(f); byCve.set(f.vulnerabilityId,l); }
      publishActionNotice(`Submitting ServiceNow incident creation for ${selectedFindings.length.toLocaleString()} finding${selectedFindings.length === 1 ? '' : 's'}…`, 'info');
      for (const [cveId, findings] of byCve) {
        const top = findings.reduce((b,f)=>(SEVERITY_ORDER[f.severity]??5)<(SEVERITY_ORDER[b.severity]??5)?f:b, findings[0]!);
        const payload: CreateServiceNowIncidentRequest = {
          findingTitle: `${cveId} — Vulnerability Remediation`,
          severity: top.severity, cvssScore: undefined,
          inKev: findings.some(f=>f.inKev), priority: incidentPriority,
          dueDate: incidentDueDate||undefined, assignedTo: incidentAssignedTo.trim()||undefined,
          notes: incidentNotes.trim()||undefined,
          affectedAssets: findings.map(f=>({ componentId:f.componentId, assetName:f.assetName, assetIdentifier:f.assetIdentifier, assetType:f.assetType, packageName:f.packageName, packageVersion:f.packageVersion, assignmentGroup:incidentAssignmentGroup.trim()||undefined })),
        };
        await cveWorkbenchApi.createServiceNowIncident(cveId, payload);
      }
      void findingsQuery.refetch();
      setSelectedIds(new Set());
      publishActionNotice(`ServiceNow incident creation completed for ${selectedFindings.length.toLocaleString()} finding${selectedFindings.length === 1 ? '' : 's'} across ${byCve.size.toLocaleString()} CVE${byCve.size === 1 ? '' : 's'}.`);
      closeModal();
    } catch(e) { setActionNotice(null); setActionError(String(e)); }
    finally { setActionLoading(false); }
  }

  // ── column filter popover ──────────────────────────────────────────────────
  function renderColFilterPopover(colKey: ColKey) {
    if (openColFilter!==colKey) return null;
    const severities = filterValues?.severities ?? ['CRITICAL','HIGH','MEDIUM','LOW','NONE','UNKNOWN'];
    const statuses   = filterValues?.statuses   ?? ['OPEN','RESOLVED','SUPPRESSED','AUTO_CLOSED'];
    const style: React.CSSProperties = {
      position: 'fixed',
      top: filterAnchorPos?.top ?? 100,
      left: filterAnchorPos?.left ?? 200,
    };
    return ReactDOM.createPortal(
      <div className="fpl-col-filter-popover" ref={colFilterRef} style={style}>
        {hasColFilter(colKey) && (
          <div className="fpl-col-filter-clear-row">
            <button type="button" className="fpl-col-filter-clear" onClick={()=>clearColFilter(colKey)}>Clear filter</button>
          </div>
        )}
        {colKey==='severity' && (
          <div className="fpl-col-filter-checks">
            {severities.map(v=>(
              <label key={v} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.severity.includes(v)} onChange={()=>toggleSeverityFilter(v)}/>
                <span className={severityClass(v)} style={{fontSize:11}}>{v}</span>
              </label>
            ))}
          </div>
        )}
        {colKey==='status' && (
          <div className="fpl-col-filter-checks">
            {statuses.map(v=>(
              <label key={v} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.status.includes(v)} onChange={()=>toggleStatusFilter(v)}/>
                <span>{v === 'SUPPRESSED' ? 'Deferred / Suppressed' : v === 'AUTO_CLOSED' ? 'Closed' : fmt(v)}</span>
              </label>
            ))}
          </div>
        )}
        {colKey==='creationSource' && (
          <div className="fpl-col-filter-checks">
            {(['MANUAL','AUTOMATIC'] as const).map(v=>(
              <label key={v} className="fpl-col-filter-check">
                <input type="checkbox" checked={colFilters.creationSource.includes(v)} onChange={()=>toggleCreationSourceFilter(v)}/>
                <span>{v === 'MANUAL' ? 'Manual' : 'Automatic'}</span>
              </label>
            ))}
          </div>
        )}
        {(['findingId','cveId','asset','owner','supportGroup','package','assignedTo','incidentId'] as readonly string[]).includes(colKey) && (
          <input autoFocus className="fpl-col-filter-input"
            placeholder={`Search ${ALL_COLUMNS.find(c=>c.key===colKey)?.label}…`}
            value={(colFilters as unknown as Record<string,string>)[colKey] ?? ''}
            onChange={e=>setColFilter(colKey as 'findingId'|'cveId'|'asset'|'owner'|'supportGroup'|'package'|'assignedTo'|'incidentId', e.target.value)}
          />
        )}
        {colKey==='risk' && (
          <input autoFocus type="number" min={0} max={10} step={0.1} className="fpl-col-filter-input"
            placeholder="Min risk score" value={colFilters.risk} onChange={e=>setColFilter('risk',e.target.value)}/>
        )}
        {colKey==='dueDate' && (
          <div className="fpl-col-filter-checks">
            {([['overdue','Overdue'],['due-soon','Due in 7 days'],['on-track','On Track'],['no-sla','No SLA']] as [DueDateBand,string][]).map(([band,label])=>(
              <label key={band!} className="fpl-col-filter-check">
                <input type="radio" name="dueband" checked={dueDateBand===band} onChange={()=>{setDueDateBand(dueDateBand===band?null:band);setPage(0);}}/>
                <span>{label}</span>
              </label>
            ))}
          </div>
        )}
      </div>,
      document.body
    );
  }

  // ── col header ─────────────────────────────────────────────────────────────
  function ColHeader({ colKey, label }: { colKey: ColKey; label: string }) {
    const active = hasColFilter(colKey);
    return (
      <th className={`fpl-th${active?' fpl-th--filtered':''}`}>
        <div className="fpl-th-inner">
          <span className="fpl-th-label">{label}</span>
          {colKey === 'priority' && (
            <span className="fpl-th-info" title="Scout AI-computed priority score (0\u201310) based on exploitability, SLA proximity, EOL risk, and blast radius">&#9432;</span>
          )}
          <button className="fpl-filter-btn" title={`Filter ${label}`}
            onClick={e=>{
              e.stopPropagation();
              const rect = e.currentTarget.getBoundingClientRect();
              setOpenColFilter(p=>{
                if (p===colKey) { setFilterAnchorPos(null); return null; }
                setFilterAnchorPos({ top: rect.bottom + 4, left: Math.min(rect.left, window.innerWidth - 280) });
                return colKey;
              });
              setShowColVis(false);
            }}>
            <svg viewBox="0 0 12 12" width="11" height="11" fill={active?'var(--accent,#3b82f6)':'currentColor'} aria-hidden>
              <path d="M1 2h10l-4 5v3l-2-1V7z"/>
            </svg>
          </button>
        </div>
        {renderColFilterPopover(colKey)}
      </th>
    );
  }

  // ── cell renderer ──────────────────────────────────────────────────────────
  function renderCell(row: Finding, key: ColKey): React.ReactNode {
    const now = Date.now();
    if (key==='findingId') return (
      <Link to={pathForFindingDetail(row.displayId||row.id)} state={{finding:row}} className="finding-id-link mono">
        {row.displayId||row.id}
      </Link>
    );
    if (key==='cveId') return onOpenCveWorkbench
      ? <button type="button" className="fpl-cve-link" onClick={()=>onOpenCveWorkbench(row.vulnerabilityId)}>{row.vulnerabilityId}</button>
      : <span className="mono fpl-cve-text">{row.vulnerabilityId}</span>;
    if (key==='asset') return <div><div className="fpl-cell-main">{row.assetName}</div><div className="fpl-cell-sub">{fmt(row.assetType)}</div></div>;
    if (key==='owner') return (
      <div>
        <div className="fpl-cell-main">{ownershipDisplayName(row)}</div>
        <div className="fpl-cell-sub">{row.ownership?.sourceSystem ? fmt(row.ownership.sourceSystem) : 'No ownership source'}</div>
      </div>
    );
    if (key==='supportGroup') return ownershipSupportGroup(row)
      ? <span className="fpl-assigned">{ownershipSupportGroup(row)}</span>
      : <span className="fpl-empty">—</span>;
    if (key==='package') return <div><div className="fpl-cell-main">{row.packageName}</div><div className="fpl-cell-sub mono">{row.packageVersion}</div></div>;
    if (key==='severity') return <span className={severityClass(row.severity)}>{row.severity}</span>;
    if (key==='status') return <span className={statusClass(row.status)}>{statusLabel(row)}</span>;
    if (key==='creationSource') return <span className="fpl-assigned">{row.creationSource === 'MANUAL' ? 'Manual' : 'Automatic'}</span>;
    if (key==='risk') return <span className="fpl-risk">{row.riskScore.toFixed(1)}</span>;
    if (key==='priority') {
      const p = computeFindingPriorityScore(row, policyQuery.data);
      const cls = `risk-score-badge risk-score-badge--${riskScoreLabel(p.score).toLowerCase()}`;
      return (
        <span className={cls} title={p.topReasons.join(' · ')}>
          {p.score.toFixed(1)}
        </span>
      );
    }
    if (key==='ownerGroup') return row.ownerGroup ? <span className="fpl-assigned">{row.ownerGroup}</span> : <span className="fpl-empty">—</span>;
    if (key==='assignedTo') return row.assignedTo ? <span className="fpl-assigned">{row.assignedTo}</span> : <span className="fpl-empty">—</span>;
    if (key==='dueDate') {
      if (!row.dueAt) return <span className="fpl-empty">—</span>;
      const overdue = row.status==='OPEN' && new Date(row.dueAt).getTime()<now;
      return <span className={overdue?'fpl-overdue':'fpl-date'}>{new Date(row.dueAt).toLocaleDateString()}</span>;
    }
    if (key==='incidentId') return row.incidentId ? <span className="mono fpl-incident-id">{row.incidentId}</span> : <span className="fpl-empty">—</span>;
    if (key==='incidentStatus') return row.incidentStatus ? <span className="fpl-inc-status">{row.incidentStatus}</span> : <span className="fpl-empty">—</span>;
    if (key==='suppressionRule') return row.suppressedByRuleName
      ? <span style={{ fontSize: '0.78rem', color: 'var(--medium)', fontWeight: 500 }}>{row.suppressedByRuleName}</span>
      : <span className="fpl-empty">—</span>;
    if (key==='firstObserved') return row.firstObservedAt ? <span className="fpl-date">{new Date(row.firstObservedAt).toLocaleDateString()}</span> : <span className="fpl-empty">—</span>;
    if (key==='lastObserved') return row.lastObservedAt ? <span className="fpl-date">{new Date(row.lastObservedAt).toLocaleDateString()}</span> : <span className="fpl-empty">—</span>;
    return null;
  }

  const visColDefs = ALL_COLUMNS.filter(c=>c.alwaysVisible||visibleCols.has(c.key));

  // ── modal ──────────────────────────────────────────────────────────────────
  function renderModal() {
    if (!actionModal) return null;
    const n = selectedIds.size;
    const TITLES: Record<ActionType,string> = {
      'create-incident':'Create ServiceNow Incident','defer':'Defer Findings',
      'resolve':`Resolve ${n} Finding${n!==1?'s':''}`,
      'false-positive':'Mark as False Positive',
      'assign':`Assign ${n} Finding${n!==1?'s':''} to Group`,
      'duplicate':'Mark as Duplicate',
      'delete':`Delete ${n} Finding${n!==1?'s':''}`,
    };
    return (
      <div className="fd3-modal-overlay" onClick={e=>{if(e.target===e.currentTarget)closeModal();}}>
        <div className="fd3-modal" style={{maxWidth:actionModal==='create-incident'?520:440}}>
          <div className="fd3-modal-header">
            <span>{TITLES[actionModal]}</span>
            <button className="fd3-modal-close" onClick={closeModal}>✕</button>
          </div>
          <div className="fd3-modal-body">
            {actionError && <div className="notice error" style={{marginBottom:12}}>{actionError}</div>}
            {actionModal==='create-incident' && (
              <div className="fpl-form">
                <div className="fpl-form-row"><label>Priority</label>
                  <select value={incidentPriority} onChange={e=>setIncidentPriority(e.target.value)} className="fpl-form-select">
                    <option value="1">1 - Critical</option><option value="2">2 - High</option>
                    <option value="3">3 - Moderate</option><option value="4">4 - Low</option>
                  </select>
                </div>
                <div className="fpl-form-row"><label>Assigned To</label><input className="fpl-form-input" value={incidentAssignedTo} onChange={e=>setIncidentAssignedTo(e.target.value)} placeholder="username or email"/></div>
                <div className="fpl-form-row"><label>Assignment Group</label><input className="fpl-form-input" value={incidentAssignmentGroup} onChange={e=>setIncidentAssignmentGroup(e.target.value)} placeholder="Security Operations"/></div>
                <div className="fpl-form-row"><label>Due Date</label><input type="date" className="fpl-form-input" value={incidentDueDate} onChange={e=>setIncidentDueDate(e.target.value)}/></div>
                <div className="fpl-form-row"><label>Notes</label><textarea className="fpl-form-textarea" rows={3} value={incidentNotes} onChange={e=>setIncidentNotes(e.target.value)} placeholder="Remediation context…"/></div>
                <div className="fpl-form-info">Creating for <strong>{n}</strong> finding(s) across <strong>{new Set(selectedFindings.map(f=>f.vulnerabilityId)).size}</strong> CVE(s).</div>
              </div>
            )}
            {actionModal==='defer' && (
              <div className="fpl-form">
                <p className="fpl-form-desc">Suppress {n} finding(s) until a specified date.</p>
                <div className="fpl-form-row"><label>Reason</label>
                  <select value={deferReason} onChange={e=>setDeferReason(e.target.value)} className="fpl-form-select">
                    <option value="">Select reason…</option>
                    <option value="RISK_ACCEPTED">Risk Accepted</option>
                    <option value="COMPENSATING_CONTROL">Compensating Control</option>
                    <option value="PENDING_PATCH">Pending Patch</option>
                    <option value="DEFERRED">Deferred</option>
                  </select>
                </div>
                <div className="fpl-form-row"><label>Expires</label><input type="date" className="fpl-form-input" value={deferExpiry} onChange={e=>setDeferExpiry(e.target.value)}/></div>
              </div>
            )}
            {actionModal==='resolve' && <p className="fpl-form-desc">Mark <strong>{n}</strong> finding(s) as resolved.</p>}
            {actionModal==='false-positive' && (
              <div className="fpl-form">
                <p className="fpl-form-desc">Suppress <strong>{n}</strong> finding(s) as false positives.</p>
                <div className="fpl-form-row"><label>Justification</label><textarea className="fpl-form-textarea" rows={3} value={fpJustification} onChange={e=>setFpJustification(e.target.value)} placeholder="Why is this a false positive?"/></div>
              </div>
            )}
            {actionModal==='duplicate' && (
              <div className="fpl-form">
                <p className="fpl-form-desc">Mark <strong>{n}</strong> finding(s) as duplicate.</p>
                <div className="fpl-form-row"><label>Duplicate Of</label><input className="fpl-form-input mono" value={duplicateOf} onChange={e=>setDuplicateOf(e.target.value)} placeholder="Finding ID or Incident ID"/></div>
              </div>
            )}
            {actionModal==='assign' && (() => {
              const groups = Array.from(new Set(selectedFindings.map(f=>f.ownerGroup).filter(Boolean))) as string[];
              return (
                <div className="fpl-form">
                  <p className="fpl-form-desc">Assign <strong>{n}</strong> finding{n!==1?'s':''} to an assignment group.</p>
                  <div className="fpl-form-row">
                    <label>Assignment Group</label>
                    {groups.length > 0
                      ? <select className="fpl-form-select" value={assignGroupTarget} onChange={e=>setAssignGroupTarget(e.target.value)}>
                          <option value="">— select group —</option>
                          {groups.map(g=><option key={g} value={g}>{g}</option>)}
                          <option value="__custom__">Other…</option>
                        </select>
                      : null}
                    {(groups.length === 0 || assignGroupTarget === '__custom__') &&
                      <input className="fpl-form-input" value={assignGroupTarget==='__custom__'?'':assignGroupTarget}
                        onChange={e=>setAssignGroupTarget(e.target.value)} placeholder="Enter group name"/>}
                  </div>
                </div>
              );
            })()}
            {actionModal==='delete' && (
              <div className="fpl-form">
                <p className="fpl-form-desc" style={{color:'var(--danger,#ef4444)'}}>
                  Permanently delete <strong>{n}</strong> finding{n!==1?'s':''} and all related data (comments, events)?
                  <br/><strong>This cannot be undone.</strong>
                </p>
              </div>
            )}
          </div>
          <div className="fd3-modal-footer">
            <button className="btn btn-secondary" onClick={closeModal} disabled={actionLoading}>Cancel</button>
            {actionModal==='delete'
              ? <button className="btn btn-danger" disabled={actionLoading} onClick={()=>void handleDelete()}
                  style={{background:'#ef4444',color:'#fff',borderColor:'#ef4444'}}>
                  {actionLoading ? 'Deleting…' : `Delete ${n} Finding${n!==1?'s':''}`}
                </button>
              : <button className="btn btn-primary" disabled={actionLoading}
                  onClick={()=>{
                    if (actionModal==='create-incident') void handleCreateIncident();
                    else if (actionModal==='defer') void handleDefer();
                    else if (actionModal==='resolve') void handleResolve();
                    else if (actionModal==='false-positive') void handleFalsePos();
                    else if (actionModal==='duplicate') void handleDuplicate();
                    else if (actionModal==='assign') void handleAssign();
                  }}>
                  {actionLoading ? 'Working…' : actionModal==='create-incident' ? 'Create Incident' : actionModal==='defer' ? 'Defer' : actionModal==='resolve' ? 'Resolve' : actionModal==='false-positive' ? 'Mark False Positive' : actionModal==='assign' ? 'Assign' : 'Mark Duplicate'}
                </button>
            }
          </div>
        </div>
      </div>
    );
  }

  function renderQueueDialog() {
    if (!queueDialogMode) return null;
    return (
      <div className="fd3-modal-overlay" onClick={e=>{if(e.target===e.currentTarget)closeQueueDialog();}}>
        <div className="fd3-modal" style={{maxWidth:460}}>
          <div className="fd3-modal-header">
            <span>{queueDialogMode === 'create' ? 'Save Current View' : 'Edit Saved Queue'}</span>
            <button className="fd3-modal-close" onClick={closeQueueDialog}>✕</button>
          </div>
          <div className="fd3-modal-body">
            {queueActionError && <div className="notice error" style={{marginBottom:12}}>{queueActionError}</div>}
            <div className="fpl-form">
              <div className="fpl-form-row">
                <label>Title</label>
                <input className="fpl-form-input" value={queueTitle} onChange={e=>setQueueTitle(e.target.value)} placeholder="Queue title"/>
              </div>
              <div className="fpl-form-row">
                <label>Description</label>
                <textarea className="fpl-form-textarea" rows={3} value={queueDescription} onChange={e=>setQueueDescription(e.target.value)} placeholder="Optional description"/>
              </div>
              <label className="fpl-col-filter-check" style={{marginTop:8}}>
                <input type="checkbox" checked={queueSetAsDefault} onChange={e=>setQueueSetAsDefault(e.target.checked)} />
                <span>Set as my default queue</span>
              </label>
              <div className="fpl-form-info">
                Saving the current workspace scope plus any active narrowing filters.
              </div>
            </div>
          </div>
          <div className="fd3-modal-footer">
            <button className="btn btn-secondary" onClick={closeQueueDialog} disabled={queueActionLoading}>Cancel</button>
            <button className="btn btn-primary" onClick={()=>void saveQueue()} disabled={queueActionLoading || queueTitle.trim().length === 0}>
              {queueActionLoading ? 'Saving…' : queueDialogMode === 'create' ? 'Save Queue' : 'Save Changes'}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── render ─────────────────────────────────────────────────────────────────

  return (
    <div className="fpl-root">
      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={refreshingResults}
        refreshLabel="Refreshing findings while keeping current results visible…"
      />
      {actionNotice && (
        <div className={`notice${actionNotice.tone === 'success' ? ' success' : ''}`} style={{ marginBottom: 12 }} role="status">
          {actionNotice.message}
        </div>
      )}
      {workspaceError && (
        <div className="notice error" style={{ marginBottom: 12 }}>
          {workspaceError.message}
        </div>
      )}
      {queueActionError && (
        <div className="notice error" style={{ marginBottom: 12 }}>
          {queueActionError}
        </div>
      )}
      {/* ── toolbar ────────────────────────────────────────────────────── */}
      <div className="fpl-toolbar">
        <div className="fpl-toolbar-left">
          <MultiGroupBy options={GROUP_OPTIONS} value={groupBy} onChange={setGroupBy}
            label="GROUP BY" placeholder="None" allowEmptyPrimary emptyPrimaryLabel="None" showSelectorsByDefault={false}/>

          {/* active filter chips */}
          {activeChips.length>0 && (
            <div className="fpl-active-chips">
              {activeChips.map((chip,i)=>(
                <span key={i} className="fpl-chip">
                  {chip.label}
                  <button onClick={chip.onRemove} aria-label="Remove filter">✕</button>
                </span>
              ))}
              {activeChips.length>1 && <button className="fpl-chip-clear" onClick={clearAllFilters}>Clear all</button>}
            </div>
          )}
        </div>
        <div className="fpl-toolbar-right">
          {queueActionTarget && (
            <>
              <button type="button" className="btn btn-secondary" onClick={() => openEditQueueDialog(queueActionTarget)}>
                Edit Queue
              </button>
              <button type="button" className="btn btn-secondary" onClick={() => void duplicateQueue(queueActionTarget)}>
                Duplicate Queue
              </button>
              {!queueActionTarget.isDefault && (
                <button type="button" className="btn btn-secondary" onClick={() => void setDefaultQueue(queueActionTarget)}>
                  Set Default
                </button>
              )}
              <button type="button" className="btn btn-secondary" onClick={() => void deleteQueue(queueActionTarget)}>
                Delete Queue
              </button>
            </>
          )}
          <button type="button" className="btn btn-secondary" onClick={openCreateQueueDialog}>
            Save Current View
          </button>
        </div>
      </div>

      <FindingsSummaryWidgets
        colFilters={colFilters}
        dueDateBand={dueDateBand}
        severityCounts={severityCounts}
        statusCounts={statusCounts}
        assetCounts={assetCounts}
        dueDateCounts={dueDateCounts}
        summary={summaryQuery.data}
        severityColors={SEV_COLORS}
        statusColors={STATUS_COLORS}
        formatLabel={fmt}
        onFilterBySeverity={filterBySeverity}
        onFilterByStatus={filterByStatus}
        onFilterByAsset={filterByAsset}
        onFilterByDueBand={filterByDueBand}
        onCriticalOpenClick={() => { setColFilters((p) => ({ ...p, severity: ['CRITICAL'], status: ['OPEN'] })); setDueDateBand(null); setPage(0); }}
        onUnassignedClick={() => { clearAllFilters(); setColFilters({ ...DEFAULT_COL_FILTERS, status: ['OPEN'] }); setUnassignedOnly(true); }}
        onWithIncidentsClick={() => { clearAllFilters(); setIncidentLinked(true); }}
      />

      {/* ── group breakdown ──────────────────────────────────────────────── */}
      {groupCards.length>0 && (
        <div className="fpl-group-row">
          {groupCards.map(g=>(
            <div className="fpl-group-card" key={g.key}>
              <div className="fpl-group-title">{g.label}</div>
              {g.items.map(({ key: v, count: c })=>(
                <button type="button" className="fpl-group-item" key={v}
                  aria-pressed={groupFilter?.field === g.key && groupFilter.value === v}
                  onClick={() => { clearAllFilters(); setGroupFilter({ field: g.key, value: v }); }}>
                  <span>{v}</span><strong>{c}</strong>
                </button>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* ── list controls bar ────────────────────────────────────────────── */}
      <div className="fpl-list-bar">
        <div className="fpl-list-bar-left">
          {/* Resolve — primary standalone action */}
          <button className={`fpl-action-btn fpl-action-btn--resolve${!hasSelection || !canMutateFindings?' fpl-action-btn--disabled':''}`}
            onClick={()=>openAction('resolve')} disabled={!hasSelection || !canMutateFindings}>Resolve</button>

          {/* More actions "..." dropdown */}
          <div className="fpl-more-wrap" ref={moreActionsRef}>
            <button className={`fpl-more-btn${showMoreActions?' fpl-more-btn--open':''}`}
              onClick={()=>setShowMoreActions(p=>!p)} title="More actions">
              <span className="fpl-more-dots">•••</span>
            </button>
            {showMoreActions && (
              <div className="fpl-more-menu">
                <button className="fpl-more-item" onClick={()=>openAction('create-incident')} disabled={!hasSelection || !canMutateFindings}>+ Create Incident</button>
                <button className="fpl-more-item" onClick={()=>openAction('defer')} disabled={!hasSelection || !canMutateFindings}>Defer</button>
                <button className="fpl-more-item" onClick={()=>openAction('false-positive')} disabled={!hasSelection || !canMutateFindings}>False Positive</button>
                <button className="fpl-more-item" onClick={()=>openAction('duplicate')} disabled={!hasSelection || !canMutateFindings}>Duplicate</button>
                <button className="fpl-more-item" onClick={()=>openAction('assign')} disabled={!hasSelection || !canMutateFindings}>Assign to…</button>
                <div className="fpl-more-sep"/>
                <button className="fpl-more-item" onClick={()=>void handleReopen()} disabled={!hasSelection || !canMutateFindings}>Re-open</button>
                <div className="fpl-more-sep"/>
                <button className="fpl-more-item fpl-more-item--danger" onClick={()=>openAction('delete')} disabled={!hasSelection || !canMutateFindings}
                  style={{color:'#ef4444'}}>Delete</button>
              </div>
            )}
          </div>

          {/* Selected count badge */}
          {selectedIds.size > 0 && (
            <span className="fpl-sel-badge">{selectedIds.size} selected</span>
          )}
        </div>

        <div className="fpl-list-bar-right">
          {/* Column visibility — gear icon */}
          <div className="fpl-colvis-wrap" ref={colVisRef}>
            <button className={`fpl-colvis-btn${showColVis?' fpl-colvis-btn--open':''}`}
              onClick={()=>{setShowColVis(p=>!p);setOpenColFilter(null);}} title="Column settings">
              <svg viewBox="0 0 20 20" width="15" height="15" fill="currentColor" aria-hidden>
                <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd"/>
              </svg>
            </button>
            {showColVis && (
              <div className="fpl-colvis-popover fpl-colvis-popover--right">
                <div className="fpl-colvis-header"><span>VISIBLE COLUMNS</span><button className="fpl-col-filter-clear" onClick={()=>saveColVis(new Set(DEFAULT_VISIBLE))}>Reset</button></div>
                {ALL_COLUMNS.filter(c=>!c.alwaysVisible).map(c=>(
                  <label key={c.key} className="fpl-colvis-item">
                    <input type="checkbox" checked={visibleCols.has(c.key)} onChange={()=>{
                      const n = new Set(visibleCols);
                      if (n.has(c.key)) {
                        n.delete(c.key);
                      } else {
                        n.add(c.key);
                      }
                      saveColVis(n);
                    }}/>
                    <span>{c.label}</span>
                  </label>
                ))}
              </div>
            )}
          </div>

        </div>
      </div>

      {/* ── main table ───────────────────────────────────────────────────── */}
      <div className="fpl-table-wrap">
        {findingsQuery.error && <div className="notice error">Failed to load findings: {String(findingsQuery.error)}</div>}
        {refreshingResults && rows.length > 0 ? (
          <div className="notice" role="status" style={{ marginBottom: 12 }}>
            Updating results for the active filters. Current rows stay visible until the refresh completes.
          </div>
        ) : null}

        <div className="fpl-table-scroll">
          <table className="fpl-table">
            <thead>
              <tr>
                <th className="fpl-th fpl-th--check">
                  <input type="checkbox" checked={allSelected}
                    ref={el=>{if(el) el.indeterminate=selectedIds.size>0&&!allSelected;}}
                    onChange={toggleSelectAll} aria-label="Select all"/>
                </th>
                {visColDefs.map(c=><ColHeader key={c.key} colKey={c.key} label={c.label}/>)}
              </tr>
            </thead>
            <tbody>
              {initialLoading && rows.length===0 ? (
                <tr><td colSpan={visColDefs.length+1} className="fpl-loading-row">Loading findings…</td></tr>
              ) : rows.length===0 ? (
                <tr><td colSpan={visColDefs.length+1} className="fpl-empty-row">
                  {(findingsQuery.data?.totalItems ?? 0) === 0 && activeChips.length === 0 ? (
                    <div className="empty-state-inline">
                      <strong>No findings yet</strong>
                      <p>Findings are generated when ingested vulnerabilities are correlated with your software inventory.</p>
                      <Link to={pathForConnectView('sources')} className="btn btn-secondary btn-inline">Configure Sources</Link>
                    </div>
                  ) : (
                    <>
                      No findings matched the current filters.{' '}
                      {activeChips.length>0 && <button className="fpl-link-btn" onClick={clearAllFilters}>Clear filters</button>}
                    </>
                  )}
                </td></tr>
              ) : rows.map(row=>(
                <tr key={row.id} className={`fpl-tr${selectedIds.has(row.id)?' fpl-tr--selected':''}`} onClick={()=>toggleSelect(row.id)}>
                  <td className="fpl-td fpl-td--check" onClick={e=>e.stopPropagation()}>
                    <input type="checkbox" checked={selectedIds.has(row.id)} onChange={()=>toggleSelect(row.id)} aria-label="Select row"/>
                  </td>
                  {visColDefs.map(c=>(
                    <td key={c.key} className="fpl-td"
                      onClick={c.key==='findingId'||c.key==='cveId'?e=>e.stopPropagation():undefined}>
                      {renderCell(row,c.key)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="fpl-pagination">
          <button className="btn btn-secondary btn-inline" disabled={page<=0||loading} onClick={()=>setPage(p=>Math.max(0,p-1))}>← Prev</button>
          <span className="fpl-page-info">
            {totalItems===0 ? 'No results' : `Page ${page+1} of ${Math.max(1,totalPages)} · ${totalItems.toLocaleString()} findings`}
          </span>
          <button
            className="btn btn-secondary btn-inline"
            disabled={loading || !nextCursor}
            onClick={() => {
              if (!nextCursor) return;
              setPageCursors((prev) => {
                if (prev[page + 1] === nextCursor) {
                  return prev;
                }
                const next = prev.slice(0, page + 1);
                next.push(nextCursor);
                return next;
              });
              setPage(p => p + 1);
            }}
          >
            Next →
          </button>
        </div>
      </div>

      {renderModal()}
      {renderQueueDialog()}
    </div>
  );
}
