import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolBadge } from '../components/EolBadge';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import {
  VulnRepoCveAssessmentWorkbench,
} from '../components/VulnRepoCveAssessmentWorkbench';
import {
  CveDetail,
  OrgCveAutomationStatus,
  OrgSpecificCveExposureRecord
} from '../features/cve-workbench/types';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import {
  useCveDetailQuery,
  useOrgSpecificCveAutomationStatusQuery,
  useOrgSpecificCvesQuery,
  useRiskPolicyQuery
} from '../features/cve-workbench/queries';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import { useActor } from '../features/auth/context';
import { canRefreshTenantExposure } from '../features/auth/roles';
import { api } from '../api/client';
import { computeCveRiskScore, computeOrgImpact, riskScoreLabel } from '../lib/riskScoring';

const PAGE_SIZE = 25;
const WORKBENCH_LABEL = 'Unified Vulnerability Records';
const ORG_CVE_COLUMNS: DataTableColumn[] = [
  { id: 'cve', label: 'CVE', header: 'CVE', initialSize: 180 },
  { id: 'title', label: 'Title', header: 'Title', initialSize: 280 },
  { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 120 },
  { id: 'cvss', label: 'CVSS', header: 'CVSS', initialSize: 100 },
  { id: 'epss', label: 'EPSS', header: 'EPSS', initialSize: 100 },
  { id: 'cveRisk', label: 'Scout Risk', header: 'Scout Risk', initialSize: 110 },
  { id: 'applicability', label: 'Applicability', header: 'Applicability', initialSize: 160 },
  { id: 'orgImpact', label: 'Impact', header: 'Impact', initialSize: 130 },
  { id: 'matched', label: 'Matched Software / Assets', header: 'Matched Software / Assets', initialSize: 200 },
  { id: 'eol', label: 'EOL', header: 'EOL', initialSize: 120 },
  { id: 'eos', label: 'EOS', header: 'EOS', initialSize: 120 },
  { id: 'openFindings', label: 'Open Findings', header: 'Open Findings', initialSize: 120 },
  { id: 'suppression', label: 'Suppression', header: 'Suppression', initialSize: 160 },
  { id: 'lastEvaluated', label: 'Last Evaluated', header: 'Last Evaluated', initialSize: 180 }
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

function applicabilityClass(value: OrgSpecificCveExposureRecord['applicability']): string {
  if (value === 'APPLICABLE') {
    return 'status-open';
  }
  if (value === 'NOT_APPLICABLE') {
    return 'status-auto_closed';
  }
  return 'status-suppressed';
}


function vexEvidenceCategory(item: OrgSpecificCveExposureRecord): 'VEX_BACKED' | 'RESOLVED_BY_VEX' | 'AWAITING_VEX' | 'NONE' {
  if (item.impactedComponentCount > 0 || item.noPatchComponentCount > 0) {
    return 'VEX_BACKED';
  }
  if (item.fixedComponentCount > 0 || item.notAffectedComponentCount > 0 || item.underInvestigationComponentCount > 0) {
    return 'RESOLVED_BY_VEX';
  }
  if (item.applicableComponentCount > 0 || item.unknownComponentCount > 0) {
    return 'AWAITING_VEX';
  }
  return 'NONE';
}

function buildFallbackRecord(detail: CveDetail, externalId: string): OrgSpecificCveExposureRecord {
  const matchedSoftwareCount = new Set(
    detail.matchedSoftware.map((item) => `${item.packageName}|${item.version ?? ''}`)
  ).size;
  const matchedAssetCount = new Set(
    detail.matchedSoftware.map((item) => item.assetId ?? item.assetIdentifier ?? item.componentId)
  ).size;
  const applicableComponentCount = detail.matchedSoftware.filter((item) => item.applicabilityState === 'APPLICABLE').length;
  const impactedComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'IMPACTED').length;
  const notAffectedComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'NOT_IMPACTED').length;
  const fixedComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'FIXED').length;
  const noPatchComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'NO_PATCH').length;
  const underInvestigationComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'UNDER_INVESTIGATION').length;
  const unknownComponentCount = detail.matchedSoftware.filter((item) => item.impactState === 'UNKNOWN').length;
  const severity = detail.summary.severity || 'UNKNOWN';
  const impactState: OrgSpecificCveExposureRecord['impactState'] = impactedComponentCount > 0
    ? 'IMPACTED'
    : noPatchComponentCount > 0
      ? 'NO_PATCH'
      : fixedComponentCount > 0
        ? 'FIXED'
        : notAffectedComponentCount > 0
          ? 'NOT_IMPACTED'
          : underInvestigationComponentCount > 0
            ? 'UNDER_INVESTIGATION'
            : 'UNKNOWN';
  const applicability: OrgSpecificCveExposureRecord['applicability'] = applicableComponentCount > 0
    ? 'APPLICABLE'
    : detail.matchedSoftware.length > 0
      ? 'UNKNOWN'
      : 'NOT_APPLICABLE';

  return {
    recordId: `fallback:${externalId}`,
    vulnerabilityId: externalId,
    externalId,
    title: detail.summary.title || externalId,
    descriptionSnippet: detail.summary.description,
    applicability,
    impacted: impactedComponentCount > 0 || noPatchComponentCount > 0,
    impactState,
    severity,
    cvssScore: detail.summary.cvssScore,
    epssScore: detail.summary.epssScore,
    inKev: Boolean(detail.summary.inKev),
    matchedComponentCount: detail.matchedSoftware.length,
    matchedSoftwareCount,
    matchedAssetCount,
    applicableComponentCount,
    impactedComponentCount,
    notAffectedComponentCount,
    fixedComponentCount,
    noPatchComponentCount,
    underInvestigationComponentCount,
    unknownComponentCount,
    openFindings: 0,
    lastEvaluatedAt: detail.summary.modifiedAt,
    eolComponentCount: 0,
    eosComponentCount: 0,
    hasInvestigationSummary: false,
    hasAiSolution: false,
  };
}

type VulnRepoOrgCvePageProps = {
  initialCveId?: string;
  onSelectedCveChange?: (cveId?: string) => void;
  returnTo?: string;
};

export function VulnRepoOrgCvePage({
  initialCveId,
  onSelectedCveChange,
  returnTo
}: VulnRepoOrgCvePageProps = {}) {
  const actor = useActor();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const euvdContextId = searchParams.get('euvdId') ?? undefined;
  const jvndbContextId = searchParams.get('jvndbId') ?? undefined;
  const queryClient = useQueryClient();
  const [page, setPage] = React.useState(0);
  const [queryInput, setQueryInput] = React.useState('');
  const [query, setQuery] = React.useState('');
  const [evidenceFilter, setEvidenceFilter] = React.useState<'ALL' | 'VEX_BACKED' | 'RESOLVED_BY_VEX' | 'AWAITING_VEX'>('ALL');
  const [kevFilter, setKevFilter] = React.useState<'ALL' | 'KEV_ONLY' | 'NON_KEV'>('ALL');
  const [selectedRecord, setSelectedRecord] = React.useState<OrgSpecificCveExposureRecord | null>(null);
  const automationStatusRef = React.useRef<OrgCveAutomationStatus | null>(null);
  const orgCveQuery = useOrgSpecificCvesQuery({
    page,
    size: PAGE_SIZE,
    query,
    inKev: kevFilter === 'ALL' ? undefined : kevFilter === 'KEV_ONLY'
  });
  const automationStatusQuery = useOrgSpecificCveAutomationStatusQuery();
  const policyQuery = useRiskPolicyQuery();
  const detailTargetCveId = selectedRecord?.externalId ?? initialCveId ?? null;
  const detailQuery = useCveDetailQuery(detailTargetCveId);
  const loading = orgCveQuery.isLoading || orgCveQuery.isFetching;
  const error = orgCveQuery.error instanceof Error ? orgCveQuery.error.message : null;
  const summary = orgCveQuery.data?.summary ?? null;
  const items = React.useMemo(() => orgCveQuery.data?.items ?? [], [orgCveQuery.data?.items]);
  const refreshing = orgCveQuery.isFetching && items.length > 0;
  const totalPages = orgCveQuery.data?.totalPages ?? 0;
  const selectedDetail = detailQuery.data ?? null;
  const detailLoading = detailQuery.isLoading || detailQuery.isFetching;
  const detailError = detailQuery.error instanceof Error ? detailQuery.error.message : null;
  const canRefreshExposure = canRefreshTenantExposure(actor);
  const latestDataUpdate = React.useMemo(() => latestFreshnessValue([
    orgCveQuery.dataUpdatedAt,
    automationStatusQuery.dataUpdatedAt,
  ]), [
    automationStatusQuery.dataUpdatedAt,
    orgCveQuery.dataUpdatedAt,
  ]);
  const refreshExposureMutation = useMutation({
    mutationFn: cveWorkbenchApi.refreshTenantExposure,
    onSuccess: async () => {
      await Promise.all([
        orgCveQuery.refetch(),
        policyQuery.refetch(),
        automationStatusQuery.refetch()
      ]);
    }
  });

  const [reopeningId, setReopeningId] = React.useState<string | null>(null);

  const openRecord = React.useCallback((record: OrgSpecificCveExposureRecord) => {
    setSelectedRecord(record);
  }, []);

  const handleReopenCve = React.useCallback(async (recordId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setReopeningId(recordId);
    try {
      await api.reopenCveRecord(recordId);
      await orgCveQuery.refetch();
    } finally {
      setReopeningId(null);
    }
  }, [orgCveQuery]);

  React.useEffect(() => {
    if (!initialCveId) {
      return;
    }
    setPage(0);
    setQueryInput(initialCveId);
    setQuery(initialCveId);
  }, [initialCveId]);

  // Auto-open a specific CVE when navigated from FindingsPage
  const initialCveHandledRef = React.useRef(false);
  React.useEffect(() => {
    const requestedCveId = initialCveId;
    if (!requestedCveId || initialCveHandledRef.current || loading || items.length === 0) return;
    const record = items.find((item) => item.externalId === requestedCveId);
    if (record) {
      initialCveHandledRef.current = true;
      openRecord(record);
    }
  }, [initialCveId, items, loading, openRecord]);

  React.useEffect(() => {
    const requestedCveId = initialCveId;
    if (!requestedCveId || initialCveHandledRef.current || loading) return;
    if (selectedRecord?.externalId === requestedCveId) {
      initialCveHandledRef.current = true;
      return;
    }
    if (!detailQuery.data) return;
    initialCveHandledRef.current = true;
    setSelectedRecord(buildFallbackRecord(detailQuery.data, requestedCveId));
  }, [detailQuery.data, initialCveId, loading, selectedRecord?.externalId]);

  React.useEffect(() => {
    setSelectedRecord((current) => {
      if (!current) {
        return current;
      }
      return items.find((item) => item.recordId === current.recordId) ?? current;
    });
  }, [items]);

  React.useEffect(() => {
    onSelectedCveChange?.(selectedRecord?.externalId);
  }, [onSelectedCveChange, selectedRecord]);

  React.useEffect(() => {
    const nextStatus = automationStatusQuery.data;
    if (!nextStatus) {
      return;
    }
    const previousStatus = automationStatusRef.current;
    automationStatusRef.current = nextStatus;

    const queueDrained = (previousStatus?.pendingEventCount ?? 0) > 0 && nextStatus.pendingEventCount === 0;
    const evaluationAdvanced = previousStatus?.latestOrgCveEvaluatedAt != null
      && previousStatus.latestOrgCveEvaluatedAt !== nextStatus.latestOrgCveEvaluatedAt;

    if (queueDrained || evaluationAdvanced) {
      void orgCveQuery.refetch();
      if (selectedRecord?.externalId) {
        void queryClient.invalidateQueries({ queryKey: ['cve-detail', selectedRecord.externalId] });
      }
    }
  }, [automationStatusQuery.data, orgCveQuery, queryClient, selectedRecord?.externalId]);

  // Back from workbench: if opened via returnTo, navigate back; otherwise clear workbench state
  const closeDrawer = React.useCallback(() => {
    if (returnTo) {
      navigate(returnTo);
      return;
    }
    setSelectedRecord(null);
    void Promise.all([
      orgCveQuery.refetch(),
      policyQuery.refetch(),
      automationStatusQuery.refetch()
    ]);
  }, [automationStatusQuery, navigate, orgCveQuery, policyQuery, returnTo]);

  // Mid-session refresh inside workbench: detail by default, with optional row/list refresh for finding mutations.
  const refreshDetail = React.useCallback(async (options?: { includeList?: boolean }) => {
    const tasks: Array<Promise<unknown>> = [
      policyQuery.refetch(),
      automationStatusQuery.refetch(),
      selectedRecord ? detailQuery.refetch() : Promise.resolve()
    ];
    if (options?.includeList) {
      tasks.push(orgCveQuery.refetch());
    }
    await Promise.all(tasks);
  }, [automationStatusQuery, detailQuery, orgCveQuery, policyQuery, selectedRecord]);

  const visibleItems = React.useMemo(() => (
    evidenceFilter === 'ALL'
      ? items
      : items.filter((item) => vexEvidenceCategory(item) === evidenceFilter)
  ), [evidenceFilter, items]);
  const tableRows = React.useMemo<DataTableRow[]>(() => (
    visibleItems.map((item) => ({
      id: item.recordId,
      rowProps: {
        className: `org-cve-row ${selectedRecord?.recordId === item.recordId ? 'table-row-selected' : ''}`.trim(),
        onClick: () => openRecord(item),
        tabIndex: 0,
        onKeyDown: (event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            openRecord(item);
          }
        }
      },
      cells: (() => {
        const riskResult = computeCveRiskScore(item, policyQuery.data);
        const orgImpact = computeOrgImpact(item, riskResult.score, 0);
        const orgImpactStyle: React.CSSProperties =
          orgImpact === 'HIGH'
            ? { background: '#9b233522', color: '#9b2335', border: '1px solid #9b233544' }
            : orgImpact === 'MEDIUM'
              ? { background: '#b7791f22', color: '#b7791f', border: '1px solid #b7791f44' }
              : orgImpact === 'LOW'
                ? { background: '#2d6a4f22', color: '#2d6a4f', border: '1px solid #2d6a4f44' }
                : { background: 'var(--dp-surface-2)', color: 'var(--dp-text-2)', border: '1px solid var(--dp-border)' };
        const orgImpactLabel = orgImpact === 'NONE' ? 'No' : orgImpact.charAt(0) + orgImpact.slice(1).toLowerCase();
        return {
        cve: {
          content: (
            <>
              <button type="button" className="org-cve-link-btn" onClick={() => openRecord(item)}>
                <span className="mono">{item.externalId}</span>
                {item.euvdId && (
                  <span className="mono euvd-id-badge" title={`EUVD ID: ${item.euvdId}`}>
                    {item.euvdId}
                  </span>
                )}
              </button>
              {item.inKev && (
                <span className="cve-source-badge kev org-cve-kev-badge" title="CISA Known Exploited Vulnerabilities catalog">
                  KEV
                </span>
              )}
            </>
          )
        },
        title: { content: <div className="org-cve-title-cell">{item.title}</div> },
        severity: { content: <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span> },
        cvss: { content: item.cvssScore?.toFixed(1) ?? '-' },
        epss: { content: item.epssScore != null ? `${(item.epssScore * 100).toFixed(1)}%` : '-' },
        cveRisk: {
          content: (
            <span
              className={`risk-score-badge risk-score-badge--${riskScoreLabel(riskResult.score).toLowerCase()}`}
              title={riskResult.topReasons.join(' · ')}
            >
              {riskResult.score.toFixed(1)}
            </span>
          )
        },
        applicability: {
          content: (
            <span className={`status-pill ${applicabilityClass(item.applicability)}`}>
              {formatLabel(item.applicability)}
            </span>
          )
        },
        orgImpact: {
          content: (
            <span style={{
              display: 'inline-block', padding: '2px 10px', borderRadius: 12,
              fontSize: 11, fontWeight: 700, letterSpacing: '0.04em',
              ...orgImpactStyle,
            }}>
              {orgImpactLabel}
            </span>
          )
        },
        matched: {
          content: (
            <>
              {item.matchedSoftwareCount.toLocaleString()}
              <div className="panel-caption">{item.matchedAssetCount.toLocaleString()} assets</div>
            </>
          )
        },
        eol: {
          content: (
            <>
              {item.eolComponentCount > 0
                ? <EolBadge isEol={true} />
                : <span className="cve-muted">—</span>}
              {item.eolComponentCount > 0 && (
                <div className="panel-caption">{item.eolComponentCount} component{item.eolComponentCount !== 1 ? 's' : ''}</div>
              )}
            </>
          )
        },
        eos: {
          content: (
            <>
              {item.eosComponentCount > 0
                ? <span className="eol-badge eol-badge-warn">EOS</span>
                : <span className="cve-muted">—</span>}
              {item.eosComponentCount > 0 && (
                <div className="panel-caption">{item.eosComponentCount} component{item.eosComponentCount !== 1 ? 's' : ''}</div>
              )}
            </>
          )
        },
        openFindings: { content: item.openFindings.toLocaleString() },
        suppression: {
          content: item.suppressedByRuleId ? (
            <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span style={{
                display: 'inline-block', padding: '1px 7px', borderRadius: 10,
                fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.04em',
                background: '#f59e0b22', color: '#b45309', border: '1px solid #f59e0b44',
              }}>
                Suppressed
              </span>
              <span style={{ fontSize: '0.7rem', color: 'var(--dp-medium)' }}>{item.suppressedByRuleName}</span>
              <button
                type="button"
                style={{ fontSize: '0.7rem', padding: '1px 6px', cursor: 'pointer', marginTop: 2, border: '1px solid var(--dp-border)', borderRadius: 4, background: 'var(--dp-surface-2)', color: 'var(--dp-text)' }}
                disabled={reopeningId === item.recordId}
                onClick={(e) => void handleReopenCve(item.recordId, e)}
              >
                {reopeningId === item.recordId ? '…' : 'Reopen'}
              </button>
            </span>
          ) : <span className="cve-muted">—</span>
        },
        lastEvaluated: { content: formatDateTime(item.lastEvaluatedAt) }
        };
      })()
    }
  ))
  ), [handleReopenCve, openRecord, policyQuery.data, reopeningId, selectedRecord?.recordId, visibleItems]);

  if (selectedRecord) {
    return (
      <VulnRepoCveAssessmentWorkbench
        key={selectedRecord.externalId}
        item={selectedRecord}
        detail={selectedDetail}
        loading={detailLoading}
        error={detailError}
        analystId={actor?.userId ?? undefined}
        onBack={closeDrawer}
        onRefreshDetail={refreshDetail}
        euvdId={euvdContextId}
        jvndbId={jvndbContextId}
      />
    );
  }

  return (
    <section className="panel ui2-cve-family">
        <PageFreshnessStatus
          updatedAt={latestDataUpdate}
          isRefreshing={refreshing}
          refreshLabel="Refreshing investigation queue while keeping current rows visible…"
        />

        <div className="panel-header">
          <div>
            {returnTo && (
              <button
                type="button"
                className="btn btn-secondary cve-back-to-asset-btn"
                onClick={() => navigate(returnTo)}
              >
                ← Back to asset
              </button>
            )}
            <h3>{WORKBENCH_LABEL}</h3>
          </div>
          <div className="button-row">
            {canRefreshExposure && (
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => refreshExposureMutation.mutate()}
                disabled={refreshExposureMutation.isPending}
                title="Refresh tenant exposure from the current central vulnerability repository"
              >
                {refreshExposureMutation.isPending ? 'Queueing...' : 'Refresh My Exposure'}
              </button>
            )}
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => void Promise.all([orgCveQuery.refetch(), policyQuery.refetch(), automationStatusQuery.refetch()])}
              disabled={loading}
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {refreshExposureMutation.isSuccess && (
          <div className="notice">
            Tenant exposure refresh queued from the current central vulnerability repository.
          </div>
        )}
        {refreshExposureMutation.isError && (
          <div className="notice error" role="alert">
            {refreshExposureMutation.error instanceof Error ? refreshExposureMutation.error.message : 'Failed to queue tenant exposure refresh'}
          </div>
        )}


        {summary && (
          <div className="org-cve-hero-stats">
            <div className="org-cve-score-card">
              <span>Review Queue CVEs</span>
              <strong>{summary.reviewQueueCount.toLocaleString()}</strong>
            </div>
            <div className="org-cve-score-card">
              <span>Applicable CVEs</span>
              <strong>{summary.applicableCount.toLocaleString()}</strong>
            </div>
            <div className="org-cve-score-card">
              <span>Impacted CVEs</span>
              <strong>{summary.impactedCount.toLocaleString()}</strong>
            </div>
            <div className="org-cve-score-card">
              <span>Under Investigation</span>
              <strong>{summary.underInvestigationCount.toLocaleString()}</strong>
            </div>
            <div className="org-cve-score-card">
              <span>Resolved CVEs</span>
              <strong>{summary.resolvedCount.toLocaleString()}</strong>
            </div>
          </div>
        )}

        <div className="org-cve-filter-row">
          <div className="findings-filter-chip org-cve-filter-chip">
            <label htmlFor="org-cve-search">Search CVE / Title / Severity</label>
            <input
              id="org-cve-search"
              value={queryInput}
              onChange={(event) => setQueryInput(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault();
                  setPage(0);
                  setQuery(queryInput.trim());
                }
              }}
              placeholder="CVE-2024-21762, FortiOS, critical"
            />
          </div>
          <div className="findings-filter-chip org-cve-filter-chip">
            <label htmlFor="org-cve-vex-filter">Impact Evidence</label>
            <select
              id="org-cve-vex-filter"
              value={evidenceFilter}
              onChange={(event) => setEvidenceFilter(event.target.value as 'ALL' | 'VEX_BACKED' | 'RESOLVED_BY_VEX' | 'AWAITING_VEX')}
            >
              <option value="ALL">All evidence states</option>
              <option value="VEX_BACKED">VEX-backed impact</option>
              <option value="RESOLVED_BY_VEX">Resolved by VEX</option>
              <option value="AWAITING_VEX">Awaiting exact VEX</option>
            </select>
          </div>
          <div className="findings-filter-chip org-cve-filter-chip">
            <label htmlFor="org-cve-kev-filter">KEV Status</label>
            <select
              id="org-cve-kev-filter"
              value={kevFilter}
              onChange={(event) => {
                setPage(0);
                setKevFilter(event.target.value as 'ALL' | 'KEV_ONLY' | 'NON_KEV');
              }}
            >
              <option value="ALL">All CVEs</option>
              <option value="KEV_ONLY">KEV only</option>
              <option value="NON_KEV">Non-KEV only</option>
            </select>
          </div>
          <div className="button-row org-cve-filter-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setPage(0);
                setQuery(queryInput.trim());
              }}
              disabled={loading}
            >
              Apply
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setPage(0);
                setQueryInput('');
                setQuery('');
                setEvidenceFilter('ALL');
                setKevFilter('ALL');
              }}
              disabled={loading && query.length === 0 && evidenceFilter === 'ALL' && kevFilter === 'ALL'}
            >
              Clear
            </button>
          </div>
        </div>

        {error && <div className="notice error">Failed to load vulnerability investigation records: {error}</div>}

        {loading && items.length === 0 ? (
          <div className="notice">Loading vulnerability investigation records...</div>
        ) : items.length === 0 ? (
          <div className="empty-state">
            <p>No review-queue CVEs found.</p>
            <p>
              This view only shows CVEs with inventory-correlated applicability or exact VEX-backed impacted and no-patch states. If you have already ingested inventory and vulnerability data, the review queue updates automatically in the background. If filters are active, try clearing them first.
            </p>
          </div>
        ) : visibleItems.length === 0 ? (
          <div className="empty-state">
            <p>No CVEs matched the current impact-evidence filter on this page.</p>
            <p>Try switching the filter back to <strong>All evidence states</strong> or loading another page.</p>
          </div>
        ) : (
          <>
            <div className="table-scroll">
              <DataTable
                storageKey="vuln-intel-org-cve-table-widths"
                columns={ORG_CVE_COLUMNS}
                rows={tableRows}
              />
            </div>

            <div className="pagination-row">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage((current) => Math.max(0, current - 1))}
                disabled={page <= 0 || loading}
              >
                Previous
              </button>
              <span className="panel-caption pagination-caption">
                {items.length === 0 ? 'No results' : `Page ${page + 1} of ${totalPages}`}
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage((current) => (current + 1 < totalPages ? current + 1 : current))}
                disabled={loading || totalPages === 0 || page + 1 >= totalPages}
              >
                Next
              </button>
            </div>
          </>
        )}
    </section>
  );
}
