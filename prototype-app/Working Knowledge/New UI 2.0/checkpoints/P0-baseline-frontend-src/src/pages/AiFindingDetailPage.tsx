import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { pathForAiFindings, pathForInventoryAiAsset, pathForPolicyDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { severityClassName, formatLabel } from '../features/cve-workbench/formatting';
import type { ServiceNowIncidentResponse } from '../features/cve-workbench/types';
import { InventoryOverviewPanel, type OverviewField } from '../features/inventory/InventoryOverviewPanel';

type AiFindingDetailPageProps = {
  findingId: string;
};

type AiFindingDetailTab = 'overview' | 'artifact';

function fmtDt(value?: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatFactValue(value: unknown): string {
  if (Array.isArray(value)) return value.length === 0 ? 'None' : `${value.length} item${value.length === 1 ? '' : 's'}`;
  if (typeof value === 'object' && value != null) return JSON.stringify(value);
  if (value == null || value === '') return 'Not observed';
  return String(value);
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fd3-panel">
      <div className="fd3-panel-title">{title}</div>
      <div className="fd3-panel-body">{children}</div>
    </div>
  );
}

function KVRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{label}</span>
      <span className="fd3-kv-val">{children ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}

export function AiFindingDetailPage({ findingId }: AiFindingDetailPageProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const actor = useActor();
  const canManageWorkflow = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'SECURITY_ANALYST');
  const canCreateIncident = hasRole(actor, 'PLATFORM_OWNER') || hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'SECURITY_ANALYST');
  const [tab, setTab] = React.useState<AiFindingDetailTab>('overview');
  const [incidentResult, setIncidentResult] = React.useState<ServiceNowIncidentResponse | null>(null);
  const returnTo = searchParams.get('returnTo')?.trim() || (
    typeof location.state === 'object' && location.state && 'returnTo' in location.state
      ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
      : ''
  ) || pathForAiFindings();

  const findingQuery = useQuery({
    queryKey: ['ai-security-finding', findingId],
    queryFn: () => api.getAiSecurityFinding(findingId),
  });
  const policiesQuery = useQuery({
    queryKey: ['ai-security-policies'],
    queryFn: api.listAiGridPolicyDetails,
  });
  const reviewMutation = useMutation({
    mutationFn: (disposition: 'CONFIRMED' | 'FALSE_POSITIVE' | 'NEEDS_INVESTIGATION') =>
      api.reviewAiSecurityFinding(findingId, disposition),
    onSuccess: (updated) => {
      queryClient.setQueryData(['ai-security-finding', findingId], updated);
      void queryClient.invalidateQueries({ queryKey: ['ai-security-findings'] });
    },
  });
  const workflowMutation = useMutation({
    mutationFn: (status: 'RESOLVED' | 'OPEN') =>
      api.updateFindingWorkflow(findingId, { status, actor: actor?.principal }),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-finding', findingId] }),
  });
  const incidentMutation = useMutation({
    mutationFn: () => {
      const current = findingQuery.data;
      if (!current) throw new Error('Finding not loaded yet');
      return api.createFindingIncident(findingId, {
        findingTitle: current.title,
        severity: current.severity,
        inKev: false,
        priority: current.severity,
        affectedAssets: [],
      });
    },
    onSuccess: (response) => setIncidentResult(response),
  });

  const finding = findingQuery.data ?? null;
  const policy = React.useMemo(
    () => (policiesQuery.data ?? []).find((candidate) => candidate.id === finding?.policyId) ?? null,
    [policiesQuery.data, finding?.policyId],
  );

  const artifactQuery = useQuery({
    queryKey: ['ai-security-artifact', finding?.artifactId],
    queryFn: () => api.getAiSecurityArtifact(finding!.artifactId!),
    enabled: tab === 'artifact' && !!finding?.artifactId,
  });
  const artifact = artifactQuery.data ?? null;
  const artifactPrimaryFields = React.useMemo<OverviewField[]>(() => {
    if (!artifact) return [];
    return [
      { label: 'Provider', value: artifact.provider },
      { label: 'Native type', value: formatLabel(artifact.nativeKind) },
      { label: 'Account', value: artifact.accountId },
      { label: 'Region', value: artifact.region },
      { label: 'Provider ID', value: <span className="mono">{artifact.providerResourceId}</span> },
      { label: 'First observed', value: fmtDt(artifact.firstObservedAt) },
      { label: 'Last observed', value: fmtDt(artifact.lastObservedAt) },
      { label: 'Owner', value: artifact.ownerName ?? 'Unowned' },
      { label: 'Owner state', value: artifact.ownerState ?? 'UNOWNED' },
    ];
  }, [artifact]);
  const artifactSecondaryFields = React.useMemo<OverviewField[]>(() => {
    if (!artifact) return [];
    return Object.entries(artifact.attributes).map(([key, value]) => ({
      label: key.replace(/([A-Z_])/g, ' $1'),
      value: formatFactValue(value),
    }));
  }, [artifact]);

  const handleBack = React.useCallback(() => navigate(returnTo), [navigate, returnTo]);

  if (findingQuery.isLoading) {
    return (
      <div className="fd3-page">
        <div className="empty-state"><p>Loading AI finding…</p></div>
      </div>
    );
  }

  if (findingQuery.isError || !finding) {
    return (
      <div className="fd3-page">
        <div className="empty-state">
          <p>This AI finding could not be found.</p>
          <button type="button" className="btn btn-secondary" onClick={handleBack}>← Back to AI Findings</button>
        </div>
      </div>
    );
  }

  return (
    <div className="fd3-page">
      {finding.exposurePaths?.length ? <nav aria-label="Associated exposure paths">{finding.exposurePaths.map((path) => <a key={path.id} href={`/findings/ai/exposures/${path.id}`}>{path.title} · {formatLabel(path.state)}</a>)}</nav> : null}
      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <div className="fd3-topbar">
        <button className="fd3-back-btn" onClick={handleBack}>← Back</button>
        <span className="fd3-finding-id mono">{finding.displayId}</span>
        {finding.findingKind === 'AI_EXPOSURE' ? <span className="status-pill">Exposure</span> : null}
        <span className={severityClassName(finding.severity)}>{finding.severity}</span>
        <span className="status-pill">{finding.status.replace(/_/g, ' ')}</span>
        <div style={{ flex: 1 }} />
        <div className="fd3-actions">
          {canCreateIncident && (
            <button
              className="fd3-action-btn fd3-action-btn--incident"
              disabled={incidentMutation.isPending}
              onClick={() => incidentMutation.mutate()}
            >
              + Create Incident
            </button>
          )}
          {canManageWorkflow && (
            finding.status === 'OPEN' ? (
              <button
                className="fd3-action-btn"
                disabled={workflowMutation.isPending}
                onClick={() => workflowMutation.mutate('RESOLVED')}
              >
                Resolve
              </button>
            ) : (
              <button
                className="fd3-action-btn fd3-action-btn--reopen"
                disabled={workflowMutation.isPending}
                onClick={() => workflowMutation.mutate('OPEN')}
              >
                Re-open
              </button>
            )
          )}
          <button
            className="fd3-action-btn"
            disabled={reviewMutation.isPending}
            onClick={() => reviewMutation.mutate('CONFIRMED')}
          >
            Confirm
          </button>
          <button
            className="fd3-action-btn"
            disabled={reviewMutation.isPending}
            onClick={() => reviewMutation.mutate('NEEDS_INVESTIGATION')}
          >
            Investigate
          </button>
          <button
            className="fd3-action-btn fd3-action-btn--fp"
            disabled={reviewMutation.isPending}
            onClick={() => reviewMutation.mutate('FALSE_POSITIVE')}
          >
            False Positive
          </button>
        </div>
      </div>

      {(incidentMutation.isError || incidentResult || workflowMutation.isError) && (
        <div className="fd3-topbar" style={{ borderTop: 'none' }}>
          {incidentMutation.isError && (
            <div className="notice error">Incident could not be created: {String(incidentMutation.error)}</div>
          )}
          {incidentResult && incidentResult.status === 'created' && (
            <div className="notice success">
              Incident {incidentResult.incidentNumber} created.
              {incidentResult.url && <> <a href={incidentResult.url} target="_blank" rel="noreferrer">Open in ServiceNow →</a></>}
            </div>
          )}
          {incidentResult && incidentResult.status === 'error' && (
            <div className="notice error">{incidentResult.message}</div>
          )}
          {workflowMutation.isError && (
            <div className="notice error">Status could not be updated: {String(workflowMutation.error)}</div>
          )}
        </div>
      )}

      {/* ── tab bar ─────────────────────────────────────────────────────── */}
      <div className="fd3-tab-bar">
        <button
          className={`fd3-tab${tab === 'overview' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('overview')}
        >
          Overview
        </button>
        {finding.artifactId && <button
          className={`fd3-tab${tab === 'artifact' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('artifact')}
        >Artifact</button>}

      </div>

      {tab === 'overview' && (
        <div className="fd3-body">
          <div className="fd3-col fd3-col-left">
            <Panel title="Details">
              <div className="fd3-kv-table">
                <KVRow label="Finding">{finding.title}</KVRow>
                <KVRow label="Status"><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></KVRow>
                {finding.closedReason && <KVRow label="Closure reason">
                  {finding.closedReason === 'AUTO_POLICY_PLATFORM_DEPRECATED'
                    ? 'Closed — policy deprecated by platform'
                    : finding.closedReason === 'AUTO_POLICY_TENANT_DISABLED'
                      ? 'Closed — policy disabled for this tenant'
                      : finding.closedReason.replace(/_/g, ' ')}
                </KVRow>}
                {(finding.closedReason === 'AUTO_POLICY_PLATFORM_DEPRECATED' || finding.closedReason === 'AUTO_POLICY_TENANT_DISABLED') && (
                  <p className="fd3-muted">This closure does not indicate verified remediation.</p>
                )}
                <KVRow label="Analyst review">{finding.reviewDisposition.replace(/_/g, ' ')}</KVRow>
                <KVRow label="Artifact">
                  {finding.artifactId ? <button type="button" className="btn-link" onClick={() => navigate(pathForInventoryAiAsset(finding.artifactId!))}>
                    {finding.artifactName}
                  </button> : <span>Unavailable</span>}
                </KVRow>
                <KVRow label="First observed">{fmtDt(finding.firstObservedAt)}</KVRow>
                <KVRow label="Last observed">{fmtDt(finding.lastObservedAt)}</KVRow>
                {finding.resolvedAt && <KVRow label="Resolved at">{fmtDt(finding.resolvedAt)}</KVRow>}
              </div>
            </Panel>
          </div>

          <div className="fd3-col fd3-col-right">
            {policiesQuery.isLoading ? (
              <div className="empty-state"><p>Loading policy…</p></div>
            ) : !policy ? (
              <div className="empty-state"><p>Policy details are not available.</p></div>
            ) : (
              <Panel title={policy.name}>
                <div className="fd3-kv-table">
                  <KVRow label="Policy ID"><span className="mono">{policy.id}</span></KVRow>
                  <KVRow label="Severity"><span className={severityClassName(policy.severity)}>{policy.severity}</span></KVRow>
                  <KVRow label="Coverage">{Math.round(policy.decisionCoverage * 100)}%</KVRow>
                  <KVRow label="Description">{policy.description}</KVRow>
                  <KVRow label="Remediation">{policy.remediation}</KVRow>
                </div>
                <div className="button-row" style={{ marginTop: 12 }}>
                  <button type="button" className="btn btn-secondary" onClick={() => navigate(pathForPolicyDetail(policy.id))}>
                    Open policy →
                  </button>
                </div>
              </Panel>
            )}
          </div>
        </div>
      )}

      {tab === 'artifact' && (
        <div className="fd3-body">
          <div className="fd3-col fd3-col-right">
            {artifactQuery.isLoading ? (
              <div className="empty-state"><p>Loading artifact…</p></div>
            ) : artifactQuery.isError || !artifact ? (
              <div className="empty-state"><p>Artifact details are not available.</p></div>
            ) : (
              <>
                <div className="button-row" style={{ marginBottom: 12 }}>
                  <button type="button" className="btn btn-secondary" onClick={() => navigate(pathForInventoryAiAsset(artifact.id))}>
                    View full asset →
                  </button>
                </div>
                <InventoryOverviewPanel
                  primaryTitle={artifact.name}
                  primaryFields={artifactPrimaryFields}
                  secondaryFields={artifactSecondaryFields}
                />
              </>
            )}
          </div>
        </div>
      )}


    </div>
  );
}
