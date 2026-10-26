import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { categoryForNativeKind } from '../features/ai-security/categories';
import { api } from '../api/client';
import { pathForInventoryAiAsset, pathForInventoryView, pathForPolicyDetail } from '../app/routes';
import { AiBaselineSection } from '../features/ai-security/AiBaselineSection';
import { AiDependencyGraph } from '../features/ai-security/AiDependencyGraph';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import { InventoryOverviewPanel, type OverviewField } from '../features/inventory/InventoryOverviewPanel';
import { timeAgo } from '../lib/time';

type AiAssetDetailPageProps = {
  artifactId: string;
};

type AssetDetailTab = 'overview' | 'policies' | 'findings' | 'relationships';

const ARTIFACT_TYPE_ICON: Record<string, string> = {
  AI_AGENT: '🤖',
  AI_AGENT_VERSION: '🧬',
  AI_PROMPT: '📝',
  AI_TOOL: '🛠️',
  AI_COMPONENT: '🧩',
  AI_MODEL: '🧠',
  OTHER_AI_ARTIFACT: '📦',
};

function formatTimestamp(value?: string | null): string {
  if (!value) return '—';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}


function formatFactItem(item: unknown): string {
  if (item == null) return '—';
  if (typeof item !== 'object') return String(item);
  const entries = Object.entries(item as Record<string, unknown>).filter(([, v]) => v != null && v !== '');
  if (entries.length === 0) return '—';
  return entries.map(([key, entryValue]) => `${key}: ${entryValue}`).join(' · ');
}

function formatFactValue(value: unknown): string {
  if (Array.isArray(value)) return value.length === 0 ? 'None' : value.map(formatFactItem).join(', ');
  if (typeof value === 'object' && value != null) return formatFactItem(value);
  if (value == null || value === '') return 'Not observed';
  return String(value);
}

function formatSensitivity(value: string): string {
  if (value === 'NOT_SCANNED') return 'Not scanned';
  if (value === 'UNKNOWN') return 'Unknown — insufficient evidence';
  if (value === 'LOOKUP_FAILED') return 'Unknown — lookup failed';
  return formatLabel(value);
}

const ATTRIBUTE_LABEL_OVERRIDES: Record<string, string> = {
  dataSourceAccessCount: 'Access to data sources',
};

function formatAttributeLabel(key: string): string {
  return ATTRIBUTE_LABEL_OVERRIDES[key] ?? key.replace(/([A-Z_])/g, ' $1');
}

export function AiAssetDetailPage({ artifactId }: AiAssetDetailPageProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const actor = useActor();
  const canManagePolicies = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER');
  const returnTo = searchParams.get('returnTo')?.trim() || (
    typeof location.state === 'object' && location.state && 'returnTo' in location.state
      ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
      : ''
  );
  const canConfirmOwner = hasRole(actor, 'PLATFORM_OWNER') || hasRole(actor, 'TENANT_ADMIN')
    || hasRole(actor, 'SECURITY_ANALYST');
  const [tab, setTab] = React.useState<AssetDetailTab>('overview');
  const [ownerDraft, setOwnerDraft] = React.useState('');

  const artifactQuery = useQuery({
    queryKey: ['ai-security-artifact', artifactId],
    queryFn: () => api.getAiSecurityArtifact(artifactId),
  });
  React.useEffect(
    () => setOwnerDraft(artifactQuery.data?.ownerName ?? ''),
    [artifactQuery.data?.id, artifactQuery.data?.ownerName],
  );
  const ownerMutation = useMutation({
    mutationFn: () => api.confirmAiGridArtifactOwner(artifactId, ownerDraft, 'Confirmed from AI asset detail'),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ai-security-artifact', artifactId] });
      void queryClient.invalidateQueries({ queryKey: ['ai-security-artifacts'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-coverage'] });
    },
  });
  const policiesQuery = useQuery({
    queryKey: ['ai-security-policies'],
    queryFn: api.listAiGridPolicyDetails,
  });
  const findingsQuery = useQuery({
    queryKey: ['ai-security-findings-all'],
    queryFn: () => api.listAiSecurityFindings(undefined, undefined, 0, 200),
  });
  const graphQuery = useQuery({
    queryKey: ['ai-security-graph', artifactId],
    placeholderData: keepPreviousData,
    queryFn: () => api.getAiSecurityGraph(artifactId, 2),
  });
  const handleGraphNodeClick = React.useCallback((clickedArtifactId: string) => {
    if (clickedArtifactId === artifactId) return;
    navigate(pathForInventoryAiAsset(clickedArtifactId, `${location.pathname}${location.search}`));
  }, [artifactId, navigate, location.pathname, location.search]);
  const postureQuery = useQuery({
    queryKey: ['ai-asset-posture', artifactId],
    queryFn: () => api.getAiAssetPosture(artifactId),
    enabled: tab === 'overview',
  });
  const policyMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.updateAiGridPolicySelection(id, enabled ? 'ENABLED' : 'DISABLED'),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] }),
  });

  const artifact = artifactQuery.data ?? null;
  const isLogicalAgent = categoryForNativeKind(artifact?.nativeKind ?? '')?.key === 'AGENTS';
  const [versionPage, setVersionPage] = React.useState(0);
  React.useEffect(() => { setVersionPage(0); }, [artifactId]);
  const versionsQuery = useQuery({
    queryKey: ['ai-agent-versions', artifactId, versionPage],
    queryFn: () => api.listAiAgentVersions(artifactId, versionPage),
    enabled: isLogicalAgent && tab === 'overview',
  });
  const agentDefinitionBindings = React.useMemo(() => {
    if (!artifact || categoryForNativeKind(artifact.nativeKind)?.key !== 'AGENTS' || !graphQuery.data) return null;
    const nodes = new Map(graphQuery.data.nodes.map(node => [node.id, node]));
    const definitionVersionIds = new Set(graphQuery.data.edges
      .filter(edge => edge.sourceArtifactId === artifact.id && edge.relationshipType === 'ACTIVE_VERSION')
      .map(edge => edge.targetArtifactId));
    const versions = graphQuery.data.edges
      .filter(edge => edge.targetArtifactId === artifact.id && edge.relationshipType === 'VERSION_OF')
      .map(edge => nodes.get(edge.sourceArtifactId)?.name ?? edge.sourceName);
    const activeEdges = graphQuery.data.edges.filter(edge => edge.sourceArtifactId === artifact.id
      || definitionVersionIds.has(edge.sourceArtifactId));
    const names = (type: string) => activeEdges.filter(edge => edge.relationshipType === type)
      .map(edge => nodes.get(edge.targetArtifactId)?.name ?? edge.targetName)
      .filter((value, index, all) => all.indexOf(value) === index);
    return { versions, definitionVersions: [...definitionVersionIds].map(id => nodes.get(id)?.name).filter(Boolean),
      models: names('USES_MODEL'), prompts: names('USES_PROMPT'), tools: names('USES_TOOL') };
  }, [artifact, graphQuery.data]);
  const policiesById = React.useMemo(
    () => new Map((policiesQuery.data ?? []).map((policy) => [policy.id, policy])),
    [policiesQuery.data],
  );
  const artifactFindings = React.useMemo(
    () => (findingsQuery.data?.items ?? []).filter((finding) => finding.artifactId === artifactId),
    [findingsQuery.data, artifactId],
  );
  const findingsCountByArtifactId = React.useMemo(() => {
    const counts: Record<string, number> = {};
    for (const finding of findingsQuery.data?.items ?? []) {
      if (!finding.artifactId) continue;
      counts[finding.artifactId] = (counts[finding.artifactId] ?? 0) + 1;
    }
    return counts;
  }, [findingsQuery.data]);
  const openFindings = React.useMemo(
    () => artifactFindings.filter((finding) => finding.status === 'OPEN'),
    [artifactFindings],
  );
  const applicablePolicies = React.useMemo(() => {
    if (!artifact) return [];
    return (policiesQuery.data ?? []).filter((policy) => policy.artifactTypes.includes(artifact.artifactType));
  }, [policiesQuery.data, artifact]);

  const overviewPrimaryFields = React.useMemo<OverviewField[]>(() => {
    if (!artifact) return [];
    return [
      { label: 'Provider', value: artifact.provider },
      { label: 'Native type', value: formatLabel(artifact.nativeKind) },
      { label: 'Account', value: artifact.accountId },
      { label: 'Region', value: artifact.region },
      { label: 'Provider ID', value: <span className="mono">{artifact.providerResourceId}</span> },
      { label: 'System attachment', value: formatLabel(artifact.attachmentState) },
      { label: 'Systems', value: artifact.systemIds.length ? artifact.systemIds.join(', ') : 'None' },
      { label: 'First observed', value: formatTimestamp(artifact.firstObservedAt) },
      { label: 'Last observed', value: formatTimestamp(artifact.lastObservedAt) },
      { label: 'Owner', value: artifact.ownerName ?? 'Unowned' },
      { label: 'Owner state', value: artifact.ownerState ?? 'UNOWNED' },
      { label: 'Owner source', value: artifact.ownerSource ?? 'No owner signal' },
    ];
  }, [artifact]);

  const overviewSecondaryFields = React.useMemo<OverviewField[]>(() => {
    if (!artifact) return [];
    return Object.entries(artifact.attributes).map(([key, value]) => ({
      label: formatAttributeLabel(key),
      value: formatFactValue(value),
    }));
  }, [artifact]);

  const typeSpecificFields = React.useMemo<OverviewField[]>(() => {
    if (!artifact) return [];
    const attributes = artifact.attributes;
    const fields: Array<[string, unknown]> = artifact.artifactType === 'MCP_SERVER' || artifact.artifactType === 'MCP_GATEWAY' || artifact.artifactType === 'MCP_TARGET'
      ? [['Role', artifact.artifactType], ['Endpoint host', attributes.endpointHost], ['Exposure', attributes.endpointExposure], ['Configured authentication', attributes.configuredAuthType ?? attributes.inboundAuthType], ['Target health', attributes.status], ['Last synchronized', attributes.lastSynchronizedAt]]
      : artifact.artifactType === 'KNOWLEDGE_BASE' || artifact.artifactType === 'DATA_SOURCE' || artifact.artifactType === 'DATA_STORE' || artifact.artifactType === 'SEARCH_INDEX'
        ? [['Source type', attributes.sourceType], ['Sensitivity', formatSensitivity(artifact.piiScanStatus)], ['ACL state', attributes.aclSupport], ['Retrieval mode', attributes.retrievalMode], ['Backing store', attributes.storeType ?? attributes.backingStore]]
        : [];
    return fields.map(([label, value]) => ({ label, value: formatFactValue(value) }));
  }, [artifact]);

  const overviewOwnerFooter = canConfirmOwner ? (
    <div className="ai-security-owner-confirmation">
      <label>
        <span>Accountable owner</span>
        <input
          value={ownerDraft}
          onChange={(event) => setOwnerDraft(event.target.value)}
          placeholder="Team or owner"
          aria-label="Accountable owner"
        />
      </label>
      <button
        className="btn btn-secondary"
        type="button"
        disabled={!ownerDraft.trim() || ownerMutation.isPending}
        onClick={() => ownerMutation.mutate()}
      >
        {ownerMutation.isPending ? 'Confirming…' : 'Confirm owner'}
      </button>
      {ownerMutation.isError && <div className="notice error">Owner could not be confirmed.</div>}
    </div>
  ) : null;

  const handleClose = React.useCallback(() => {
    if (returnTo) {
      navigate(returnTo);
      return;
    }
    navigate(pathForInventoryView('ai'));
  }, [navigate, returnTo]);

  if (artifactQuery.isLoading) {
    return (
      <section className="ai-asset-detail-page">
        <div className="empty-state"><p>Loading AI asset…</p></div>
      </section>
    );
  }

  if (artifactQuery.isError || !artifact) {
    return (
      <section className="ai-asset-detail-page">
        <div className="empty-state">
          <p>This AI asset could not be found.</p>
          <button type="button" className="btn btn-secondary" onClick={handleClose}>← Back to AI Inventory</button>
        </div>
      </section>
    );
  }

  return (
    <section className="ai-asset-detail-page">
      <div className="button-row host-detail-close-row">
        <button type="button" className="modal-close-btn" onClick={handleClose} aria-label="Close AI asset detail">
          x
        </button>
      </div>

      <div className="fd3-topbar">
        <span aria-hidden="true">{ARTIFACT_TYPE_ICON[artifact.artifactType] ?? '🤖'}</span>
        <span className="fd3-finding-id mono">{artifact.name}</span>
        <span className="panel-caption mono">{artifact.providerResourceId}</span>
        <div style={{ flex: 1 }} />
        <div className="fd3-actions">
          <span className="cvd-signal-pill">{artifact.provider}</span>
          <span className="cvd-signal-pill">{formatLabel(artifact.nativeKind)}</span>
          <span className={`status-pill ${artifact.active ? 'success' : 'muted'}`}>
            {artifact.active ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      <div className="fd3-tab-bar" role="tablist" aria-label="AI asset detail sections">
        <button
          type="button"
          className={`fd3-tab${tab === 'overview' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('overview')}
        >
          Overview
        </button>
        <button
          type="button"
          className={`fd3-tab${tab === 'policies' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('policies')}
        >
          Policies<span className="fd3-tab-count">{applicablePolicies.length}</span>
        </button>
        <button
          type="button"
          className={`fd3-tab${tab === 'findings' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('findings')}
        >
          Findings<span className="fd3-tab-count">{artifactFindings.length}</span>
        </button>
        <button
          type="button"
          className={`fd3-tab${tab === 'relationships' ? ' fd3-tab--active' : ''}`}
          onClick={() => setTab('relationships')}
        >
          Relationships<span className="fd3-tab-count">{graphQuery.data?.edges.length ?? 0}</span>
        </button>
      </div>

      <div className="fd3-body">
        <div className="fd3-col fd3-col-right">
          {tab === 'overview' && (
            <>
            <InventoryOverviewPanel
              alerts={openFindings.length > 0 && (
                <div className="fd3-panel">
                  <div className="fd3-panel-title">Needs Attention</div>
                  <div className="cvd2-wf-cards">
                    <button type="button" className="cvd2-wf-card" onClick={() => setTab('findings')}>
                      <div className="cvd2-wf-card-num">1</div>
                      <div className="cvd2-wf-card-body">
                        <div className="cvd2-wf-card-title-row">
                          <span className="cvd2-wf-card-title">Review open findings</span>
                        </div>
                        <p className="cvd2-wf-card-sub">
                          {openFindings.length} open finding{openFindings.length === 1 ? '' : 's'} on this asset need
                          {openFindings.length === 1 ? 's' : ''} review.
                        </p>
                      </div>
                    </button>
                  </div>
                </div>
              )}
              primaryFields={overviewPrimaryFields}
              primaryFooter={overviewOwnerFooter}
              secondaryFields={overviewSecondaryFields}
            />
            {typeSpecificFields.length > 0 && <section className="fd3-panel"><div className="fd3-panel-title">{artifact.artifactType.startsWith('MCP_') ? 'MCP configuration' : 'Knowledge and data configuration'}</div><InventoryOverviewPanel primaryFields={typeSpecificFields} /></section>}
            {isLogicalAgent && <section className="fd3-panel">
              <div className="fd3-panel-title">Deployment</div>
              <InventoryOverviewPanel primaryFields={[
                { label: 'Status', value: artifact.deployment?.status === 'SERVED' ? 'Served' : artifact.deployment?.status === 'NOT_CURRENTLY_SERVED' ? 'Not currently served' : 'Deployment unverified' },
                { label: 'Reason', value: artifact.deployment?.reasonCode.replace(/_/g, ' ').toLowerCase() ?? 'No evidence' },
                { label: 'Observed', value: artifact.deployment?.observedAt ?? 'Not observed' },
                { label: 'Expires', value: artifact.deployment?.expiresAt ?? 'Not observed' },
                { label: 'Last verified observation', value: artifact.deployment?.lastVerifiedObservation ? `${artifact.deployment.lastVerifiedObservation.status} at ${artifact.deployment.lastVerifiedObservation.observedAt}` : 'None' },
              ]} />
              {artifact.deployment?.evidenceReferences.map(evidence => <p key={evidence.scopeId}>
                {evidence.family}: {evidence.collectionStatus} · {evidence.observedAt}
                {evidence.routeIds.map(id => <button key={id} className="btn btn-secondary" type="button" onClick={() => navigate(pathForInventoryAiAsset(id, `${location.pathname}${location.search}`))}>Route evidence</button>)}
              </p>)}
            </section>}
            {isLogicalAgent && <section className="fd3-panel">
              <div className="fd3-panel-title">Versions</div>
              {versionsQuery.isError ? <p role="alert">Versions could not be loaded.</p> : versionsQuery.isLoading ? <p>Loading versions…</p> : <>
                {(versionsQuery.data?.items ?? []).map(version => <p key={version.id}>
                  <button className="btn btn-secondary" type="button" onClick={() => navigate(pathForInventoryAiAsset(version.id, `${location.pathname}${location.search}`))}>{version.name}</button>
                  {version.definitionVersion && <span> Definition / latest</span>}
                  {version.servedVersion && <span> Served</span>}
                </p>)}
                {!versionsQuery.data?.total && <p>No versions observed.</p>}
                {(versionsQuery.data?.total ?? 0) > 50 && <div className="pagination-row">
                  <button type="button" disabled={versionPage === 0} onClick={() => setVersionPage(value => value - 1)}>Previous versions</button>
                  <span>Page {versionPage + 1}</span>
                  <button type="button" disabled={(versionPage + 1) * 50 >= (versionsQuery.data?.total ?? 0)} onClick={() => setVersionPage(value => value + 1)}>Next versions</button>
                </div>}
              </>}
            </section>}
            {agentDefinitionBindings && <section className="fd3-panel"><div className="fd3-panel-title">Agent definition</div><InventoryOverviewPanel primaryTitle="Definition lineage" primaryFields={[
              { label: 'Versions', value: agentDefinitionBindings.versions.length ? agentDefinitionBindings.versions.join(', ') : 'Not observed' },
              { label: 'Definition / latest versions', value: agentDefinitionBindings.definitionVersions.length ? agentDefinitionBindings.definitionVersions.join(', ') : 'Not observed' },
              { label: 'Definition models', value: agentDefinitionBindings.models.length ? agentDefinitionBindings.models.join(', ') : 'Not observed' },
              { label: 'Definition prompts', value: agentDefinitionBindings.prompts.length ? agentDefinitionBindings.prompts.join(', ') : 'Not observed' },
              { label: 'Definition tools', value: agentDefinitionBindings.tools.length ? agentDefinitionBindings.tools.join(', ') : 'Not observed' },
            ]} /></section>}
            <AiBaselineSection artifactId={artifactId} canApprove={canConfirmOwner}
              component={artifact.name} version={String(artifact.attributes.version ?? artifact.attributes.modelVersion ?? 'Not observed')} />
            <section className="fd3-panel">
              <div className="fd3-panel-title">Control posture</div>
              {postureQuery.isLoading ? <p className="panel-caption">Loading evaluated controls…</p> : postureQuery.isError ? <p className="notice error">Control posture could not be loaded.</p> : (postureQuery.data?.controls.length ?? 0) === 0 ? <p className="panel-caption">No current policy evidence covers this asset.</p> : <table className="data-table"><thead><tr><th>Control</th><th>Evidence</th><th>Decision</th></tr></thead><tbody>
                {postureQuery.data?.controls.map((control) => <tr key={control.policyId}><td>{control.policyId}</td><td>{control.evidenceReadiness}</td><td>{control.decision}</td></tr>)}
              </tbody></table>}
              {(postureQuery.data?.exposures.length ?? 0) > 0 && <p className="panel-caption">{postureQuery.data?.exposures.length} validated exposure path{postureQuery.data?.exposures.length === 1 ? '' : 's'} use this asset as a root cause.</p>}
            </section>
            </>
          )}

          {tab === 'policies' && (
            applicablePolicies.length === 0 ? (
              <div className="empty-state"><p>No policies currently cover this artifact type.</p></div>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Policy</th>
                      <th>Severity</th>
                      <th>Coverage</th>
                      <th>Findings on this asset</th>
                      <th>Enabled</th>
                    </tr>
                  </thead>
                  <tbody>
                    {applicablePolicies.map((policy) => {
                      const policyFindings = artifactFindings.filter((finding) => finding.policyId === policy.id);
                      const openForPolicy = policyFindings.filter((finding) => finding.status === 'OPEN').length;
                      return (
                        <tr key={policy.id} onClick={() => navigate(pathForPolicyDetail(policy.id))}>
                          <td>
                            <strong>{policy.name}</strong>
                            <small className="mono">{policy.id} · v{policy.version}</small>
                          </td>
                          <td><span className={severityClassName(policy.severity)}>{policy.severity}</span></td>
                          <td><strong>{Math.round(policy.decisionCoverage * 100)}%</strong></td>
                          <td>
                            {policyFindings.length === 0 ? (
                              <span className="panel-caption">No findings</span>
                            ) : (
                              <button
                                type="button"
                                className="ai-policy-findings-link"
                                onClick={(event) => { event.stopPropagation(); setTab('findings'); }}
                              >
                                <strong>{openForPolicy}</strong><span> open · {policyFindings.length} total</span>
                              </button>
                            )}
                          </td>
                          <td>
                            <label className="ai-policy-switch" onClick={(event) => event.stopPropagation()}>
                              <input
                                type="checkbox"
                                checked={policy.enabled}
                                disabled={!canManagePolicies || (policyMutation.isPending && policyMutation.variables?.id === policy.id)}
                                onChange={(event) => policyMutation.mutate({ id: policy.id, enabled: event.target.checked })}
                                aria-label={policy.enabled ? 'Enabled' : 'Disabled'}
                              />
                            </label>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'findings' && (
            artifactFindings.length === 0 ? (
              <div className="empty-state"><p>No findings are currently attached to this AI asset.</p></div>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>Finding</th><th>Policy</th><th>Severity</th><th>State</th><th>Observed</th></tr>
                  </thead>
                  <tbody>
                    {artifactFindings.map((finding) => {
                      const policy = policiesById.get(finding.policyId);
                      return (
                        <tr key={finding.id}>
                          <td><strong>{finding.displayId}</strong><small>{finding.title}</small></td>
                          <td>
                            <button
                              type="button"
                              className="ai-policy-findings-link"
                              onClick={() => navigate(pathForPolicyDetail(finding.policyId))}
                            >
                              {policy?.name ?? finding.policyId}
                            </button>
                            <br /><small className="mono">v{finding.policyVersion}</small>
                          </td>
                          <td><span className={severityClassName(finding.severity)}>{finding.severity}</span></td>
                          <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                          <td>{timeAgo(finding.lastObservedAt) ?? 'Unknown'}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          )}

          {tab === 'relationships' && (
            <>
            {graphQuery.isLoading ? (
              <div className="empty-state"><p>Loading connected resources…</p></div>
            ) : (graphQuery.data?.edges.length ?? 0) === 0 ? (
              <div className="empty-state"><p>No active relationships observed for this asset.</p></div>
            ) : (
              <AiDependencyGraph
                graph={graphQuery.data!}
                rootArtifactId={artifactId}
                onNodeClick={handleGraphNodeClick}
                findingsCountByArtifactId={findingsCountByArtifactId}
                policies={policiesQuery.data ?? []}
              />
            )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}
