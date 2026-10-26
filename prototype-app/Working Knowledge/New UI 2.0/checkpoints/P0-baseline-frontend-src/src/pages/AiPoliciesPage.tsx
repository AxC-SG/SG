import { assessmentMessage, assessmentPending, invalidateAiAssessmentQueries } from '../features/ai-security/assessment';
import { useAssessmentUpdates } from '../features/ai-security/useAssessmentUpdates';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForPolicyDetail } from '../app/routes';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { ProviderLogo } from '../features/ai-security/ProviderLogo';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type { AiFrameworkCoverage, AiFrameworkDefinition, AiGridPolicy, AiGridPolicyAssessmentStateSummary, AiGridPolicySelection } from '../features/ai-security/types';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const PROVIDER_ORDER = ['AWS', 'AZURE', 'MULTI_CLOUD'];
const assessmentKey = (policyId: string, version: string) => `${policyId}:${version}`;
const CAPABILITY_LABELS: Record<string, string> = {
  AI_ACCOUNTS: 'AI account inventory',
  DIAGNOSTIC_SETTINGS: 'diagnostic logging configuration',
  FOUNDRY_DEPLOYMENTS_RAI: 'Azure AI Foundry deployment and responsible-AI policy data',
  ML_WORKSPACES_ENDPOINTS: 'machine-learning workspace and endpoint data',
};

function statusClass(value: string): string {
  return `policy-status policy-status--${value.toLowerCase().replace(/_/g, '-')}`;
}
const RESOURCE_FAMILY_ARTIFACT_TYPES: Record<string, string> = {
  AWS_BEDROCK_AGENTS: 'AI_AGENT',
  BEDROCK_AGENTS: 'AI_AGENT',
  AWS_BEDROCK_GUARDRAILS: 'AI_GUARDRAIL',
  BEDROCK_GUARDRAILS: 'AI_GUARDRAIL',
  AZURE_FOUNDRY_AGENTS: 'AI_AGENT',
  AZURE_BOT_SERVICES: 'AI_AGENT',
  AZURE_RAI_POLICIES: 'AI_GUARDRAIL',
  AZURE_AI_ACCOUNTS: 'OTHER_AI_ARTIFACT',
  AZURE_DIAGNOSTIC_SETTINGS: 'OTHER_AI_ARTIFACT',
  AZURE_ML_ENDPOINTS: 'AI_MODEL',
  AWS_AGENTCORE_GATEWAYS: 'MCP_GATEWAY',
  AWS_AGENTCORE_GATEWAY_TARGETS: 'MCP_TARGET',
  AZURE_FOUNDRY_MCP_SERVERS: 'MCP_SERVER',
  AZURE_SEARCH_MCP_SECURITY: 'MCP_SERVER',
  AZURE_SEARCH_DATA_SOURCES: 'KNOWLEDGE_BASE',
  AZURE_FOUNDRY_DEPLOYMENTS: 'AI_MODEL',
  AZURE_ML_MODELS: 'AI_MODEL',
};

function parseStringArray(json: string): string[] {
  try { const value = JSON.parse(json || '[]'); return Array.isArray(value) ? value.map(String) : []; } catch { return []; }
}

function parseFrameworks(json: string): string[] {
  try {
    const value = JSON.parse(json || '[]');
    if (!Array.isArray(value)) return [];
    return Array.from(new Set(value.map((mapping) => {
      if (typeof mapping === 'string') return mapping;
      if (!mapping || typeof mapping !== 'object') return '';
      const item = mapping as { framework?: unknown; frameworkVersion?: unknown };
      return [item.framework, item.frameworkVersion].filter(Boolean).join(' ');
    }).filter(Boolean)));
  } catch { return []; }
}

function applicableArtifactTypes(policy: AiGridPolicy): string[] {
  const explicitTypes = parseStringArray(policy.artifactTypesJson);
  if (explicitTypes.length > 0) return Array.from(new Set(explicitTypes));
  const resourceFamilies = parseStringArray(policy.requiredResourceFamiliesJson);
  return Array.from(new Set(resourceFamilies.map((family) => RESOURCE_FAMILY_ARTIFACT_TYPES[family]).filter(Boolean)));
}

function providerNames(provider: string): string[] {
  const normalized = provider.toUpperCase();
  if (normalized === 'MULTI_CLOUD' || normalized === 'MULTI-CLOUD') return ['AWS', 'AZURE'];
  return normalized.split(/[,/ ]+/).filter((name) => name === 'AWS' || name === 'AZURE');
}

function userReadableBlockers(blockers: string[]): string[] {
  return Array.from(new Set(blockers.map((blocker) => {
    if (blocker.startsWith('assessment:')) return 'A mapped policy has not yet produced decision-ready assessment evidence.';
    const capability = /^capability:([^:]+):MISSING$/i.exec(blocker);
    if (capability) {
      const label = CAPABILITY_LABELS[capability[1]] ?? formatLabel(capability[1]);
      return `Required connector data is unavailable: ${label}.`;
    }
    const messages: Record<string, string> = {
      TENANT_SCHEMA_VERSION_UNAVAILABLE: 'This workspace needs a schema upgrade before framework coverage can be assessed.',
      TENANT_SCHEMA_UPGRADE_REQUIRED: 'This workspace needs a schema upgrade before policy evidence can be assessed.',
      NO_COVERAGE_EPOCH: 'Framework coverage has not been assessed yet.',
      POLICY_PAUSED_PENDING_EVIDENCE: 'A mapped policy is paused until the required evidence is available.',
      POLICY_NOT_DISTRIBUTED: 'A mapped policy is not available to this workspace.',
    };
    return messages[blocker] ?? formatLabel(blocker).replace(/\b\w/g, (character) => character.toLowerCase());
  }).filter(Boolean)));
}

export function AiPoliciesPage() {
  useAssessmentUpdates();
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [severityFilter, setSeverityFilter] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState('');
  const [selectedPolicyIds, setSelectedPolicyIds] = React.useState<Set<string>>(new Set());
  const policiesQuery = useQuery({
    queryKey: ['ai-grid-policies'],
    queryFn: api.listAiGridPolicies,
  });
  const frameworksQuery = useQuery({ queryKey: ['ai-frameworks'], queryFn: api.getAiFrameworks });
  const coverageQueries = useQueries({ queries: (frameworksQuery.data ?? []).map((framework) => ({
    queryKey: ['ai-framework-coverage', framework.framework, framework.frameworkVersion],
    queryFn: () => api.getAiFrameworkCoverage(framework.framework, framework.frameworkVersion),
  })) });
  const assessmentStatesQuery = useQuery({ queryKey: ['ai-assessment-states-latest'], queryFn: api.getLatestAiGridAssessmentStates });
  const mutation = useMutation({
    mutationFn: ({ id, selection }: { id: string; selection: AiGridPolicySelection }) =>
      api.updateAiGridPolicySelection(id, selection),
    onSuccess: () => {
      void invalidateAiAssessmentQueries(queryClient);
    },
  });
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER');
  const canExecute = canManage || hasRole(actor, 'SECURITY_ANALYST');
  const executeMutation = useMutation({
    mutationFn: () => api.executeAiGridPolicies(Array.from(selectedPolicyIds)),
    onSuccess: () => {
      setSelectedPolicyIds(new Set());
      void invalidateAiAssessmentQueries(queryClient);
    },
  });

  const executionStatus = useQuery({
    queryKey: ['ai-assessment-status', executeMutation.data?.runId],
    queryFn: () => api.getAiAssessmentStatus(executeMutation.data!.runId),
    enabled: !!executeMutation.data?.runId && assessmentPending(executeMutation.data),
    refetchInterval: (query) => assessmentPending(query.state.data ?? executeMutation.data) ? 5000 : false,
  });
  const executionOutcome = executionStatus.data ?? executeMutation.data;
  React.useEffect(() => {
    if (executionStatus.data && !assessmentPending(executionStatus.data)) void invalidateAiAssessmentQueries(queryClient);
  }, [executionStatus.data, queryClient]);

  const policies = React.useMemo(() => policiesQuery.data ?? [], [policiesQuery.data]);
  const severityOptions = React.useMemo(() => (
    Array.from(new Set(policies.map((policy) => policy.severity.toUpperCase())))
      .sort((left, right) => (SEVERITY_RANK[left] ?? 99) - (SEVERITY_RANK[right] ?? 99))
  ), [policies]);
  const trimmedSearch = search.trim().toLowerCase();
  const visiblePolicies = React.useMemo(() => policies.filter((policy) => {
    if (severityFilter && policy.severity.toUpperCase() !== severityFilter) return false;
    if (trimmedSearch && !policy.name.toLowerCase().includes(trimmedSearch) && !policy.policyId.toLowerCase().includes(trimmedSearch)) return false;
    return true;
  }), [policies, severityFilter, trimmedSearch]);
  const allVisibleSelected = visiblePolicies.length > 0 && visiblePolicies.every((policy) => selectedPolicyIds.has(policy.policyId));
  const someVisibleSelected = !allVisibleSelected && visiblePolicies.some((policy) => selectedPolicyIds.has(policy.policyId));
  const toggleSelectAllVisible = (checked: boolean) => {
    setSelectedPolicyIds((current) => {
      const next = new Set(current);
      visiblePolicies.forEach((policy) => {
        if (checked) next.add(policy.policyId); else next.delete(policy.policyId);
      });
      return next;
    });
  };
  const policyInsights = React.useMemo(() => buildPolicyInsights(policies), [policies]);
  const assessmentStates = React.useMemo(() => new Map((assessmentStatesQuery.data ?? [])
    .map((summary) => [assessmentKey(summary.policyId, summary.policyVersion), summary])), [assessmentStatesQuery.data]);
  return (
    <div className="ai-security-page">
      <section className="ai-security-hero policies">
        <div>
          <span className="ai-security-kicker">Built-in, versioned controls</span>
          <h2>Policies</h2>
          <p>Governed AI security controls, with tenant selection and evidence readiness shown independently.</p>
        </div>
      </section>

      {!policiesQuery.isError ? <PolicyInsights insights={policyInsights} loading={policiesQuery.isLoading} /> : null}

      <TenantFrameworkCoverage frameworksQuery={frameworksQuery} coverageQueries={coverageQueries} />

      {policiesQuery.isLoading ? (
        <section className="panel"><div className="empty-state"><p>Loading policies…</p></div></section>
      ) : policiesQuery.isError ? (
        <section className="panel"><div className="notice error">AI Security policies could not be loaded.</div></section>
      ) : (
        <>
          <div className="ai-policy-toolbar">
            <div className="ai-policy-severity-pills">
              <span className="ai-policy-severity-pills-label">Severity</span>
              <div className="ai-policy-severity-pills-row">
                <button
                  type="button"
                  className={`ai-policy-severity-pill${severityFilter === null ? ' is-active' : ''}`}
                  onClick={() => setSeverityFilter(null)}
                >
                  All
                </button>
                {severityOptions.map((severity) => (
                  <button
                    key={severity}
                    type="button"
                    className={`ai-policy-severity-pill${severityFilter === severity ? ' is-active' : ''}`}
                    onClick={() => setSeverityFilter((current) => (current === severity ? null : severity))}
                  >
                    {formatLabel(severity)}
                  </button>
                ))}
              </div>
            </div>
            <div className="ai-policy-search">
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search policies"
                aria-label="Search policies"
              />
            </div>
            <button
              type="button"
              className="btn btn-primary ai-policy-execute-button"
              disabled={!canExecute || selectedPolicyIds.size === 0 || executeMutation.isPending}
              onClick={() => executeMutation.mutate()}
            >
              {executeMutation.isPending ? 'Assessing…' : 'Execute now'}
            </button>
          </div>
          {executeMutation.isError ? <div className="notice error">Selected policies could not be assessed. Please try again.</div> : null}
          {executionOutcome ? <div role="status" className={`notice ${assessmentPending(executionOutcome) ? '' : executionOutcome.assessmentStatus === 'COMPLETE' ? 'success' : ''}`}>{assessmentMessage(executionOutcome)}</div> : null}
          {selectedPolicyIds.size > 0 ? <div className="ai-policy-selection-status">{selectedPolicyIds.size} {selectedPolicyIds.size === 1 ? 'policy' : 'policies'} selected for assessment.</div> : null}
          <div className="panel ai-security-table-panel">
            {visiblePolicies.length === 0 ? (
              <div className="empty-state"><p>No policies match the current filters.</p></div>
            ) : (
              <table className="data-table">
                    <thead>
                      <tr>
                        <th>
                          <input
                            className="ai-policy-select-checkbox"
                            type="checkbox"
                            checked={allVisibleSelected}
                            ref={(element) => { if (element) element.indeterminate = someVisibleSelected; }}
                            onChange={(event) => toggleSelectAllVisible(event.target.checked)}
                            aria-label="Select all visible policies"
                          />
                        </th>
                        <th>Policy</th>
                        <th>Severity</th>
                        <th>Framework</th>
                        <th>Failed artefacts</th>
                        <th>Assessment state</th>
                        <th>Provide</th>
                        <th>Artefact types</th>
                        <th>Enabled/disabled</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visiblePolicies.map((policy) => (
                        <PolicyRows
                          key={policy.policyId}
                          policy={policy}
                          canManage={canManage}
                          saving={mutation.isPending && mutation.variables?.id === policy.policyId}
                          onOpen={() => navigate(pathForPolicyDetail(policy.policyId))}
                          onSelect={(checked) => mutation.mutate({ id: policy.policyId, selection: checked ? 'ENABLED' : 'DISABLED' })}
                          selected={selectedPolicyIds.has(policy.policyId)}
                          onToggleSelected={(checked) => setSelectedPolicyIds((current) => {
                            const next = new Set(current);
                            if (checked) next.add(policy.policyId); else next.delete(policy.policyId);
                            return next;
                          })}
                          assessmentState={assessmentStates.get(assessmentKey(policy.policyId, policy.version))}
                        />
                      ))}
                    </tbody>
                  </table>
            )}
          </div>
        </>
      )}
    </div>
  );
}

type PolicyInsights = ReturnType<typeof buildPolicyInsights>;

function TenantFrameworkCoverage({ frameworksQuery, coverageQueries }: {
  frameworksQuery: { data?: AiFrameworkDefinition[]; isLoading: boolean; isError: boolean };
  coverageQueries: Array<{ data?: AiFrameworkCoverage; isLoading: boolean; isError: boolean }>;
}) {
  return <section className="panel"><div className="panel-header"><div><h3>Framework risk coverage</h3><p className="panel-caption">Breadth shows mapped controls; effective coverage requires a policy available to this tenant, enabled, and backed by decision-ready evidence.</p></div></div>
    {frameworksQuery.isLoading ? <p role="status">Loading framework coverage…</p> : null}
    {frameworksQuery.isError ? <p className="notice error">The framework registry could not be loaded.</p> : null}
    {!frameworksQuery.isLoading && !frameworksQuery.isError && coverageQueries.length === 0 ? <p>No active framework registry entries were returned.</p> : coverageQueries.map((queryResult, index) => {
      const framework = frameworksQuery.data?.[index];
      const coverage = queryResult.data;
      return <div key={`${framework?.framework}:${framework?.frameworkVersion}`}><h4>{framework?.displayName}</h4>
        {queryResult.isLoading ? <p role="status">Loading {framework?.displayName} coverage…</p> : null}
        {queryResult.isError ? <p className="notice error">Coverage could not be loaded for this tenant.</p> : null}
        {coverage ? <><div className="table-scroll"><table className="data-table"><thead><tr><th>Control</th><th>Status</th><th>Applicable</th><th>Decision ready</th><th>Blocking reasons</th></tr></thead><tbody>
          {coverage.controls.map((control) => <tr key={control.controlId}><td><strong>{control.controlId}</strong><br /><small>{control.name}</small></td><td><span className={statusClass(control.coverageStatus)}>{control.coverageStatus}</span></td><td>{control.applicableCount}</td><td>{control.decisionReadyCount}</td><td>{userReadableBlockers(control.blockers).join(' ') || '—'}</td></tr>)}
        </tbody></table></div><p className="panel-caption">Legacy compatibility: {coverage.legacyCompatibility.distributed} of {coverage.legacyCompatibility.policies} policies distributed.</p></> : null}
      </div>;
    })}
  </section>;
}

function buildPolicyInsights(policies: AiGridPolicy[]) {
  const required = policies.filter((policy) => policy.selection === 'REQUIRED').length;
  const enabled = policies.filter((policy) => policy.selection === 'ENABLED').length;
  const critical = policies.filter((policy) => policy.severity.toUpperCase() === 'CRITICAL').length;
  const high = policies.filter((policy) => policy.severity.toUpperCase() === 'HIGH').length;
  const ready = policies.filter((policy) => policy.readiness.toUpperCase() === 'READY').length;
  const partial = policies.filter((policy) => policy.readiness.toUpperCase() === 'PARTIAL').length;
  const blocked = policies.filter((policy) => policy.readiness.toUpperCase() === 'BLOCKED').length;
  const noResources = policies.filter((policy) => policy.readiness.toUpperCase() === 'NO_RESOURCES').length;
  const notEvaluated = policies.filter((policy) => policy.readiness.toUpperCase() === 'NOT_EVALUATED').length;
  const providers = PROVIDER_ORDER.map((provider) => ({
    label: formatLabel(provider),
    count: policies.filter((policy) => policy.provider.toUpperCase() === provider).length,
  }));
  const readinessPercent = policies.length === 0 ? 0 : Math.round((ready / policies.length) * 100);
  return {
    required, enabled, critical, high, ready, partial, blocked, noResources, notEvaluated,
    providers, readinessPercent, total: policies.length, enforced: required + enabled,
    gaps: policies.length - ready,
  };
}

function PolicyInsights({ insights, loading }: { insights: PolicyInsights; loading: boolean }) {
  const value = (number: number) => loading ? '—' : number.toLocaleString();
  return (
    <section className="ai-policy-insight-grid" aria-label="Policy organization insights">
      <PolicyInsightCard
        tone="accent"
        label="Policy estate"
        value={value(insights.total)}
        detail={loading ? 'Loading catalog' : `${value(insights.providers[0].count)} AWS · ${value(insights.providers[1].count)} Azure · ${value(insights.providers[2].count)} multi-cloud`}
      />
      <PolicyInsightCard
        tone="accent"
        label="Enforcement posture"
        value={value(insights.enforced)}
        detail={loading ? 'Loading selections' : `${value(insights.required)} required · ${value(insights.enabled)} enabled`}
      />
      <PolicyInsightCard
        tone={insights.critical > 0 ? 'critical' : 'accent'}
        label="High-priority controls"
        value={value(insights.critical + insights.high)}
        detail={loading ? 'Loading severity mix' : `${value(insights.critical)} critical · ${value(insights.high)} high`}
      />
      <PolicyInsightCard
        tone={insights.readinessPercent >= 80 ? 'positive' : 'warn'}
        label="Evidence ready"
        value={loading ? '—' : `${insights.readinessPercent}%`}
        detail={loading ? 'Loading readiness' : `${value(insights.ready)} of ${value(insights.total)} controls ready`}
      />
      <PolicyInsightCard
        tone={insights.gaps > 0 ? 'warn' : 'positive'}
        label="Coverage gaps"
        value={value(insights.gaps)}
        detail={loading ? 'Loading gaps' : `${value(insights.partial)} partial · ${value(insights.blocked)} blocked`}
      />
      <PolicyInsightCard
        tone={insights.noResources + insights.notEvaluated > 0 ? 'warn' : 'positive'}
        label="Organization blind spots"
        value={value(insights.noResources + insights.notEvaluated)}
        detail={loading ? 'Loading evaluation state' : `${value(insights.noResources)} no resources · ${value(insights.notEvaluated)} not evaluated`}
      />
    </section>
  );
}

function PolicyInsightCard({ label, value, detail, tone }: {
  label: string;
  value: string;
  detail: string;
  tone: 'accent' | 'positive' | 'warn' | 'critical';
}) {
  return (
    <article className={`ai-policy-insight-card ai-policy-insight-card-${tone}`}>
      <span className="ai-policy-insight-label">{label}</span>
      <strong className="ai-policy-insight-value">{value}</strong>
      <span className="ai-policy-insight-detail">{detail}</span>
    </article>
  );
}

function PolicyRows({ policy, canManage, saving, onOpen, onSelect, selected, onToggleSelected, assessmentState }: {
  policy: AiGridPolicy;
  canManage: boolean;
  saving: boolean;
  onOpen: () => void;
  onSelect: (checked: boolean) => void;
  selected: boolean;
  onToggleSelected: (checked: boolean) => void;
  assessmentState?: AiGridPolicyAssessmentStateSummary;
}) {
  const conditionalCapabilities = parseStringArray(policy.conditionalCapabilitiesJson);
  const frameworks = parseFrameworks(policy.frameworkMappingsJson);
  const artifactTypes = applicableArtifactTypes(policy);
  const providers = providerNames(policy.provider);
  return (
    <>
      <tr onClick={onOpen}>
        <td onClick={(event) => event.stopPropagation()}>
          <input
            className="ai-policy-select-checkbox"
            type="checkbox"
            checked={selected}
            onChange={(event) => onToggleSelected(event.target.checked)}
            aria-label={`Select ${policy.name}`}
          />
        </td>
        <td>
          <strong>{policy.name}</strong>
          {conditionalCapabilities.length > 0 ? (
            <span className="ai-policy-capability-flag" title="Requires an optional connector capability"> · needs capability</span>
          ) : null}
        </td>
        <td><span className={severityClassName(policy.severity)}>{policy.severity}</span></td>
        <td>
          <div className="ai-policy-framework-list">
            {frameworks.length > 0 ? frameworks.map((framework) => <span key={framework}>{formatLabel(framework)}</span>) : <small>—</small>}
          </div>
        </td>
        <td><strong>{policy.failedArtifacts} / {policy.totalArtifacts}</strong></td>
        <td>{assessmentState ? <div className="ai-policy-framework-list" aria-label={`Assessment states for ${policy.name}`}>
          {assessmentState.fail > 0 ? <span className={statusClass('FAIL')}>Fail {assessmentState.fail}</span> : null}
          {assessmentState.unknown > 0 ? <span className={statusClass('UNKNOWN')}>Unknown {assessmentState.unknown}</span> : null}
          {assessmentState.pass > 0 ? <span className={statusClass('PASS')}>Pass {assessmentState.pass}</span> : null}
          {assessmentState.notAssessed > 0 ? <span className={statusClass('NOT_ASSESSED')}>Not assessed {assessmentState.notAssessed}</span> : null}
        </div> : <small>Not evaluated</small>}</td>
        <td>
          <div className="ai-policy-provider-logos" aria-label={`Applicable providers: ${providers.join(', ')}`}>
            {providers.length > 0 ? providers.map((provider) => <span key={provider} className="ai-policy-provider-logo"><ProviderLogo provider={provider} /></span>) : <small>—</small>}
          </div>
        </td>
        <td>
          <div className="ai-policy-artifact-list">
            {artifactTypes.map((type) => <span key={type}>{formatLabel(type)}</span>)}
            {artifactTypes.length === 0 ? <small>—</small> : null}
          </div>
        </td>
        <td>
          <label className="ai-policy-toggle" onClick={(event) => event.stopPropagation()}>
            <input
              type="checkbox"
              checked={policy.selection === 'REQUIRED' || policy.selection === 'ENABLED'}
              disabled={!canManage || saving}
              onChange={(event) => onSelect(event.target.checked)}
              aria-label={`${policy.name} enabled`}
            />
            <span className="ai-policy-toggle-track" aria-hidden="true"><span className="ai-policy-toggle-thumb" /></span>
          </label>
        </td>
      </tr>
    </>
  );
}
