import { assessmentPending, assessmentMessage, invalidateAiAssessmentQueries } from '../features/ai-security/assessment';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import { hasRole } from '../features/auth/roles';
import { formatDate, formatLabel, severityClassName } from '../features/cve-workbench/formatting';
import type {
  AiGridPolicy,
  AiSecurityPolicy,
  AiSecurityFinding,
  PolicyExceptionOverride,
  PolicyScopeCondition,
  PolicyScopeMode,
} from '../features/ai-security/types';
import { timeAgo } from '../lib/time';

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
type PolicyDetailTab = 'overview' | 'configure' | 'findings' | 'artifacts';
type FrameworkMapping = { framework?: string; frameworkVersion?: string; controlId?: string; mappingType?: string; rationale?: string };

function parseJsonArray(json: string | undefined): string[] {
  try {
    const value = JSON.parse(json || '[]');
    return Array.isArray(value) ? value.map(String) : [];
  } catch {
    return [];
  }
}

function parseFrameworkMappings(json: string | undefined): FrameworkMapping[] {
  try {
    const value = JSON.parse(json || '[]');
    return Array.isArray(value) ? value as FrameworkMapping[] : [];
  } catch {
    return [];
  }
}

const SCOPE_FIELD_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'ARTIFACT_TYPE', label: 'Artifact type' },
  { value: 'PROVIDER', label: 'Provider' },
  { value: 'REGION', label: 'Region' },
  { value: 'ACCOUNT_ID', label: 'Account ID' },
  { value: 'NATIVE_KIND', label: 'Native type' },
  { value: 'NAME', label: 'Name' },
];

const SCOPE_OPERATOR_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'EQUALS', label: 'is' },
  { value: 'NOT_EQUALS', label: 'is not' },
  { value: 'CONTAINS', label: 'contains' },
  { value: 'NOT_CONTAINS', label: 'does not contain' },
];

const SCOPE_MODE_OPTIONS: Array<{ value: PolicyScopeMode; label: string }> = [
  { value: 'ALL', label: 'All AI inventory' },
  { value: 'MATCH_RULES', label: 'Match rules' },
  { value: 'CUSTOM_LIST', label: 'Custom list' },
];

const CONDITION_VALUE_OPTIONS: Record<string, Array<{ value: string; label: string }>> = {
  ARTIFACT_TYPE: [
    { value: 'AI_AGENT', label: 'AI agent' },
    { value: 'AI_AGENT_VERSION', label: 'AI agent version' },
    { value: 'AI_PROMPT', label: 'AI prompt' },
    { value: 'AI_TOOL', label: 'AI tool' },
    { value: 'AI_COMPONENT', label: 'AI component' },
    { value: 'AI_MODEL', label: 'AI model' },
    { value: 'AI_GUARDRAIL', label: 'AI guardrail' },
    { value: 'MCP_GATEWAY', label: 'MCP gateway' },
    { value: 'MCP_TARGET', label: 'MCP target' },
    { value: 'MCP_SERVER', label: 'MCP server' },
    { value: 'KNOWLEDGE_BASE', label: 'Knowledge base' },
    { value: 'OTHER_AI_ARTIFACT', label: 'Other AI artifact' },
  ],
  PROVIDER: [
    { value: 'AWS', label: 'AWS' },
    { value: 'AZURE', label: 'Azure' },
    { value: 'MULTI_CLOUD', label: 'Multi-cloud' },
  ],
};

const ARTIFACT_ATTRIBUTE_FIELDS = new Set(['NAME', 'PROVIDER', 'REGION', 'ACCOUNT_ID', 'NATIVE_KIND']);

function selectedArtifactType(conditions: PolicyScopeCondition[]): string | null {
  const condition = conditions.find((item) => item.field === 'ARTIFACT_TYPE' && item.value.trim());
  return condition?.value ?? null;
}

function artifactTypeLabel(value: string | null): string {
  if (!value) return 'selected artifact type';
  return CONDITION_VALUE_OPTIONS.ARTIFACT_TYPE.find((option) => option.value === value)?.label ?? formatLabel(value);
}

function conditionFieldOptions(conditions: PolicyScopeCondition[]): Array<{ value: string; label: string }> {
  const type = selectedArtifactType(conditions);
  return SCOPE_FIELD_OPTIONS.map((option) => (
    type && ARTIFACT_ATTRIBUTE_FIELDS.has(option.value)
      ? { ...option, label: `${option.label} · ${artifactTypeLabel(type)}` }
      : option
  ));
}

function newConditionFor(conditions: PolicyScopeCondition[]): PolicyScopeCondition {
  return {
    field: selectedArtifactType(conditions) ? 'NAME' : 'ARTIFACT_TYPE',
    operator: selectedArtifactType(conditions) ? 'CONTAINS' : 'EQUALS',
    value: '',
  };
}

function isArtifactAttributeChild(conditions: PolicyScopeCondition[], index: number): boolean {
  return index > 0
    && conditions[index]?.field !== 'ARTIFACT_TYPE'
    && conditions.slice(0, index).some((condition) => condition.field === 'ARTIFACT_TYPE' && condition.value.trim());
}

function isFirstArtifactAttributeChild(conditions: PolicyScopeCondition[], index: number): boolean {
  return isArtifactAttributeChild(conditions, index) && !isArtifactAttributeChild(conditions, index - 1);
}

type ImpactedArtifact = {
  artifactId: string;
  artifactName: string;
  openFindings: number;
  totalFindings: number;
  worstSeverity: string;
  lastObservedAt: string;
};

function buildImpactedArtifacts(findings: AiSecurityFinding[]): ImpactedArtifact[] {
  const byArtifact = new Map<string, ImpactedArtifact>();
  findings.forEach((finding) => {
    if (!finding.artifactId) return;
    const isOpen = finding.status === 'OPEN';
    const existing = byArtifact.get(finding.artifactId);
    if (!existing) {
      byArtifact.set(finding.artifactId, {
        artifactId: finding.artifactId,
        artifactName: finding.artifactName,
        openFindings: isOpen ? 1 : 0,
        totalFindings: 1,
        worstSeverity: finding.severity,
        lastObservedAt: finding.lastObservedAt,
      });
      return;
    }
    existing.totalFindings += 1;
    if (isOpen) existing.openFindings += 1;
    if ((SEVERITY_RANK[finding.severity.toUpperCase()] ?? 99) < (SEVERITY_RANK[existing.worstSeverity.toUpperCase()] ?? 99)) {
      existing.worstSeverity = finding.severity;
    }
    if (new Date(finding.lastObservedAt).getTime() > new Date(existing.lastObservedAt).getTime()) {
      existing.lastObservedAt = finding.lastObservedAt;
    }
  });
  return Array.from(byArtifact.values())
    .sort((left, right) => (SEVERITY_RANK[left.worstSeverity.toUpperCase()] ?? 99) - (SEVERITY_RANK[right.worstSeverity.toUpperCase()] ?? 99));
}

function conditionValueOptions(field: string): Array<{ value: string; label: string }> {
  return CONDITION_VALUE_OPTIONS[field] ?? [];
}

function PolicyEvidenceMetadata({ policy }: { policy: AiGridPolicy }) {
  const evidenceTiers = parseJsonArray(policy.baseEvidenceTiersJson);
  const conditionalCapabilities = parseJsonArray(policy.conditionalCapabilitiesJson);
  const mappings = parseFrameworkMappings(policy.frameworkMappingsJson);

  return (
    <div className="cvd2-panel">
      <div className="cvd2-panel-hdr">Evidence &amp; Framework Mappings</div>
      <div className="ai-policy-overview-metadata">
        <div className="ai-policy-detail">
        <p className="ai-policy-detail-evidence">
          <strong>Evidence tiers:</strong> {evidenceTiers.length > 0 ? evidenceTiers.join(', ') : '—'}
        </p>
        <div className="ai-policy-detail-block">
          <strong>Required connector capabilities</strong>
          {conditionalCapabilities.length === 0 ? (
            <p>None — decides from base connector evidence.</p>
          ) : (
            <ul className="ai-policy-setup-list">
              {conditionalCapabilities.map((capability) => (
                <li key={capability}>
                  Enable <code>{formatLabel(capability)}</code> in the connector to make this policy decision-capable; without it the policy reports <em>NO_DECISION</em>.
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="ai-policy-detail-block">
          <strong>Framework mappings</strong>
          {mappings.length === 0 ? (
            <p>No structured framework mappings.</p>
          ) : (
            <ul className="ai-policy-mapping-list">
              {mappings.map((mapping, index) => (
                <li key={`${mapping.framework}-${mapping.controlId}-${index}`}>
                  <strong>{mapping.framework} {mapping.frameworkVersion}</strong> · {mapping.controlId} <span className="ai-policy-mapping-type">{mapping.mappingType}</span>
                  {mapping.rationale ? <><br /><small>{mapping.rationale}</small></> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
        </div>
      </div>
    </div>
  );
}

function coverageStatusLabel(status: 'PASS' | 'FAIL' | 'NO_DATA'): string {
  if (status === 'NO_DATA') return 'Coverage not measured';
  return status === 'PASS' ? 'Pilot coverage gate passed' : 'Pilot coverage gate blocked';
}

type DraftScope = {
  mode: PolicyScopeMode;
  conditionLogic: 'AND' | 'OR';
  conditions: PolicyScopeCondition[];
};

export function AiPolicyDetailPage({ policyId }: { policyId: string }) {
  const actor = useActor();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const canManage = hasRole(actor, 'TENANT_ADMIN') || hasRole(actor, 'PLATFORM_OWNER') || hasRole(actor, 'SECURITY_ANALYST');
  const [tab, setTab] = React.useState<PolicyDetailTab>('overview');
  const [findingsStatusFilter, setFindingsStatusFilter] = React.useState('OPEN');

  const policiesQuery = useQuery({
    queryKey: ['ai-security-policy', policyId],
    queryFn: () => api.getAiGridPolicyDetail(policyId),
  });
  const policyMetadataQuery = useQuery({
    queryKey: ['ai-grid-policies'],
    queryFn: api.listAiGridPolicies,
  });
  const findingsQuery = useQuery({
    queryKey: ['ai-security-findings-for-policy', policyId],
    queryFn: () => api.listAiSecurityFindings(policyId, undefined, 0, 200),
  });
  const mutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.updateAiGridPolicySelection(id, enabled ? 'ENABLED' : 'DISABLED'),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['ai-security-policies'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-policies'] });
    },
  });

  const policyMetadata: AiGridPolicy | null = policyMetadataQuery.data?.find((item) => item.policyId === policyId) ?? null;
  const nativeKinds = parseJsonArray(policyMetadata?.nativeKindsJson);
  const legacyPolicy = policiesQuery.data ?? null;
  const policy: AiSecurityPolicy | null = legacyPolicy ?? (policyMetadata ? {
    id: policyMetadata.policyId,
    version: policyMetadata.version,
    name: policyMetadata.name,
    severity: policyMetadata.severity,
    artifactTypes: [],
    requiredResourceFamilies: [],
    description: `${policyMetadata.provider} governed AI security policy evaluated with ${policyMetadata.evaluationMode}.`,
    remediation: 'Review the policy evidence and remediate any failing control objective.',
    controlMappings: {},
    available: true,
    enabled: policyMetadata.selection !== 'DISABLED',
    openFindings: 0,
    lifetimeFindings: 0,
    lastEvaluatedAt: null,
    decisionCoverage: 0,
    decisionCoverageThreshold: 1,
    decisionCoverageStatus: 'NO_DATA',
    evaluatedArtifacts: 0,
    noDecisionCount: 0,
    lifecycle: policyMetadata.lifecycle,
    inactiveReason: null,
  } : null);
  const allFindings = React.useMemo(() => findingsQuery.data?.items ?? [], [findingsQuery.data?.items]);
  const visibleFindings = React.useMemo(() => (
    findingsStatusFilter ? allFindings.filter((finding) => finding.status === findingsStatusFilter) : allFindings
  ), [allFindings, findingsStatusFilter]);
  const impactedArtifacts = React.useMemo(() => buildImpactedArtifacts(allFindings), [allFindings]);

  const configQuery = useQuery({
    queryKey: ['ai-security-policy-configuration', policyId],
    queryFn: () => api.getAiGridPolicyConfiguration(policyId),
    refetchInterval: (query) => assessmentPending(query.state.data) ? 5000 : false,
  });
  const configuration = configQuery.data ?? null;
  React.useEffect(() => {
    if (configuration?.assessmentStatus && !assessmentPending(configuration)) {
      void queryClient.invalidateQueries({ queryKey: ['ai-security-findings-for-policy', policyId] });
      void queryClient.invalidateQueries({ queryKey: ['ai-grid-policies'] });
      void queryClient.invalidateQueries({ queryKey: ['ai-assessment-states-latest'] });
    }
  }, [configuration, policyId, queryClient]);


  const [draftScope, setDraftScope] = React.useState<DraftScope | null>(null);
  const [scopeDirty, setScopeDirty] = React.useState(false);
  React.useEffect(() => {
    if (configuration && !scopeDirty) {
      setDraftScope({
        mode: configuration.scope.mode,
        conditionLogic: configuration.scope.conditionLogic,
        conditions: configuration.scope.conditions,
      });
    }
  }, [configuration, scopeDirty]);

  const [draftParameters, setDraftParameters] = React.useState<Record<string, string>>({});
  const [parametersDirty, setParametersDirty] = React.useState(false);
  React.useEffect(() => {
    if (configuration && !parametersDirty) {
      const next: Record<string, string> = {};
      configuration.parameters.forEach((param) => { next[param.key] = param.value; });
      setDraftParameters(next);
    }
  }, [configuration, parametersDirty]);

  const refreshAfterConfigChange = React.useCallback(() => {
    void invalidateAiAssessmentQueries(queryClient);
  }, [queryClient]);

  const scopeMutation = useMutation({
    mutationFn: () => {
      if (!draftScope) throw new Error('Scope is not loaded yet');
      return api.updateAiGridPolicyScope(policyId, draftScope.mode, draftScope.conditionLogic, draftScope.conditions);
    },
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setScopeDirty(false);
      refreshAfterConfigChange();
    },
  });

  const parametersMutation = useMutation({
    mutationFn: () => api.updateAiGridPolicyParameters(policyId, draftParameters),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setParametersDirty(false);
      refreshAfterConfigChange();
    },
  });

  const [exceptionConditionLogic, setExceptionConditionLogic] = React.useState<'AND' | 'OR'>('AND');
  const [exceptionConditions, setExceptionConditions] = React.useState<PolicyScopeCondition[]>([
    { field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: '' },
  ]);
  const [exceptionOverride, setExceptionOverride] = React.useState<PolicyExceptionOverride>('EXCLUDED');
  const [exceptionReason, setExceptionReason] = React.useState('');

  const addExceptionRuleMutation = useMutation({
    mutationFn: () => api.addAiGridPolicyExceptionRule(
      policyId, exceptionConditionLogic, exceptionConditions, exceptionOverride, exceptionReason || undefined,
    ),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      setExceptionConditions([{ field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: '' }]);
      setExceptionReason('');
      refreshAfterConfigChange();
    },
  });
  const removeExceptionMutation = useMutation({
    mutationFn: (artifactId: string) => api.removeAiGridPolicyException(policyId, artifactId),
    onSuccess: (data) => {
      queryClient.setQueryData(['ai-security-policy-configuration', policyId], data);
      refreshAfterConfigChange();
    },
  });

  const explainQuery = useQuery({
    queryKey: ['ai-security-policy-explain', policyId],
    queryFn: () => api.explainAiGridPolicy(policyId),
    enabled: false,
  });

  const updateCondition = (index: number, next: PolicyScopeCondition) => {
    if (!draftScope) return;
    const conditions = draftScope.conditions.slice();
    conditions[index] = next;
    setDraftScope({ ...draftScope, conditions });
    setScopeDirty(true);
  };
  const removeCondition = (index: number) => {
    if (!draftScope) return;
    setDraftScope({ ...draftScope, conditions: draftScope.conditions.filter((_, i) => i !== index) });
    setScopeDirty(true);
  };
  const addCondition = () => {
    if (!draftScope) return;
    setDraftScope({
      ...draftScope,
      conditions: [...draftScope.conditions, { field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: '' }],
    });
    setScopeDirty(true);
  };
  const addAttributeCondition = () => {
    if (!draftScope) return;
    setDraftScope({
      ...draftScope,
      conditions: [...draftScope.conditions, newConditionFor(draftScope.conditions)],
    });
    setScopeDirty(true);
  };
  const updateExceptionCondition = (index: number, next: PolicyScopeCondition) => {
    setExceptionConditions((current) => current.map((condition, conditionIndex) => conditionIndex === index ? next : condition));
  };
  const addExceptionCondition = () => {
    setExceptionConditions((current) => [...current, newConditionFor(current)]);
  };
  const addExceptionTopLevelCondition = () => {
    setExceptionConditions((current) => [...current, { field: 'ARTIFACT_TYPE', operator: 'EQUALS', value: '' }]);
  };
  const removeExceptionCondition = (index: number) => {
    setExceptionConditions((current) => current.filter((_, conditionIndex) => conditionIndex !== index));
  };

  if (policiesQuery.isLoading && policyMetadataQuery.isLoading) {
    return <section className="panel"><div className="empty-state"><p>Loading policy…</p></div></section>;
  }
  if (policiesQuery.isError && policyMetadataQuery.isError) {
    return <section className="panel"><div className="notice error">AI Security policies could not be loaded.</div></section>;
  }
  if (!policy) {
    return (
      <section className="panel">
        <div className="empty-state">
          <p>Policy <strong>{policyId}</strong> was not found.</p>
          <button type="button" className="btn btn-secondary" onClick={() => navigate('/policies')}>← Back to Policies</button>
        </div>
      </section>
    );
  }

  return (
    <div className="cvd2-page ai-policy-detail-page">
      {configuration?.assessmentStatus ? <p role="status" className="notice">{assessmentMessage(configuration)}</p> : null}
      <div className="ai-policy-detail-topbar">
        <button type="button" className="cvd-ov-link" onClick={() => navigate('/policies')}>← Back to Policies</button>
        <label className="ai-policy-switch">
          <input
            type="checkbox"
            checked={policy.enabled}
            disabled={!canManage || mutation.isPending || policy.lifecycle === 'DEPRECATED'}
            onChange={(event) => mutation.mutate({ id: policy.id, enabled: event.target.checked })}
          />
          <span>{policy.lifecycle === 'DEPRECATED' ? 'Deprecated · inactive' : policy.enabled ? 'Enabled' : 'Disabled'}</span>
        </label>
      </div>

      <div className="cvd2-tab-bar">
        <button type="button" className={`cvd2-tab${tab === 'overview' ? ' active' : ''}`} onClick={() => setTab('overview')}>
          Overview
        </button>
        <button type="button" className={`cvd2-tab${tab === 'configure' ? ' active' : ''}`} onClick={() => setTab('configure')}>
          Governance
        </button>
        <button type="button" className={`cvd2-tab${tab === 'findings' ? ' active' : ''}`} onClick={() => setTab('findings')}>
          Findings · {policy.openFindings}
        </button>
        <button type="button" className={`cvd2-tab${tab === 'artifacts' ? ' active' : ''}`} onClick={() => setTab('artifacts')}>
          AI Artifacts · {impactedArtifacts.length}
        </button>
      </div>

      <div className="cvd2-tab-content">
        {tab === 'overview' && (
          <div className="cvd2-overview-body">
            <div className="cvd2-overview-main">
              <div className="cvd2-panel">
                <div className="cvd-ov-left">
                  <div className="cvd-ov-meta">
                    <span className={`cvd-status-pill ${policy.enabled ? 'cvd-status-ok' : 'cvd-status-neutral'}`}>
                      {policy.lifecycle === 'DEPRECATED' ? 'Deprecated · inactive' : policy.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                    {policy.lastEvaluatedAt && (
                      <span className="cvd-ov-meta-eval">· Last evaluated {formatDate(policy.lastEvaluatedAt)}</span>
                    )}
                  </div>
                  <div className="cvd-ov-first-seen">{policy.id}</div>
                  <h1 className="cvd-ov-cve-id">{policy.name}</h1>
                  <div className="cvd-ov-badges">
                    <span className={severityClassName(policy.severity)}>{policy.severity}</span>
                    <span className="cvd-signal-pill">Coverage {Math.round(policy.decisionCoverage * 100)}%</span>
                    <span className="cvd-signal-pill">{policy.openFindings} open finding{policy.openFindings === 1 ? '' : 's'}</span>
                    <span className="cvd-signal-pill">{impactedArtifacts.length} artifact{impactedArtifacts.length === 1 ? '' : 's'} impacted</span>
                    <span className="cvd-signal-pill">{policy.requiredResourceFamilies.length} evidence source{policy.requiredResourceFamilies.length === 1 ? '' : 's'}</span>
                    {configuration && configuration.scope.mode !== 'ALL' && (
                      <span className="cvd-signal-pill ai-policy-scope-pill">
                        Scoped · {configuration.matchedArtifactCount} of {configuration.totalArtifactCount}
                      </span>
                    )}
                  </div>
                </div>
                <p className="cvd-ov-description">{policy.description}</p>
                <div className="cvd-ov-divider" />
                <div className="cvd-ov-links">
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('configure')}>
                    Open governance controls →
                  </button>
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('findings')}>
                    {policy.openFindings} open finding{policy.openFindings === 1 ? '' : 's'} →
                  </button>
                  <button type="button" className="cvd-ov-link" onClick={() => setTab('artifacts')}>
                    {impactedArtifacts.length} AI artifact{impactedArtifacts.length === 1 ? '' : 's'} impacted →
                  </button>
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Policy Details</div>
                <div className="cvd-tech-attrs">
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Policy ID</span>
                    <span className="cvd-tech-attr-value mono">{policy.id}</span>
                  </div>
                  <div className="cvd-tech-attr">
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Artifact types</span>
                    <span className="cvd-tech-attr-value">{policy.artifactTypes.map((type) => formatLabel(type)).join(', ')}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Native types</span>
                    <span className="cvd-tech-attr-value">{nativeKinds.length ? nativeKinds.map((type) => formatLabel(type)).join(', ') : 'Not specified'}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Lifetime findings</span>
                    <span className="cvd-tech-attr-value">{policy.lifetimeFindings.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Last evaluated</span>
                    <span className="cvd-tech-attr-value">{policy.lastEvaluatedAt ? formatDate(policy.lastEvaluatedAt) : 'Never'}</span>
                  </div>
                </div>
              </div>

              {policyMetadata && (
                <PolicyEvidenceMetadata policy={policyMetadata} />
              )}

              {Object.keys(policy.controlMappings).length > 0 && (
                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Control Mappings · {Object.keys(policy.controlMappings).length}</div>
                  <div className="cvd-refs-list">
                    {Object.entries(policy.controlMappings).map(([framework, control]) => (
                      <div key={framework} className="cvd-ref-row">
                        <span style={{ color: 'var(--title)', fontSize: 13, fontWeight: 500 }}>{framework}</span>
                        <span className="cvd-src-tag">{control}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="cvd2-overview-sidebar">
              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Decision Coverage</div>
                <div className={`ai-policy-coverage-gate ${policy.decisionCoverageStatus.toLowerCase()}`} style={{ margin: 16, borderRadius: 'var(--radius-md)' }}>
                  <strong style={{ fontSize: '1.6rem', fontFamily: 'var(--font-display)' }}>
                    {Math.round(policy.decisionCoverage * 100)}%
                  </strong>
                  <span>{coverageStatusLabel(policy.decisionCoverageStatus)}</span>
                </div>
                <div className="cvd-tech-attrs">
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Evaluated</span>
                    <span className="cvd-tech-attr-value">{policy.evaluatedArtifacts.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">No decision</span>
                    <span className="cvd-tech-attr-value">{policy.noDecisionCount.toLocaleString()}</span>
                  </div>
                  <div className="cvd-tech-attr">
                    <span className="cvd-tech-attr-label">Required</span>
                    <span className="cvd-tech-attr-value">{Math.round(policy.decisionCoverageThreshold * 100)}%</span>
                  </div>
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Required Evidence · {policy.requiredResourceFamilies.length}</div>
                <div className="cvd2-wf-cards">
                  {policy.requiredResourceFamilies.map((family, index) => (
                    <div key={family} className="cvd2-wf-card" style={{ cursor: 'default' }}>
                      <div className="cvd2-wf-card-num">{index + 1}</div>
                      <div className="cvd2-wf-card-body">
                        <div className="cvd2-wf-card-title-row">
                          <span className="cvd2-wf-card-title">{formatLabel(family)}</span>
                          <span className="cvd-wf-badge cvd-wf-badge--pending">Required</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="cvd2-panel">
                <div className="cvd2-panel-hdr">Remediation</div>
                <p className="cvd-ov-description" style={{ padding: 16 }}>{policy.remediation}</p>
              </div>
            </div>
          </div>
        )}

        {tab === 'configure' && (
          configQuery.isLoading || !draftScope ? (
            <div className="empty-state"><p>Loading configuration…</p></div>
          ) : configQuery.isError || !configuration ? (
            <div className="notice error">This policy's configuration could not be loaded.</div>
          ) : (
            <div className="cvd2-overview-body ai-policy-governance">
              <div className="cvd2-overview-main">
                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Governance boundary</div>
                  <div className="cvd-tech-attrs">
                    <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Platform baseline</span><span className="cvd-tech-attr-value">{configuration.governance.platformPolicyVersion ?? '—'} · {formatLabel(configuration.governance.platformLifecycle ?? '—')}</span></div>
                    <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Tenant state</span><span className="cvd-tech-attr-value">{formatLabel(configuration.governance.configurationSource)}</span></div>
                  </div>
                  <p className="panel-caption">The platform owns the policy definition and release lifecycle. This tenant can configure scope, exceptions, and parameters only when the platform permits it.</p>
                </div>
                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Scope · which AI inventory this policy evaluates</div>
                  <div className="ai-policy-config-body">
                    <p className="card-note">
                      Artifacts outside scope are skipped entirely — any existing finding for them is suppressed, not just hidden.
                    </p>
                    <div className="ai-policy-scope-modes" role="tablist" aria-label="Scope mode">
                      {SCOPE_MODE_OPTIONS.map((option) => (
                        <button
                          key={option.value}
                          type="button"
                          className={`ai-policy-scope-mode-btn${draftScope.mode === option.value ? ' active' : ''}`}
                          disabled={!canManage}
                          onClick={() => { setDraftScope({ ...draftScope, mode: option.value }); setScopeDirty(true); }}
                        >
                          {option.label}
                        </button>
                      ))}
                    </div>

                    {draftScope.mode === 'MATCH_RULES' && (
                      <>
                        <div className="ai-policy-rule-logic">
                          <strong>Conditions</strong>
                          <span>Match</span>
                          <div className="ai-policy-scope-modes ai-policy-rule-logic-toggle">
                            {(['AND', 'OR'] as const).map((logic) => (
                              <button
                                key={logic}
                                type="button"
                                className={`ai-policy-scope-mode-btn${draftScope.conditionLogic === logic ? ' active' : ''}`}
                                disabled={!canManage}
                                onClick={() => { setDraftScope({ ...draftScope, conditionLogic: logic }); setScopeDirty(true); }}
                              >
                                {logic === 'AND' ? 'ALL' : 'ANY'}
                              </button>
                            ))}
                          </div>
                          of the following conditions
                        </div>
                        {selectedArtifactType(draftScope.conditions) && (
                          <div className="ai-policy-attribute-hint">
                            {artifactTypeLabel(selectedArtifactType(draftScope.conditions))} attributes: Name, Provider, Region, Account ID, and Native type
                          </div>
                        )}
                        {draftScope.conditions.map((condition, index) => (
                          <React.Fragment key={`${condition.field}-${index}`}>
                          {index > 0 && !isArtifactAttributeChild(draftScope.conditions, index) && <div className="ai-policy-condition-joiner">{draftScope.conditionLogic}</div>}
                          {isFirstArtifactAttributeChild(draftScope.conditions, index) && (
                            <div className="ai-policy-condition-child-label">Attributes for {artifactTypeLabel(selectedArtifactType(draftScope.conditions))}</div>
                          )}
                          <div className={`ai-policy-rule-row${isArtifactAttributeChild(draftScope.conditions, index) ? ' ai-policy-condition-child' : ''}`}>
                            <select
                              value={condition.field}
                              disabled={!canManage}
                              onChange={(event) => updateCondition(index, { ...condition, field: event.target.value, value: '' })}
                            >
                              {conditionFieldOptions(draftScope.conditions).map((option) => (
                                <option key={option.value} value={option.value}>{option.label}</option>
                              ))}
                            </select>
                            <select
                              value={condition.operator}
                              disabled={!canManage}
                              onChange={(event) => updateCondition(index, { ...condition, operator: event.target.value })}
                            >
                              {SCOPE_OPERATOR_OPTIONS.map((option) => (
                                <option key={option.value} value={option.value}>{option.label}</option>
                              ))}
                            </select>
                            {conditionValueOptions(condition.field).length > 0 ? (
                              <>
                                <select
                                  className="ai-policy-condition-value-select"
                                  value={conditionValueOptions(condition.field).some((option) => option.value === condition.value) ? condition.value : '__OTHER__'}
                                  disabled={!canManage}
                                  aria-label="Condition value category"
                                  onChange={(event) => updateCondition(index, { ...condition, value: event.target.value === '__OTHER__' ? '' : event.target.value })}
                                >
                                  <option value="__OTHER__">Other</option>
                                  {conditionValueOptions(condition.field).map((option) => (
                                    <option key={option.value} value={option.value}>{option.label}</option>
                                  ))}
                                </select>
                                {!conditionValueOptions(condition.field).some((option) => option.value === condition.value) && (
                                  <input
                                    type="text"
                                    value={condition.value}
                                    disabled={!canManage}
                                    placeholder="Enter value"
                                    aria-label="Custom condition value"
                                    onChange={(event) => updateCondition(index, { ...condition, value: event.target.value })}
                                  />
                                )}
                              </>
                            ) : (
                              <input
                                type="text"
                                value={condition.value}
                                disabled={!canManage}
                                placeholder="Enter value"
                                onChange={(event) => updateCondition(index, { ...condition, value: event.target.value })}
                              />
                            )}
                            <button
                              type="button"
                              className="ai-policy-rule-remove"
                              aria-label="Remove condition"
                              disabled={!canManage}
                              onClick={() => removeCondition(index)}
                            >
                              ✕
                            </button>
                          </div>
                          </React.Fragment>
                        ))}
                        <div className="ai-policy-condition-actions">
                          <button type="button" className="ai-policy-add-row" disabled={!canManage} onClick={addCondition}>
                            + Add condition
                          </button>
                          {selectedArtifactType(draftScope.conditions) && (
                            <button type="button" className="ai-policy-add-row" disabled={!canManage} onClick={addAttributeCondition}>
                              + Add artifact attribute
                            </button>
                          )}
                        </div>
                      </>
                    )}

                    {draftScope.mode === 'CUSTOM_LIST' && (
                      <p className="card-note">
                        Nothing is in scope by default. Mark specific artifacts as “Included” in Exceptions below.
                      </p>
                    )}

                    <div className="ai-policy-scope-preview">
                      <span>
                        <strong>{configuration.matchedArtifactCount} of {configuration.totalArtifactCount}</strong>{' '}
                        eligible artifact{configuration.totalArtifactCount === 1 ? '' : 's'} currently match this scope
                      </span>
                    </div>

                    <div className="button-row" style={{ marginTop: 12 }}>
                      <button
                        type="button"
                        className="btn btn-primary"
                        disabled={!canManage || !scopeDirty || scopeMutation.isPending}
                        onClick={() => scopeMutation.mutate()}
                      >
                        {scopeMutation.isPending ? 'Saving…' : 'Save scope'}
                      </button>
                    </div>
                  </div>
                </div>

                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Exceptions · {configuration.exceptions.length}</div>
                  <div className="ai-policy-config-body">
                    {configuration.exceptions.length === 0 ? (
                      <p className="card-note">No per-artifact overrides yet.</p>
                    ) : (
                      configuration.exceptions.map((exception) => (
                        <div className="ai-policy-exception-row" key={exception.artifactId}>
                          <div>
                            <div className="ai-policy-exception-name">{exception.artifactName}</div>
                            <div className="panel-caption">
                              {exception.override === 'EXCLUDED' ? 'Excluded' : 'Included'} by {exception.createdBy} · {formatDate(exception.createdAt)}
                              {exception.reason ? ` · "${exception.reason}"` : ''}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="ai-policy-rule-remove"
                            aria-label={`Remove exception for ${exception.artifactName}`}
                            disabled={!canManage || removeExceptionMutation.isPending}
                            onClick={() => removeExceptionMutation.mutate(exception.artifactId)}
                          >
                            ✕
                          </button>
                        </div>
                      ))
                    )}

                    {canManage && (
                      <div className="ai-policy-add-exception">
                        <div className="ai-policy-exception-rule-heading">
                          <strong>Exception rule</strong>
                          <span>Apply this action to artifacts matching</span>
                          <div className="ai-policy-scope-modes ai-policy-rule-logic-toggle">
                            {(['AND', 'OR'] as const).map((logic) => (
                              <button
                                key={logic}
                                type="button"
                                className={`ai-policy-scope-mode-btn${exceptionConditionLogic === logic ? ' active' : ''}`}
                                onClick={() => setExceptionConditionLogic(logic)}
                              >
                                {logic === 'AND' ? 'ALL' : 'ANY'}
                              </button>
                            ))}
                          </div>
                          <span>of these conditions:</span>
                        </div>
                        {selectedArtifactType(exceptionConditions) && (
                          <div className="ai-policy-attribute-hint">
                            {artifactTypeLabel(selectedArtifactType(exceptionConditions))} attributes: Name, Provider, Region, Account ID, and Native type
                          </div>
                        )}
                        {exceptionConditions.map((condition, index) => (
                          <React.Fragment key={`exception-condition-${index}`}>
                            {index > 0 && !isArtifactAttributeChild(exceptionConditions, index) && <div className="ai-policy-condition-joiner">{exceptionConditionLogic}</div>}
                            {isFirstArtifactAttributeChild(exceptionConditions, index) && (
                              <div className="ai-policy-condition-child-label">Attributes for {artifactTypeLabel(selectedArtifactType(exceptionConditions))}</div>
                            )}
                            <div className={`ai-policy-rule-row ai-policy-exception-condition-row${isArtifactAttributeChild(exceptionConditions, index) ? ' ai-policy-condition-child' : ''}`}>
                              <select
                                aria-label="Exception field"
                                value={condition.field}
                                onChange={(event) => updateExceptionCondition(index, { ...condition, field: event.target.value, value: '' })}
                              >
                                {conditionFieldOptions(exceptionConditions).map((option) => (
                                  <option key={option.value} value={option.value}>{option.label}</option>
                                ))}
                              </select>
                              <select
                                aria-label="Exception operator"
                                value={condition.operator}
                                onChange={(event) => updateExceptionCondition(index, { ...condition, operator: event.target.value })}
                              >
                                {SCOPE_OPERATOR_OPTIONS.map((option) => (
                                  <option key={option.value} value={option.value}>{option.label}</option>
                                ))}
                              </select>
                              {conditionValueOptions(condition.field).length > 0 ? (
                                <>
                                  <select
                                    className="ai-policy-condition-value-select"
                                    aria-label="Exception value category"
                                    value={conditionValueOptions(condition.field).some((option) => option.value === condition.value) ? condition.value : '__OTHER__'}
                                    onChange={(event) => updateExceptionCondition(index, { ...condition, value: event.target.value === '__OTHER__' ? '' : event.target.value })}
                                  >
                                    <option value="__OTHER__">Other</option>
                                    {conditionValueOptions(condition.field).map((option) => (
                                      <option key={option.value} value={option.value}>{option.label}</option>
                                    ))}
                                  </select>
                                  {!conditionValueOptions(condition.field).some((option) => option.value === condition.value) && (
                                    <input
                                      type="text"
                                      aria-label="Custom exception value"
                                      placeholder="Enter value"
                                      value={condition.value}
                                      onChange={(event) => updateExceptionCondition(index, { ...condition, value: event.target.value })}
                                    />
                                  )}
                                </>
                              ) : (
                                <input
                                  type="text"
                                  aria-label="Exception value"
                                  placeholder="Enter value"
                                  value={condition.value}
                                  onChange={(event) => updateExceptionCondition(index, { ...condition, value: event.target.value })}
                                />
                              )}
                              <button
                                type="button"
                                className="ai-policy-rule-remove"
                                aria-label="Remove exception condition"
                                disabled={exceptionConditions.length === 1}
                                onClick={() => removeExceptionCondition(index)}
                              >
                                ✕
                              </button>
                            </div>
                          </React.Fragment>
                        ))}
                        <div className="ai-policy-condition-actions">
                          <button type="button" className="ai-policy-add-row" onClick={addExceptionTopLevelCondition}>
                            + Add condition
                          </button>
                          {selectedArtifactType(exceptionConditions) && (
                            <button type="button" className="ai-policy-add-row" onClick={addExceptionCondition}>
                              + Add artifact attribute
                            </button>
                          )}
                        </div>
                        <select
                          aria-label="Override"
                          value={exceptionOverride}
                          onChange={(event) => setExceptionOverride(event.target.value as PolicyExceptionOverride)}
                        >
                          <option value="EXCLUDED">Exclude</option>
                          <option value="INCLUDED">Include</option>
                        </select>
                        <input
                          type="text"
                          placeholder="Reason (optional)"
                          value={exceptionReason}
                          onChange={(event) => setExceptionReason(event.target.value)}
                        />
                        <button
                          type="button"
                          className="btn btn-secondary btn-sm"
                          disabled={exceptionConditions.some((condition) => !condition.value.trim()) || addExceptionRuleMutation.isPending}
                          onClick={() => addExceptionRuleMutation.mutate()}
                        >
                          {addExceptionRuleMutation.isPending ? 'Applying…' : '+ Apply exception rule'}
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                <div className="cvd2-panel">
                  <div className="cvd2-panel-hdr">Parameters · tenant-tuned thresholds</div>
                  <div className="ai-policy-config-body">
                    {configuration.parameters.length === 0 ? (
                      <p className="card-note">
                        This policy has no tenant-configurable parameters — it evaluates a fixed condition.
                      </p>
                    ) : (
                      <>
                        {configuration.parameters.map((param) => (
                          <div className="ai-policy-param-row" key={param.key}>
                            <div>
                              <div className="ai-policy-param-label">{param.label}</div>
                              <div className="panel-caption">{param.helpText}</div>
                              <div className="panel-caption">Platform default: {formatLabel(param.defaultValue)}</div>
                            </div>
                            <select
                              value={draftParameters[param.key] ?? param.value}
                              disabled={!canManage}
                              onChange={(event) => {
                                setDraftParameters({ ...draftParameters, [param.key]: event.target.value });
                                setParametersDirty(true);
                              }}
                            >
                              {param.options.map((option) => (
                                <option key={option} value={option}>{formatLabel(option)}</option>
                              ))}
                            </select>
                          </div>
                        ))}
                        <div className="button-row" style={{ marginTop: 12 }}>
                          <button
                            type="button"
                            className="btn btn-primary"
                            disabled={!canManage || !parametersDirty || parametersMutation.isPending}
                            onClick={() => parametersMutation.mutate()}
                          >
                            {parametersMutation.isPending ? 'Saving…' : 'Save parameters'}
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div className="cvd2-overview-sidebar">
                <div className="cvd2-panel ai-policy-assist-card">
                  <div className="cvd2-panel-hdr"><span className="ai-assist-badge">AI</span>Assist</div>
                  <div className="ai-policy-config-body">
                    <div className="ai-policy-assist-action">
                      <div className="ai-policy-assist-title">Explain this policy for our environment</div>
                      <p className="panel-caption">
                        Reads your current AI inventory and open findings to translate the policy into what it means for your tenant right now.
                      </p>
                      <button
                        type="button"
                        className="btn btn-ai btn-sm"
                        disabled={explainQuery.isFetching}
                        onClick={() => void explainQuery.refetch()}
                      >
                        {explainQuery.isFetching ? 'Thinking…' : explainQuery.data ? 'Regenerate' : 'Explain'}
                      </button>
                      {explainQuery.data && <div className="ai-policy-assist-result">{explainQuery.data.summary}</div>}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )
        )}

        {tab === 'findings' && (
          <div className="cvd2-panel">
            <div className="cvd2-panel-hdr ai-policy-detail-panel-hdr-row">
              <span>Findings · {visibleFindings.length}</span>
              <select
                value={findingsStatusFilter}
                onChange={(event) => setFindingsStatusFilter(event.target.value)}
                aria-label="Finding status"
              >
                <option value="OPEN">Open</option>
                <option value="RESOLVED">Resolved</option>
                <option value="SUPPRESSED_BY_POLICY">Suppressed by policy</option>
                <option value="">All states</option>
              </select>
            </div>
            {findingsQuery.isLoading ? (
              <div className="empty-state"><p>Loading findings…</p></div>
            ) : findingsQuery.isError ? (
              <div className="notice error">AI findings could not be loaded.</div>
            ) : visibleFindings.length === 0 ? (
              <div className="empty-state"><p>No findings match this filter.</p></div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>Finding</th><th>Artifact</th><th>State</th><th>Observed</th></tr>
                </thead>
                <tbody>
                  {visibleFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td><span className={severityClassName(finding.severity)}>{finding.severity}</span><strong>{finding.displayId}</strong><small>{finding.title}</small></td>
                      <td>{finding.artifactName}</td>
                      <td><span className="status-pill">{finding.status.replace(/_/g, ' ')}</span></td>
                      <td>{timeAgo(finding.lastObservedAt) ?? 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {tab === 'artifacts' && (
          <div className="cvd2-panel">
            <div className="cvd2-panel-hdr">AI Artifacts Impacted · {impactedArtifacts.length}</div>
            {findingsQuery.isLoading ? (
              <div className="empty-state"><p>Loading impacted artifacts…</p></div>
            ) : findingsQuery.isError ? (
              <div className="notice error">AI findings could not be loaded.</div>
            ) : impactedArtifacts.length === 0 ? (
              <div className="empty-state"><p>No AI artifacts have findings from this policy.</p></div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr><th>Artifact</th><th>Worst severity</th><th>Open findings</th><th>Total findings</th><th>Last observed</th></tr>
                </thead>
                <tbody>
                  {impactedArtifacts.map((artifact) => (
                    <tr key={artifact.artifactId}>
                      <td><strong>{artifact.artifactName}</strong><small>{artifact.artifactId}</small></td>
                      <td><span className={severityClassName(artifact.worstSeverity)}>{artifact.worstSeverity}</span></td>
                      <td>{artifact.openFindings}</td>
                      <td>{artifact.totalFindings}</td>
                      <td>{timeAgo(artifact.lastObservedAt) ?? 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
