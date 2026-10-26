import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { pathForPlatformPolicyDetail } from '../app/routes';
import type { AiGridPolicyDistribution, AiGridPolicySelection } from '../features/ai-security/types';

const DEFAULTS: AiGridPolicySelection[] = ['REQUIRED', 'ENABLED', 'PREVIEW', 'DISABLED'];
const ROLLOUTS: AiGridPolicyDistribution['rolloutStage'][] = ['GENERAL_AVAILABILITY', 'CANARY', 'DEV', 'PAUSED', 'RETIRED'];

function owaspMappings(value?: string): string {
  try {
    return (JSON.parse(value ?? '[]') as Array<{ framework?: string; controlId?: string; mappingType?: string }>)
      .filter((mapping) => mapping.framework?.startsWith('OWASP_') && Boolean(mapping.controlId))
      .map((mapping) => `${mapping.controlId} (${mapping.mappingType === 'INFORMATIVE' ? 'SUPPORTING (legacy)' : mapping.mappingType})`).join(', ') || '—';
  } catch { return '—'; }
}

function frameworkMappings(value?: string, labels: Map<string, string> = new Map()): string {
  try {
    const mappings = JSON.parse(value ?? '[]') as Array<{ framework?: string; frameworkVersion?: string; controlId?: string; mappingType?: string }>;
    return mappings.map((mapping) => {
      const framework = labels.get(`${mapping.framework}:${mapping.frameworkVersion}`)
        ?? (mapping.framework ?? 'Unknown framework').replace(/_/g, ' ');
      const version = mapping.frameworkVersion ? ` ${mapping.frameworkVersion}` : '';
      const control = mapping.controlId ? ` · ${mapping.controlId}` : '';
      const kind = mapping.mappingType ? ` (${mapping.mappingType === 'INFORMATIVE' ? 'SUPPORTING (legacy)' : mapping.mappingType})` : '';
      return `${framework}${version}${control}${kind}`;
    }).filter(Boolean).join(', ') || '—';
  } catch { return '—'; }
}

function rolloutLabel(stage: AiGridPolicyDistribution['rolloutStage']): string {
  return stage === 'GENERAL_AVAILABILITY' ? 'General availability' : stage === 'DEV' ? 'Dev / test' : stage.charAt(0) + stage.slice(1).toLowerCase();
}

function statusClass(value: string): string {
  return `policy-status policy-status--${value.toLowerCase().replace(/_/g, '-')}`;
}

function jsonLabels(value?: string): string {
  try {
    const parsed = JSON.parse(value ?? '[]');
    return Array.isArray(parsed) && parsed.length ? parsed.map(String).map((item) => item.replace(/_/g, ' ')).join(', ') : '—';
  } catch { return '—'; }
}

export function PlatformAiPolicyStudio() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const [provider, setProvider] = React.useState('ALL');
  const [rollout, setRollout] = React.useState('ALL');
  const [selection, setSelection] = React.useState('ALL');
  const [owasp, setOwasp] = React.useState('ALL');
  const [query, setQuery] = React.useState('');
  const catalog = useQuery({ queryKey: ['platform-ai-grid-policies'], queryFn: () => api.listPlatformAiGridPolicies() });
  const frameworks = useQuery({ queryKey: ['ai-frameworks'], queryFn: api.getAiFrameworks });
  const shipping = useQuery({ queryKey: ['platform-ai-grid-shipping-status'], queryFn: api.getPlatformAiGridShippingStatus });
  const rollouts = useQuery({ queryKey: ['platform-ai-grid-policy-rollouts'], queryFn: api.listPlatformAiGridPolicyRollouts });
  const retry = useMutation({
    mutationFn: api.retryPlatformAiGridPolicyRollout,
    onSuccess: () => void client.invalidateQueries({ queryKey: ['platform-ai-grid-policy-rollouts'] }),
  });
  const frameworkLabels = React.useMemo(() => new Map((frameworks.data ?? [])
    .map((framework) => [`${framework.framework}:${framework.frameworkVersion}`, framework.displayName])), [frameworks.data]);
  const frameworkControls = React.useMemo(() => (frameworks.data ?? []).flatMap((framework) => framework.controls), [frameworks.data]);
  const policies = React.useMemo(() => (catalog.data ?? []).filter((item) => {
    const searchable = `${item.name} ${item.policyId} ${item.provider} ${owaspMappings(item.frameworkMappingsJson)}`.toLowerCase();
    return (provider === 'ALL' || item.provider === provider)
      && (rollout === 'ALL' || item.rolloutStage === rollout)
      && (selection === 'ALL' || item.defaultSelection === selection)
      && (owasp === 'ALL' || owaspMappings(item.frameworkMappingsJson).includes(owasp))
      && (query.trim() === '' || searchable.includes(query.trim().toLowerCase()));
  }), [catalog.data, owasp, provider, query, rollout, selection]);
  const hasFilters = provider !== 'ALL' || rollout !== 'ALL' || selection !== 'ALL' || owasp !== 'ALL' || query.trim() !== '';

  return <section className="platform-ai-policy-studio">
      <header className="ai-security-hero policies policy-studio-hero"><div>
      <span className="ai-security-kicker">Tenant Management / Policies</span><h2>Policy distribution</h2>
      <p>Ship a governed catalog, make tenant defaults clear, and stage rollout changes from one workspace.</p>
    </div><div className={shipping.data?.blockers.length ? 'policy-shipping-state policy-shipping-state--blocked' : 'policy-shipping-state'}>
      <span>{shipping.data?.blockers.length ? 'Action needed' : 'Catalog healthy'}</span>
      <strong>{shipping.data?.blockers.length ? `${shipping.data.blockers.length} blocker${shipping.data.blockers.length === 1 ? '' : 's'}` : 'Ready to ship'}</strong>
    </div></header>
    <ShippingSummary status={shipping.data} />
      {shipping.data?.blockers.length ? <p className="notice error">{shipping.data.blockers.join(' · ')}</p> : null}
    <section className="panel policy-catalog-panel">
      <div className="panel-header policy-catalog-header"><div><h3>Policy catalog</h3><p className="panel-caption">Deploy to dev/test, approve with evidence, then publish to selected tenants or all active tenants. Default selection and tenant rollout are tracked independently.</p></div>
        <span className="policy-results-count">{policies.length} of {catalog.data?.length ?? 0} policies</span></div>
      <div className="policy-filter-bar" aria-label="Policy catalog filters">
        <label className="policy-search"><span>Find policy</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Name, ID, provider, or OWASP mapping" /></label>
        <label>Provider <select value={provider} onChange={(event) => setProvider(event.target.value)}><option value="ALL">All providers</option><option value="AWS">AWS</option><option value="AZURE">Azure</option><option value="MULTI_CLOUD">Multi-cloud</option></select></label>
        <label>Rollout <select value={rollout} onChange={(event) => setRollout(event.target.value)}><option value="ALL">All stages</option>{ROLLOUTS.map((value) => <option key={value} value={value}>{rolloutLabel(value)}</option>)}</select></label>
        <label>Default <select value={selection} onChange={(event) => setSelection(event.target.value)}><option value="ALL">All defaults</option>{DEFAULTS.map((value) => <option key={value}>{value}</option>)}</select></label>
        <label>OWASP <select value={owasp} onChange={(event) => setOwasp(event.target.value)}><option value="ALL">All mappings</option>{frameworkControls.map((control) => <option key={control.controlId}>{control.controlId}</option>)}</select></label>
        {hasFilters ? <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setProvider('ALL'); setRollout('ALL'); setSelection('ALL'); setOwasp('ALL'); setQuery(''); }}>Clear filters</button> : null}
      </div>
      {catalog.isLoading ? <p role="status">Loading shipped policies…</p> : null}
      {catalog.isError ? <p className="notice error">The policy catalog could not be loaded.</p> : null}
      <div className="policy-management-layout">
        <div className="table-scroll policy-catalog-table"><table className="data-table"><thead><tr><th>Policy</th><th>Applicability</th><th>Native types</th><th>Framework mapping</th><th>Availability</th><th>Default selection</th><th>Rollout</th><th>Lifecycle</th><th aria-label="Actions" /></tr></thead>
          <tbody>{policies.length === 0 ? <tr><td colSpan={9} className="policy-empty-cell">No policies match the selected filters.</td></tr> : policies.map((policy) => <tr key={policy.policyId} className="policy-catalog-row">
            <td><strong>{policy.name}</strong><br /><small>{policy.policyId} · {policy.provider} · {policy.severity}</small></td>
            <td>{jsonLabels(policy.artifactTypesJson)}</td><td>{jsonLabels(policy.nativeKindsJson)}</td><td>{frameworkMappings(policy.frameworkMappingsJson, frameworkLabels)}</td><td><span className={statusClass(policy.available ? 'available' : 'unavailable')}>{policy.available ? 'Available' : 'Unavailable'}</span></td>
            <td><span className={statusClass(policy.defaultSelection)}>{policy.defaultSelection}</span><br /><small>Tenant default</small></td><td><span className={statusClass(policy.rolloutStage)}>{rolloutLabel(policy.rolloutStage)}</span></td><td><span className={statusClass(policy.lifecycle)}>{policy.lifecycle}</span></td>
            <td><button type="button" className="btn btn-secondary btn-sm" aria-label={`Open ${policy.name}`} onClick={() => navigate(pathForPlatformPolicyDetail(policy.policyId))}>Open policy</button></td>
          </tr>)}</tbody></table></div>
      </div>
    </section>

    <section className="panel policy-rollout-panel"><div className="panel-header"><div><h3>Canary rollout queue</h3><p className="panel-caption">Each canary rollout is created by one policy approval and carries its exact digest and release-decision binding.</p></div><span className="policy-results-count">{rollouts.data?.filter((item) => item.status !== 'COMPLETED' && item.status !== 'CANCELED').length ?? 0} active</span></div>
      <div className="table-scroll"><table className="data-table"><thead><tr><th>Policy</th><th>Approved digest</th><th>Decision</th><th>State</th><th>Created</th><th>Action</th></tr></thead><tbody>
        {rollouts.isLoading ? <tr><td colSpan={6}>Loading rollout jobs…</td></tr> : (rollouts.data ?? []).length === 0 ? <tr><td colSpan={6}>No rollout jobs are waiting.</td></tr> : (rollouts.data ?? []).map((item) => <tr key={item.id}><td><strong>{item.policyId}</strong></td><td className="mono">{item.approvedDigest ?? '—'}</td><td className="mono">{item.releaseDecisionId ?? '—'}</td><td><span className={statusClass(item.status)}>{item.status}</span></td><td>{new Date(item.createdAt).toLocaleString()}</td><td><button type="button" className="btn btn-secondary btn-sm" onClick={() => retry.mutate(item.id)} disabled={retry.isPending || item.status === 'COMPLETED' || item.status === 'CANCELED'}>{item.status === 'COMPLETED' ? 'Complete' : item.status === 'CANCELED' ? 'Canceled' : 'Retry'}</button></td></tr>)}
      </tbody></table></div>
    </section>
  </section>;
}

function ShippingSummary({ status }: { status?: { expectedPolicies: number; installedPolicies: number; publishedPolicies: number; distributedPolicies: number; digestMatchedPolicies: number; rolloutPendingTenants: number } }) {
  const value = (key: keyof NonNullable<typeof status>) => status ? status[key] : '—';
  return <section className="summary-strip policy-shipping-summary" aria-label="Shipping summary"><span><strong>{value('expectedPolicies')}</strong> catalog packages</span><span><strong>{value('installedPolicies')}</strong> installed</span><span><strong>{value('publishedPolicies')}</strong> published</span><span><strong>{value('distributedPolicies')}</strong> distributed</span><span><strong>{value('digestMatchedPolicies')}</strong> digest verified</span><span><strong>{value('rolloutPendingTenants')}</strong> tenant jobs pending</span></section>;
}

/* Legacy implementation retained temporarily for reference; the catalog now routes to a full policy page. */
/* eslint-disable react-hooks/rules-of-hooks */
function _PolicyConfigurationPanel({ policy, tenantIds, saving, onClose, onApprove, onDevDeploy, onPublish, onDeprecate }: { policy: AiGridPolicyDistribution | null; tenantIds: string[]; saving: boolean; onClose: () => void; onApprove: (policy: AiGridPolicyDistribution, note: string) => void; onDevDeploy: (policy: AiGridPolicyDistribution, targetTenantIds: string[], note: string) => void; onPublish: (policy: AiGridPolicyDistribution, targetTenantIds: string[], publishAll: boolean) => void; onDeprecate: (policy: AiGridPolicyDistribution, reason: string) => void }) {
  const [cohort, setCohort] = React.useState<string[]>([]);
  const [deprecationReason, setDeprecationReason] = React.useState('');
  const [testNote, setTestNote] = React.useState('');
  const [publishScope, setPublishScope] = React.useState<'SELECTED' | 'ALL'>('SELECTED');
  const detail = useQuery({ queryKey: ['platform-ai-grid-policy-detail', policy?.policyId, policy?.version], queryFn: () => api.getPlatformAiGridPolicyDetail(policy!.policyId, policy!.version), enabled: policy != null });
  if (!policy) return <aside className="policy-configuration-empty"><span className="ai-security-kicker">Lifecycle</span><h4>Select a policy</h4><p>Choose <strong>Manage</strong> beside a policy to approve, publish to a canary cohort, or deprecate it.</p></aside>;
  return <aside className="policy-configuration-panel" aria-label={`${policy.name} configuration`}><div className="policy-configuration-heading"><div><span className="ai-security-kicker">Configuration</span><h4>{policy.name}</h4><p>{policy.policyId}</p></div><button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>Close</button></div>
    <div className="policy-detail-summary"><span className={statusClass(policy.severity)}>{policy.severity}</span><span>{detail.data?.description ?? 'Loading policy intent…'}</span><dl><dt>Lifecycle</dt><dd>{policy.lifecycle}</dd><dt>Governance</dt><dd>{detail.data?.governanceStatus ?? 'Loading…'}</dd><dt>Platform owner</dt><dd>{detail.data?.governanceOwner ?? 'Loading…'}</dd><dt>Tenant configuration</dt><dd>{detail.data ? (detail.data.tenantConfigurable ? 'Allowed' : 'Platform controlled') : 'Loading…'}</dd><dt>Rollout</dt><dd>{rolloutLabel(policy.rolloutStage)}</dd><dt>Tenant default</dt><dd>{policy.defaultSelection}</dd></dl></div>
    <div className="policy-config-fields"><label>Dev/test tenants<select multiple value={cohort} aria-label={`${policy.policyId} dev test tenants`} onChange={(event) => setCohort(Array.from(event.target.selectedOptions, (option) => option.value))}>{tenantIds.map((id) => <option key={id} value={id}>{id}</option>)}</select><small>Select tenants for pre-approval testing.</small></label>
      <label>Tenant test result / approval note<textarea value={testNote} onChange={(event) => setTestNote(event.target.value)} placeholder="Describe the dev/test result before approval" /></label>
      <label>Deprecation reason<input value={deprecationReason} onChange={(event) => setDeprecationReason(event.target.value)} placeholder="Why this policy is being retired" /></label>
    </div>
    {cohort.length === 0 ? <p className="notice error">Choose at least one dev/test tenant.</p> : null}
    <div className="button-row"><button type="button" className="btn btn-secondary" disabled={saving || policy.lifecycle !== 'VALIDATED' || cohort.length === 0 || testNote.trim() === ''} onClick={() => onDevDeploy(policy, cohort, testNote.trim())}>{saving ? 'Working…' : 'Deploy to dev/test'}</button><button type="button" className="btn btn-secondary" disabled={saving || policy.lifecycle !== 'VALIDATED' || testNote.trim() === ''} onClick={() => onApprove(policy, testNote.trim())}>{saving ? 'Working…' : 'Approve policy'}</button><label>Publish scope<select value={publishScope} onChange={(event) => setPublishScope(event.target.value as 'SELECTED' | 'ALL')}><option value="SELECTED">Selected tenants</option><option value="ALL">All active tenants</option></select></label><button type="button" className="btn btn-primary" disabled={saving || policy.lifecycle !== 'APPROVED' || (publishScope === 'SELECTED' && cohort.length === 0)} onClick={() => onPublish(policy, publishScope === 'ALL' ? [] : cohort, publishScope === 'ALL')}>{saving ? 'Working…' : 'Publish policy'}</button><button type="button" className="btn btn-secondary" disabled={saving || policy.lifecycle === 'DEPRECATED' || deprecationReason.trim() === ''} onClick={() => onDeprecate(policy, deprecationReason.trim())}>{saving ? 'Working…' : 'Deprecate policy'}</button></div>
    <details className="policy-technical-details"><summary>Policy implementation details</summary><dl><dt>Control objective</dt><dd>{detail.data?.controlObjectiveId ?? policy.controlObjectiveId ?? '—'}</dd><dt>Evaluation mode</dt><dd>{detail.data?.evaluationMode ?? policy.evaluationMode ?? '—'}</dd><dt>Source</dt><dd>{detail.data?.packageSourceRef ?? 'Loading…'}</dd></dl></details>
  </aside>;
}
/* eslint-enable react-hooks/rules-of-hooks */
