import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import type { AiGridPlatformPolicyDetail, AiGridPolicyDistribution } from '../features/ai-security/types';
import { formatLabel, severityClassName } from '../features/cve-workbench/formatting';

function labels(value?: unknown): string {
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    return Array.isArray(parsed) && parsed.length ? parsed.map(String).map(formatLabel).join(', ') : '—';
  } catch { return '—'; }
}

function frameworkMappings(value?: unknown): Array<{ name: string; control: string; type: string }> {
  try {
    const parsed = typeof value === 'string' ? JSON.parse(value) : value;
    return Array.isArray(parsed) ? parsed.map((item) => ({
      name: `${formatLabel(item.framework ?? 'Framework')}${item.frameworkVersion ? ` ${item.frameworkVersion}` : ''}`,
      control: item.controlId ?? '—',
      type: item.mappingType === 'INFORMATIVE' ? 'SUPPORTING (legacy)' : (item.mappingType ?? '—'),
    })) : [];
  } catch { return []; }
}

function Overview({ policy, detail, onGovernance }: { policy: AiGridPolicyDistribution; detail?: AiGridPlatformPolicyDetail; onGovernance: () => void }) {
  const mappings = frameworkMappings(detail?.frameworkMappings ?? policy.frameworkMappingsJson);
  return (
    <div className="cvd2-tab-content"><div className="cvd2-overview-body">
      <div className="cvd2-overview-main">
        <div className="cvd2-panel"><div className="cvd-ov-left">
          <div className="cvd-ov-meta"><span className="cvd-status-pill cvd-status-ok">{policy.lifecycle}</span><span className="cvd-ov-meta-eval">· Platform catalog policy</span></div>
          <div className="cvd-ov-first-seen">{policy.policyId}</div><h1 className="cvd-ov-cve-id">{policy.name}</h1>
          <div className="cvd-ov-badges"><span className={severityClassName(policy.severity)}>{policy.severity}</span><span className="cvd-signal-pill">{formatLabel(policy.provider)}</span><span className="cvd-signal-pill">{policy.defaultSelection}</span><span className="cvd-signal-pill">{formatLabel(policy.rolloutStage)}</span></div>
        </div><p className="cvd-ov-description">{detail?.description ?? 'Loading policy intent…'}</p>
        <div className="cvd-ov-divider" /><div className="cvd-ov-links"><span className="cvd-ov-link">Platform-owned definition →</span><button type="button" className="cvd-ov-link" onClick={onGovernance}>Open governance controls →</button></div>
        </div>
        <div className="cvd2-panel"><div className="cvd2-panel-hdr">Policy Details</div><div className="cvd-tech-attrs">
          <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Policy ID</span><span className="cvd-tech-attr-value mono">{policy.policyId}</span></div>
          <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Applicability</span><span className="cvd-tech-attr-value">{labels(policy.artifactTypesJson)}</span></div>
          <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Native types</span><span className="cvd-tech-attr-value">{labels(detail?.nativeKinds)}</span></div>
          <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Evaluation subject</span><span className="cvd-tech-attr-value">{detail?.evaluationSubject ?? '—'}</span></div>
          <div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Provider</span><span className="cvd-tech-attr-value">{formatLabel(policy.provider)}</span></div>
        </div>
        </div>
        <div className="cvd2-panel"><div className="cvd2-panel-hdr">Framework Mappings · {mappings.length}</div><div className="cvd-refs-list">{mappings.length ? mappings.map((mapping) => <div key={`${mapping.name}-${mapping.control}`} className="cvd-ref-row"><span style={{ color: 'var(--title)', fontSize: 13, fontWeight: 500 }}>{mapping.name}</span><span className="cvd-src-tag">{mapping.control} · {formatLabel(mapping.type)}</span></div>) : <p className="cvd-ov-description">No structured framework mappings.</p>}</div>
        </div>
        <div className="cvd2-panel"><div className="cvd2-panel-hdr">Policy Intent</div><div className="platform-policy-copy"><p>{detail?.securityIntent ?? detail?.description ?? 'Policy intent is loading.'}</p><p><strong>Evaluation approach:</strong> {detail?.evaluationMode ? formatLabel(detail.evaluationMode) : 'Declared evidence from applicable AI inventory.'}</p></div></div>
      </div>
      <aside className="cvd2-overview-sidebar"><div className="cvd2-panel"><div className="cvd2-panel-hdr">Platform Governance</div><div className="cvd-tech-attrs"><div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Owner</span><span className="cvd-tech-attr-value">{detail?.governanceOwner ?? '—'}</span></div><div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Status</span><span className="cvd-tech-attr-value">{detail?.governanceStatus ?? policy.lifecycle}</span></div><div className="cvd-tech-attr"><span className="cvd-tech-attr-label">Tenant configuration</span><span className="cvd-tech-attr-value">{detail?.tenantConfigurable ? 'Permitted by platform' : 'Platform controlled'}</span></div></div></div><div className="cvd2-panel"><div className="cvd2-panel-hdr">Remediation Guidance</div><p className="cvd-ov-description platform-policy-copy">{detail?.remediationIntent ?? 'Review the applicable provider configuration and relationship, correct the control gap, then publish a new governed policy version.'}</p></div></aside>
    </div></div>
  );
}

export function PlatformAiPolicyDetailPage({ policyId }: { policyId: string }) {
  const navigate = useNavigate(); const client = useQueryClient();
  const [tab, setTab] = React.useState<'overview' | 'governance'>('overview'); const [note, setNote] = React.useState(''); const [reason, setReason] = React.useState(''); const [cohort, setCohort] = React.useState<string[]>([]); const [actionMessage, setActionMessage] = React.useState<string | null>(null);
  const catalog = useQuery({ queryKey: ['platform-ai-grid-policies'], queryFn: () => api.listPlatformAiGridPolicies() });
  const policy = (catalog.data ?? []).find((item) => item.policyId === policyId);
  const detail = useQuery({ queryKey: ['platform-ai-grid-policy-detail', policyId, policy?.version], queryFn: () => api.getPlatformAiGridPolicyDetail(policyId, policy!.version), enabled: Boolean(policy) });
  const tenants = useQuery({ queryKey: ['platform-ai-grid-active-tenants'], queryFn: api.listTenants });
  const refresh = () => { void client.invalidateQueries({ queryKey: ['platform-ai-grid-policies'] }); void client.invalidateQueries({ queryKey: ['platform-ai-grid-policy-detail', policyId] }); };
  const onSuccess = (message: string) => { setActionMessage(message); refresh(); };
  const onError = (error: Error) => setActionMessage(`Action failed: ${error.message}`);
  const approve = useMutation({ mutationFn: () => api.approvePlatformAiGridPolicy(policyId, note.trim()), onSuccess: (result) => onSuccess(result.approved ? 'Policy approved successfully.' : `Approval blocked: ${result.reason ?? 'release gates have not passed.'}`), onError });
  const devDeploy = useMutation({ mutationFn: () => api.deployPlatformAiGridPolicyToDev(policyId, cohort, note.trim()), onSuccess: () => onSuccess('Policy deployed to the selected dev/test tenants.'), onError });
  const publish = useMutation({ mutationFn: (publishAll: boolean) => api.publishPlatformAiGridPolicy(policyId, publishAll ? [] : cohort, publishAll), onSuccess: () => onSuccess('Policy publication started.'), onError });
  const deprecate = useMutation({ mutationFn: () => api.deprecatePlatformAiGridPolicy(policyId, reason.trim()), onSuccess: () => onSuccess('Policy deprecated successfully.'), onError });
  if (!policy) return <section className="cvd2-page ai-policy-detail-page"><div className="empty-state"><p>Policy <strong>{policyId}</strong> was not found.</p><button className="btn btn-secondary" onClick={() => navigate('/platform/ai-policies')}>← Back</button></div></section>;
  const activeTenants = (tenants.data ?? []).filter((tenant) => tenant.status === 'ACTIVE');
  return (
    <section className="cvd2-page ai-policy-detail-page platform-policy-detail-page">
      <div className="ai-policy-detail-topbar"><button type="button" className="cvd-ov-link" onClick={() => navigate('/platform/ai-policies')}>← Back to Policy distribution</button><span>Platform owner · Catalog governance</span></div>
      <div className="cvd2-tab-bar"><button className={`cvd2-tab${tab === 'overview' ? ' active' : ''}`} onClick={() => setTab('overview')}>Overview</button><button className={`cvd2-tab${tab === 'governance' ? ' active' : ''}`} onClick={() => setTab('governance')}>Governance</button></div>
      {tab === 'overview' ? <Overview policy={policy} detail={detail.data} onGovernance={() => setTab('governance')} /> : (
        <div className="cvd2-tab-content"><div className="cvd2-overview-body"><div className="cvd2-overview-main">
          <div className="cvd2-panel"><div className="cvd2-panel-hdr">Governance actions</div><p className="panel-caption">Platform owners control approval, rollout lifecycle, and tenant publication. Tenant findings and artifact results are intentionally not shown here.</p>{actionMessage ? <p className={`notice ${actionMessage.startsWith('Action failed') || actionMessage.startsWith('Approval blocked') ? 'error' : 'success'}`} role="status">{actionMessage}</p> : null}
            <label>Approval evidence / decision note<textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Describe the review evidence supporting approval or rollout" /></label><div className="button-row"><button className="btn btn-primary" disabled={approve.isPending || policy.lifecycle !== 'VALIDATED' || !note.trim()} onClick={() => approve.mutate()}>Approve policy</button></div>
            <label>Canary tenants<select multiple value={cohort} onChange={(event) => setCohort(Array.from(event.target.selectedOptions, (option) => option.value))} disabled={!activeTenants.length}>{activeTenants.map((tenant) => <option key={tenant.id} value={tenant.id}>{tenant.name ?? tenant.id}</option>)}</select></label><div className="button-row"><button className="btn btn-secondary" disabled={devDeploy.isPending || policy.lifecycle !== 'VALIDATED' || !cohort.length || !note.trim()} onClick={() => devDeploy.mutate()}>Deploy to dev/test</button><button className="btn btn-secondary" disabled={publish.isPending || policy.lifecycle !== 'APPROVED' || !cohort.length} onClick={() => publish.mutate(false)}>Publish canary</button><button className="btn btn-secondary" disabled={publish.isPending || policy.lifecycle !== 'APPROVED'} onClick={() => publish.mutate(true)}>Publish to all active tenants</button></div>
            <label>Deprecation reason<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Why this policy is being retired" /></label><div className="button-row"><button className="btn btn-secondary" disabled={deprecate.isPending || policy.lifecycle === 'DEPRECATED' || !reason.trim()} onClick={() => deprecate.mutate()}>Deprecate policy</button></div>
          </div><div className="cvd2-panel"><div className="cvd2-panel-hdr">Governance boundary</div><p>This page manages the platform-owned catalog definition and rollout state. Tenant administrators manage only the tenant configuration exposed by the published policy.</p></div>
        </div></div></div>
      )}
    </section>
  );
}
