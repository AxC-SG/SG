import React from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import type { Finding } from '../features/findings/types';
import { pathForVulnRepoView, pathForInventoryHostAsset, pathForInventoryViewWithSearch, type VulnerabilityIntelRouteView } from '../app/routes';
import { apiRequest, api } from '../api/client';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type { AiSolutionApiResponse } from '../features/cve-workbench/api';
import type { CveDetail, ServiceNowIncidentResponse, CreateServiceNowIncidentRequest } from '../features/cve-workbench/types';
import type { HostAssetSummary } from '../features/inventory/api-types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { computeFindingPriorityScore, riskScoreLabel } from '../lib/riskScoring';
import { useActor } from '../features/auth/context';

// ─── helpers ──────────────────────────────────────────────────────────────────

function fmt(v?: string | null): string {
  if (!v) return '—';
  return v.replace(/[_-]+/g, ' ').toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
}

function fmtDate(v?: string | null): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function fmtDt(v?: string | null): string {
  if (!v) return '—';
  const d = new Date(v);
  return isNaN(d.getTime()) ? v : d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function isOverdue(dueAt?: string | null): boolean {
  if (!dueAt) return false;
  return new Date(dueAt).getTime() < Date.now();
}

function statusCls(f: Finding): string {
  if (f.status === 'RESOLVED') return 'status-pill status-resolved';
  if (f.status === 'SUPPRESSED') return 'status-pill status-suppressed';
  if (f.status === 'AUTO_CLOSED') return 'status-pill status-auto-closed';
  if (f.status === 'OPEN' && f.decisionState === 'UNDER_INVESTIGATION') return 'status-pill status-investigating';
  return 'status-pill status-open';
}

function statusLabel(f: Finding): string {
  if (f.status === 'RESOLVED') return 'Resolved';
  if (f.status === 'AUTO_CLOSED') return 'Closed';
  if (f.status === 'SUPPRESSED') {
    if (f.suppressedByRuleId) return 'Suppressed';
    const r = (f.suppressionReason ?? '').toUpperCase();
    if (r.includes('FALSE_POSITIVE')) return 'False Positive';
    if (r.includes('DUPLICATE')) return 'Duplicate';
    return 'Deferred';
  }
  if (f.status === 'OPEN' && f.decisionState === 'UNDER_INVESTIGATION') return 'Under Investigation';
  if (f.status === 'OPEN') return 'Open';
  return fmt(f.status);
}

// UUID pattern – finding IDs from the backend are always UUID format
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

async function updateWorkflow(findingId: string, payload: Record<string, unknown>) {
  if (!findingId || !UUID_RE.test(findingId)) {
    throw new Error(`Invalid finding ID "${findingId}" – navigate back to the Findings list and reopen this finding.`);
  }
  return apiRequest(`/findings/${findingId}/workflow`, { method: 'PUT', body: JSON.stringify(payload) });
}

// ─── sub-components ───────────────────────────────────────────────────────────

function KVRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fd3-kv-row">
      <span className="fd3-kv-key">{label}</span>
      <span className="fd3-kv-val">{children ?? <span className="fd3-empty">—</span>}</span>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="fd3-panel">
      <div className="fd3-panel-title">{title}</div>
      <div className="fd3-panel-body">{children}</div>
    </div>
  );
}

type FixDescriptionJson = {
  summary?: string;
  fix_type?: string;
  os_hint?: string | null;
  primary_fix?: {
    action?: string;
    target_version?: string | null;
    applies_to?: string | null;
    reboot_required?: boolean | null;
    verification?: string | null;
    patch_id?: string | null;
  } | null;
  compensating_controls?: Array<{ control?: string; effort?: string; effectiveness?: string }> | null;
  rollback_plan?: string[] | null;
  lifecycle_warning?: string | null;
};

function FixDescriptionDetail({ description }: { description: string }) {
  let parsed: FixDescriptionJson | null = null;
  try { parsed = JSON.parse(description) as FixDescriptionJson; } catch { /* fall through */ }

  if (!parsed || typeof parsed !== 'object') {
    return <p style={{ marginTop: 6, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{description}</p>;
  }

  const WRAP: React.CSSProperties = { marginTop: 10, fontSize: 12, lineHeight: 1.6 };
  const SECTION: React.CSSProperties = { fontWeight: 700, fontSize: 10, letterSpacing: '0.07em', color: 'var(--muted)', textTransform: 'uppercase', marginTop: 12, marginBottom: 6 };
  // Two-column grid: label 110px, value fills rest — no wrapping in narrow columns
  const GRID: React.CSSProperties = { display: 'grid', gridTemplateColumns: '110px 1fr', gap: '3px 10px', marginBottom: 2 };
  const KEY: React.CSSProperties = { fontWeight: 600, color: 'var(--muted)', fontSize: 11, alignSelf: 'start', paddingTop: 1 };
  const VAL: React.CSSProperties = { color: 'var(--text)', fontSize: 12, wordBreak: 'break-word' };

  return (
    <div style={WRAP}>
      {parsed.primary_fix && (
        <>
          <div style={SECTION}>Primary Fix</div>
          {parsed.primary_fix.action && <div style={GRID}><span style={KEY}>Action</span><span style={VAL}>{parsed.primary_fix.action}</span></div>}
          {parsed.primary_fix.applies_to && <div style={GRID}><span style={KEY}>Applies To</span><span style={VAL}>{parsed.primary_fix.applies_to}</span></div>}
          {parsed.primary_fix.target_version && <div style={GRID}><span style={KEY}>Target Version</span><span style={{ ...VAL, fontFamily: 'monospace', fontSize: 11 }}>{parsed.primary_fix.target_version}</span></div>}
          {parsed.primary_fix.reboot_required != null && <div style={GRID}><span style={KEY}>Reboot Required</span><span style={VAL}>{parsed.primary_fix.reboot_required ? 'Yes' : 'No'}</span></div>}
          {parsed.primary_fix.verification && <div style={GRID}><span style={KEY}>Verification</span><span style={VAL}>{parsed.primary_fix.verification}</span></div>}
        </>
      )}

      {parsed.compensating_controls && parsed.compensating_controls.length > 0 && (
        <>
          <div style={SECTION}>Compensating Controls</div>
          {parsed.compensating_controls.map((c, i) => (
            <div key={i} style={{ flexDirection: 'column', display: 'flex', marginBottom: 8, paddingLeft: 8, borderLeft: '2px solid var(--border)' }}>
              <span style={{ fontWeight: 600, fontSize: 12 }}>{c.control}</span>
              {(c.effort || c.effectiveness) && (
                <span style={{ color: 'var(--muted)', fontSize: 11 }}>
                  {[c.effort && `Effort: ${c.effort}`, c.effectiveness && `Effectiveness: ${c.effectiveness}`].filter(Boolean).join(' · ')}
                </span>
              )}
            </div>
          ))}
        </>
      )}

      {parsed.rollback_plan && parsed.rollback_plan.length > 0 && (
        <>
          <div style={SECTION}>Rollback Plan</div>
          <ol style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {parsed.rollback_plan.map((step, i) => (
              <li key={i} style={{ fontSize: 12, lineHeight: 1.6, marginBottom: 2 }}>{step}</li>
            ))}
          </ol>
        </>
      )}

      {parsed.lifecycle_warning && (
        <>
          <div style={SECTION}>Lifecycle Warning</div>
          <p style={{ margin: '4px 0 0', fontSize: 12, lineHeight: 1.5, color: '#b7791f' }}>{parsed.lifecycle_warning}</p>
        </>
      )}

      {parsed.os_hint && (
        <>
          <div style={SECTION}>OS Hint</div>
          <p style={{ margin: '4px 0 0', fontSize: 12 }}>{parsed.os_hint}</p>
        </>
      )}
    </div>
  );
}

// ─── main component ───────────────────────────────────────────────────────────

type ActionType = 'create-incident' | 'defer' | 'resolve' | 'under-investigation' | 'false-positive' | 'reopen';

export function FindingDetailPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const finding = (location.state as { finding?: Finding } | null)?.finding ?? null;
  const returnTo = searchParams.get('returnTo') || '/findings';
  const policyQuery = useRiskPolicyQuery();

  // ── local state ────────────────────────────────────────────────────────────
  const [currentFinding, setCurrentFinding] = React.useState<Finding | null>(finding);
  const [assignedTo, setAssignedTo] = React.useState(finding?.assignedTo ?? '');
  const [editingAssignee, setEditingAssignee] = React.useState(false);
  const [assigneeSaving, setAssigneeSaving] = React.useState(false);

  const [assignmentGroup, setAssignmentGroup] = React.useState(finding?.ownerGroup ?? '');
  const [editingGroup, setEditingGroup] = React.useState(false);
  const [groupSaving, setGroupSaving] = React.useState(false);

  const [actionModal, setActionModal] = React.useState<ActionType | null>(null);
  const [actionLoading, setActionLoading] = React.useState(false);
  const [actionError, setActionError] = React.useState('');
  const [actionDone, setActionDone] = React.useState('');

  // action form fields
  const [deferReason, setDeferReason] = React.useState('');
  const [deferExpiry, setDeferExpiry] = React.useState('');
  const [fpJustification, setFpJustification] = React.useState('');
  const [incidentPriority, setIncidentPriority] = React.useState('3');
  const [incidentAssignedTo, setIncidentAssignedTo] = React.useState('');
  const [incidentAssignmentGroup, setIncidentAssignmentGroup] = React.useState('');
  const [incidentDueDate, setIncidentDueDate] = React.useState('');
  const [incidentNotes, setIncidentNotes] = React.useState('');
  const [incidentResult, setIncidentResult] = React.useState<ServiceNowIncidentResponse[] | null>(null);

  const [activeTab, setActiveTab] = React.useState<'overview' | 'affected-assets'>('overview');

  // remote data
  const [cveDetail, setCveDetail] = React.useState<CveDetail | null>(null);
  const [aiSolution, setAiSolution] = React.useState<AiSolutionApiResponse | null>(null);
  const [hostAssetId, setHostAssetId] = React.useState<string | null>(null);
  const [hostAsset, setHostAsset] = React.useState<HostAssetSummary | null>(null);
  const [loadingCveDetail, setLoadingCveDetail] = React.useState(false);
  const [loadingAiSolution, setLoadingAiSolution] = React.useState(false);
  const [loadingHostContext, setLoadingHostContext] = React.useState(false);

  const findingVulnId = currentFinding?.vulnerabilityId;
  const findingAssetIdentifier = currentFinding?.assetIdentifier;
  const findingAssetName = currentFinding?.assetName;

  React.useEffect(() => {
    if (!findingVulnId) return;
    setLoadingCveDetail(true);
    setLoadingAiSolution(true);
    cveWorkbenchApi.getCveDetail(findingVulnId)
      .then(d => setCveDetail(d))
      .catch(() => setCveDetail(null))
      .finally(() => setLoadingCveDetail(false));
    cveWorkbenchApi.getSavedAiSolution(findingVulnId)
      .then(r => setAiSolution(r))
      .catch(() => setAiSolution(null))
      .finally(() => setLoadingAiSolution(false));
  }, [findingVulnId]);

  React.useEffect(() => {
    if (!findingAssetIdentifier) return;
    setLoadingHostContext(true);
    setHostAssetId(null);
    setHostAsset(null);
    api.listAssets().then(async (assets) => {
      const match = assets.find(
        a => a.identifier === findingAssetIdentifier || a.name === findingAssetName
      );
      if (match) {
        setHostAssetId(match.id);
        try {
          const detail = await api.getHostAssetDetail(match.id);
          setHostAsset(detail.host);
        } catch {
          setHostAsset(null);
        }
      }
    }).catch(() => {
      setHostAsset(null);
    }).finally(() => {
      setLoadingHostContext(false);
    });
  }, [findingAssetIdentifier, findingAssetName]);

  if (!currentFinding) {
    return (
      <div className="page-grid">
        <section className="panel">
          <div style={{ padding: 48, textAlign: 'center' }}>
            <h2 style={{ marginBottom: 12 }}>Finding not available</h2>
            <p style={{ color: 'var(--muted)', marginBottom: 16 }}>
              Navigate here from the Findings list or the CVE Assessment Workbench.
            </p>
            <button className="btn btn-secondary" onClick={() => navigate(returnTo)}>← Back to Findings</button>
          </div>
        </section>
      </div>
    );
  }

  const overdue = isOverdue(currentFinding.dueAt) && currentFinding.status === 'OPEN';

  // ── assignee save ──────────────────────────────────────────────────────────
  async function saveAssignee() {
    setAssigneeSaving(true);
    try {
      await updateWorkflow(currentFinding!.id, { assignedTo: assignedTo.trim() || null, actor: actor?.principal });
      setCurrentFinding(f => f ? { ...f, assignedTo: assignedTo.trim() || undefined } : f);
      setEditingAssignee(false);
    } catch { /**/ }
    finally { setAssigneeSaving(false); }
  }

  async function saveAssignmentGroup() {
    setGroupSaving(true);
    try {
      await updateWorkflow(currentFinding!.id, { ownerGroup: assignmentGroup.trim() || null, actor: actor?.principal });
      setCurrentFinding(f => f ? { ...f, ownerGroup: assignmentGroup.trim() || undefined } : f);
      setEditingGroup(false);
    } catch { /**/ }
    finally { setGroupSaving(false); }
  }

  // ── modal helpers ──────────────────────────────────────────────────────────
  function openModal(t: ActionType) {
    setActionModal(t); setActionError(''); setActionDone(''); setIncidentResult(null);
  }
  function closeModal() {
    setActionModal(null); setActionError(''); setActionDone('');
    setDeferReason(''); setDeferExpiry(''); setFpJustification('');
    setIncidentPriority('3'); setIncidentAssignedTo(''); setIncidentAssignmentGroup('');
    setIncidentDueDate(''); setIncidentNotes(''); setIncidentResult(null);
  }
  async function applyWorkflow(payload: Record<string, unknown>, successMsg: string) {
    setActionLoading(true); setActionError('');
    try {
      await updateWorkflow(currentFinding!.id, payload);
      setCurrentFinding(f => {
        if (!f) return f;
        const updates: Partial<Finding> = {};
        if (payload.status) updates.status = payload.status as Finding['status'];
        if (payload.decisionState) updates.decisionState = payload.decisionState as Finding['decisionState'];
        if (payload.suppressionReason) updates.suppressionReason = payload.suppressionReason as string;
        if (payload.suppressedUntil) updates.suppressedUntil = payload.suppressedUntil as string;
        if (payload.status === 'OPEN') {
          updates.suppressedByRuleId = undefined;
          updates.suppressedByRuleName = undefined;
          updates.suppressionReason = undefined;
          updates.suppressedUntil = undefined;
        }
        return { ...f, ...updates };
      });
      setActionDone(successMsg);
    } catch (e) { setActionError(String(e)); }
    finally { setActionLoading(false); }
  }

  async function handleResolve() {
    await applyWorkflow({ status: 'RESOLVED', actor: actor?.principal }, 'Finding marked as Resolved.');
  }
  async function handleDefer() {
    await applyWorkflow({
      status: 'SUPPRESSED',
      suppressionReason: deferReason || 'DEFERRED',
      suppressedUntil: deferExpiry ? new Date(deferExpiry).toISOString() : undefined,
      actor: actor?.principal,
    }, 'Finding deferred successfully.');
  }
  async function handleFalsePositive() {
    await applyWorkflow({
      status: 'SUPPRESSED',
      suppressionReason: `FALSE_POSITIVE${fpJustification ? ': ' + fpJustification : ''}`,
      actor: actor?.principal,
    }, 'Finding marked as False Positive.');
  }
  async function handleUnderInvestigation() {
    await applyWorkflow({ status: 'OPEN', decisionState: 'UNDER_INVESTIGATION', actor: actor?.principal }, 'Status updated to Under Investigation.');
  }
  async function handleReopen() {
    await applyWorkflow({ status: 'OPEN', actor: actor?.principal }, 'Finding re-opened successfully.');
  }
  async function handleCreateIncident() {
    setActionLoading(true); setActionError('');
    const f = currentFinding!;
    try {
      const payload: CreateServiceNowIncidentRequest = {
        findingTitle: `${f.vulnerabilityId} — Vulnerability Remediation`,
        severity: f.severity,
        cvssScore: undefined,
        inKev: f.inKev,
        priority: incidentPriority,
        dueDate: incidentDueDate || undefined,
        assignedTo: incidentAssignedTo.trim() || undefined,
        notes: incidentNotes.trim() || undefined,
        affectedAssets: [{
          componentId: f.componentId,
          assetName: f.assetName,
          assetIdentifier: f.assetIdentifier,
          assetType: f.assetType,
          packageName: f.packageName,
          packageVersion: f.packageVersion,
          assignmentGroup: incidentAssignmentGroup.trim() || undefined,
        }],
      };
      const results = await cveWorkbenchApi.createServiceNowIncident(f.vulnerabilityId, payload);
      setIncidentResult(results);
      if (results[0]?.incidentNumber) {
        setCurrentFinding(f => f ? { ...f, incidentId: results[0]!.incidentNumber } : f);
      }
      setActionDone('Incident created successfully.');
    } catch (e) { setActionError(String(e)); }
    finally { setActionLoading(false); }
  }

  // ── modal render ───────────────────────────────────────────────────────────
  function renderModal() {
    if (!actionModal) return null;
    const TITLES: Record<ActionType, string> = {
      'create-incident': 'Create ServiceNow Incident',
      'defer': 'Defer Finding',
      'resolve': 'Resolve Finding',
      'under-investigation': 'Mark Under Investigation',
      'false-positive': 'Mark as False Positive',
      'reopen': 'Re-open Finding',
    };
    return (
      <div className="fd3-modal-overlay" onClick={e => { if (e.target === e.currentTarget) closeModal(); }}>
        <div className="fd3-modal">
          <div className="fd3-modal-header">
            <span>{TITLES[actionModal]}</span>
            <button className="fd3-modal-close" onClick={closeModal}>✕</button>
          </div>
          <div className="fd3-modal-body">
            {actionError && <div className="notice error" style={{ marginBottom: 12 }}>{actionError}</div>}
            {actionDone && !incidentResult && <div className="notice success" style={{ marginBottom: 12 }}>{actionDone}</div>}

            {actionModal === 'create-incident' && !actionDone && (
              <div className="fd3-form">
                <div className="fd3-form-row">
                  <label>Finding</label>
                  <span className="fd3-form-readonly mono">{currentFinding!.displayId || currentFinding!.id} · {currentFinding!.vulnerabilityId}</span>
                </div>
                <div className="fd3-form-row">
                  <label>Priority</label>
                  <select value={incidentPriority} onChange={e => setIncidentPriority(e.target.value)} className="fd3-form-select">
                    <option value="1">1 - Critical</option>
                    <option value="2">2 - High</option>
                    <option value="3">3 - Moderate</option>
                    <option value="4">4 - Low</option>
                  </select>
                </div>
                <div className="fd3-form-row">
                  <label>Assigned To</label>
                  <input className="fd3-form-input" value={incidentAssignedTo} onChange={e => setIncidentAssignedTo(e.target.value)} placeholder="username or email" />
                </div>
                <div className="fd3-form-row">
                  <label>Assignment Group</label>
                  <input className="fd3-form-input" value={incidentAssignmentGroup} onChange={e => setIncidentAssignmentGroup(e.target.value)} placeholder="Security Operations" />
                </div>
                <div className="fd3-form-row">
                  <label>Due Date</label>
                  <input type="date" className="fd3-form-input" value={incidentDueDate} onChange={e => setIncidentDueDate(e.target.value)} />
                </div>
                <div className="fd3-form-row">
                  <label>Notes</label>
                  <textarea className="fd3-form-textarea" rows={3} value={incidentNotes} onChange={e => setIncidentNotes(e.target.value)} placeholder="Remediation context…" />
                </div>
              </div>
            )}

            {actionModal === 'create-incident' && incidentResult && (
              <div className="fd3-incident-result">
                {incidentResult.map((r, i) => (
                  <div key={i} className={`fd3-incident-card${r.status === 'created' ? '' : ' fd3-incident-card--error'}`}>
                    {r.status === 'created'
                      ? <><strong>✓ Incident Created:</strong> {r.incidentNumber}</>
                      : <><strong>✗ Error:</strong> {r.message}</>
                    }
                  </div>
                ))}
              </div>
            )}

            {actionModal === 'defer' && !actionDone && (
              <div className="fd3-form">
                <p className="fd3-form-desc">Suppress this finding until a specified date.</p>
                <div className="fd3-form-row">
                  <label>Reason</label>
                  <select value={deferReason} onChange={e => setDeferReason(e.target.value)} className="fd3-form-select">
                    <option value="">Select reason…</option>
                    <option value="RISK_ACCEPTED">Risk Accepted</option>
                    <option value="COMPENSATING_CONTROL">Compensating Control</option>
                    <option value="PENDING_PATCH">Pending Patch</option>
                    <option value="DEFERRED">Deferred</option>
                  </select>
                </div>
                <div className="fd3-form-row">
                  <label>Expires</label>
                  <input type="date" className="fd3-form-input" value={deferExpiry} onChange={e => setDeferExpiry(e.target.value)} />
                </div>
              </div>
            )}

            {actionModal === 'resolve' && !actionDone && (
              <p className="fd3-form-desc">Mark this finding as resolved. This indicates the vulnerability has been remediated.</p>
            )}

            {actionModal === 'under-investigation' && !actionDone && (
              <p className="fd3-form-desc">Mark the decision state as <strong>Under Investigation</strong>. The finding will remain open while being actively reviewed.</p>
            )}

            {actionModal === 'false-positive' && !actionDone && (
              <div className="fd3-form">
                <p className="fd3-form-desc">Mark this finding as a false positive and suppress it.</p>
                <div className="fd3-form-row">
                  <label>Justification</label>
                  <textarea className="fd3-form-textarea" rows={3} value={fpJustification} onChange={e => setFpJustification(e.target.value)} placeholder="Why is this a false positive?" />
                </div>
              </div>
            )}

            {actionModal === 'reopen' && !actionDone && (
              <p className="fd3-form-desc">Re-open this finding and set its status back to <strong>Open</strong>. Any previous deferral or suppression will be cleared.</p>
            )}
          </div>
          <div className="fd3-modal-footer">
            {actionDone
              ? <button className="btn btn-secondary" onClick={closeModal}>Close</button>
              : <>
                  <button className="btn btn-secondary" onClick={closeModal} disabled={actionLoading}>Cancel</button>
                  <button className="btn btn-primary" disabled={actionLoading}
                    onClick={() => {
                      if (actionModal === 'create-incident') void handleCreateIncident();
                      else if (actionModal === 'defer') void handleDefer();
                      else if (actionModal === 'resolve') void handleResolve();
                      else if (actionModal === 'under-investigation') void handleUnderInvestigation();
                      else if (actionModal === 'false-positive') void handleFalsePositive();
                      else if (actionModal === 'reopen') void handleReopen();
                    }}>
                    {actionLoading ? 'Working…'
                      : actionModal === 'create-incident' ? 'Create Incident'
                      : actionModal === 'defer' ? 'Defer'
                      : actionModal === 'resolve' ? 'Resolve'
                      : actionModal === 'under-investigation' ? 'Set Under Investigation'
                      : actionModal === 'reopen' ? 'Re-open'
                      : 'Mark False Positive'}
                  </button>
                </>
            }
          </div>
        </div>
      </div>
    );
  }

  // ─── render ────────────────────────────────────────────────────────────────

  const cve = currentFinding.vulnerabilityId;
  const ownership = currentFinding.ownership;
  const ownershipSource = ownership?.sourceSystem || ownership?.sourceType || '—';

  // Parse grouped-finding evidence
  const evidencePayload = (() => {
    try { return JSON.parse(currentFinding.evidence ?? '{}') as Record<string, unknown>; }
    catch { return {} as Record<string, unknown>; }
  })();
  const isGroupedFinding = Boolean(evidencePayload.groupedFinding);
  const affectedAssetsFromEvidence = (Array.isArray(evidencePayload.affectedAssets)
    ? evidencePayload.affectedAssets
    : []) as Array<{ componentId?: string; assetId?: string; assetIdentifier?: string; assetName?: string; packageName?: string; version?: string; assetType?: string; businessCriticality?: string; environment?: string }>;
  const affectedAssetCount = isGroupedFinding && affectedAssetsFromEvidence.length > 0
    ? affectedAssetsFromEvidence.length : 1;

  // Most relevant fix record for this finding
  const relevantFix = (cveDetail?.fixes ?? []).find(f =>
    f.softwareEntities?.some(e => e.name?.toLowerCase() === currentFinding.packageName?.toLowerCase())
  ) ?? cveDetail?.fixes?.[0] ?? null;
  const latestDataUpdate = latestFreshnessValue([
    currentFinding.updatedAt,
    currentFinding.lastObservedAt,
    currentFinding.firstObservedAt,
    cveDetail?.summary.modifiedAt,
    cveDetail?.summary.publishedAt,
    aiSolution?.generatedAt,
    hostAsset?.lastInventoryAt,
    hostAsset?.lastCmdbSyncAt,
    hostAsset?.ssmLastPingAt,
  ]);
  const loadingSupportingContext = loadingCveDetail || loadingAiSolution || loadingHostContext;

  return (
    <div className="fd3-page">

      {/* ── top bar ─────────────────────────────────────────────────────── */}
      <div className="fd3-topbar">
        <button className="fd3-back-btn" onClick={() => navigate(returnTo)}>← Back</button>
        <span className="fd3-finding-id mono">{currentFinding.displayId || currentFinding.id}</span>
        <span className={statusCls(currentFinding)}>{statusLabel(currentFinding)}</span>
        {overdue && <span className="fd3-target-missed">⚠ Target Missed</span>}
        <div style={{ flex: 1 }} />
        <div className="fd3-actions">
          <button className="fd3-action-btn fd3-action-btn--incident" onClick={() => openModal('create-incident')}>+ Create Incident</button>
          {currentFinding.status === 'OPEN' && (
            <>
              <button className="fd3-action-btn" onClick={() => openModal('under-investigation')}>Under Investigation</button>
              <button className="fd3-action-btn" onClick={() => openModal('defer')}>Defer</button>
              <button className="fd3-action-btn" onClick={() => openModal('resolve')}>Resolve</button>
              <button className="fd3-action-btn fd3-action-btn--fp" onClick={() => openModal('false-positive')}>False Positive</button>
            </>
          )}
          {currentFinding.status !== 'OPEN' && (
            <button className="fd3-action-btn fd3-action-btn--reopen" onClick={() => openModal('reopen')}>Re-open</button>
          )}
        </div>
      </div>

      <PageFreshnessStatus
        updatedAt={latestDataUpdate}
        isRefreshing={loadingSupportingContext}
        refreshLabel="Loading supporting investigation context while keeping the finding visible…"
      />

      {/* ── tab bar ─────────────────────────────────────────────────────── */}
      <div className="fd3-tab-bar">
        <button
          className={`fd3-tab${activeTab === 'overview' ? ' fd3-tab--active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >Overview</button>
        <button
          className={`fd3-tab${activeTab === 'affected-assets' ? ' fd3-tab--active' : ''}`}
          onClick={() => setActiveTab('affected-assets')}
        >
          Affected Assets
          <span className="fd3-tab-count">{affectedAssetCount}</span>
        </button>
      </div>

      {/* ── OVERVIEW TAB ────────────────────────────────────────────────── */}
      {activeTab === 'overview' && (
        <div className="fd3-body">

          {/* ── LEFT ──────────────────────────────────────────────────── */}
          <div className="fd3-col fd3-col-left">

            {/* 1. Details (at top-left) */}
            <Panel title="Details">
              <div className="fd3-kv-table">
                <KVRow label="Status">
                  <span className={statusCls(currentFinding)}>{statusLabel(currentFinding)}</span>
                </KVRow>
                <KVRow label="Created By">
                  {currentFinding.creationSource === 'MANUAL' ? 'Manual' : 'Automatic'}
                </KVRow>
                {(() => {
                  const p = computeFindingPriorityScore(currentFinding, policyQuery.data);
                  const cls = `risk-score-badge risk-score-badge--${riskScoreLabel(p.score).toLowerCase()}`;
                  return (
                    <KVRow label="S.AI Priority">
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
                        <span className={cls}>{p.score.toFixed(1)}</span>
                        {p.topReasons.length > 0 && (
                          <span className="fd3-muted" style={{ fontSize: 11 }}>
                            {p.topReasons.join(' · ')}
                          </span>
                        )}
                      </span>
                    </KVRow>
                  );
                })()}
                <KVRow label="Due Date">
                  {currentFinding.dueAt
                    ? <span className={overdue ? 'fd3-overdue' : undefined}>{fmtDate(currentFinding.dueAt)}{overdue && ' ⚠'}</span>
                    : <span className="fd3-muted">—</span>}
                </KVRow>
                {currentFinding.status === 'SUPPRESSED' && !currentFinding.suppressedByRuleId && !((currentFinding.suppressionReason ?? '').toUpperCase().includes('FALSE_POSITIVE')) && (
                  <KVRow label="Deferral Date">{fmtDate(currentFinding.suppressedUntil)}</KVRow>
                )}
                {currentFinding.suppressedByRuleName && (
                  <KVRow label="Suppression Rule">
                    <span style={{ fontWeight: 600 }}>{currentFinding.suppressedByRuleName}</span>
                  </KVRow>
                )}
                {currentFinding.suppressedByRuleName && currentFinding.suppressionReason && (
                  <KVRow label="Suppression Reason">{currentFinding.suppressionReason}</KVRow>
                )}
                <KVRow label="Assigned To">
                  {editingAssignee ? (
                    <span className="fd3-assign-wrap">
                      <input autoFocus className="fd3-assign-input"
                        value={assignedTo} onChange={e => setAssignedTo(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') void saveAssignee(); if (e.key === 'Escape') setEditingAssignee(false); }}
                        placeholder="username or email" />
                      <button className="fd3-assign-save" onClick={() => void saveAssignee()} disabled={assigneeSaving}>
                        {assigneeSaving ? '…' : '✓'}
                      </button>
                      <button className="fd3-assign-cancel" onClick={() => { setAssignedTo(currentFinding.assignedTo ?? ''); setEditingAssignee(false); }}>✕</button>
                    </span>
                  ) : (
                    <span className="fd3-assign-display" onClick={() => setEditingAssignee(true)}>
                      {currentFinding.assignedTo || <span className="fd3-muted">Unassigned</span>}
                      <span className="fd3-assign-edit-icon">✏</span>
                    </span>
                  )}
                </KVRow>
                <KVRow label="Assignment Group">
                  {editingGroup ? (
                    <span className="fd3-assign-wrap">
                      <input autoFocus className="fd3-assign-input"
                        value={assignmentGroup} onChange={e => setAssignmentGroup(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') void saveAssignmentGroup(); if (e.key === 'Escape') setEditingGroup(false); }}
                        placeholder="e.g. Security Operations" />
                      <button className="fd3-assign-save" onClick={() => void saveAssignmentGroup()} disabled={groupSaving}>
                        {groupSaving ? '…' : '✓'}
                      </button>
                      <button className="fd3-assign-cancel" onClick={() => setEditingGroup(false)}>✕</button>
                    </span>
                  ) : (
                    <span className="fd3-assign-display" onClick={() => setEditingGroup(true)}>
                      {assignmentGroup || <span className="fd3-muted">—</span>}
                      <span className="fd3-assign-edit-icon">✏</span>
                    </span>
                  )}
                </KVRow>
                {currentFinding.incidentId && (
                  <KVRow label="Incident ID">
                    <span className="mono fd3-incident-link">{currentFinding.incidentId}</span>
                  </KVRow>
                )}
                <KVRow label="First Observed">{fmtDt(currentFinding.firstObservedAt)}</KVRow>
                <KVRow label="Last Observed">{fmtDt(currentFinding.lastObservedAt)}</KVRow>
                {currentFinding.consecutiveMisses != null && currentFinding.consecutiveMisses > 0 && (
                  <KVRow label="Missed Scans">{currentFinding.consecutiveMisses}</KVRow>
                )}
                {currentFinding.autoCloseEligibleAt && (
                  <KVRow label="Auto-Close Eligible">{fmtDt(currentFinding.autoCloseEligibleAt)}</KVRow>
                )}
                {currentFinding.closedReason && (
                  <KVRow label="Closed Reason">{currentFinding.closedReason === 'AUTO_POLICY_PLATFORM_DEPRECATED'
                    ? 'Closed — policy deprecated by platform'
                    : currentFinding.closedReason === 'AUTO_POLICY_TENANT_DISABLED'
                      ? 'Closed — policy disabled for this tenant'
                      : currentFinding.closedReason.replace(/_/g, ' ')}</KVRow>
                )}
                {(currentFinding.closedReason === 'AUTO_POLICY_PLATFORM_DEPRECATED' || currentFinding.closedReason === 'AUTO_POLICY_TENANT_DISABLED') && (
                  <p className="fd3-muted">This closure does not indicate verified remediation.</p>
                )}
                {currentFinding.closedAt && (
                  <KVRow label="Closed At">{fmtDt(currentFinding.closedAt)}</KVRow>
                )}
              </div>

              {/* Impacted Software */}
              <div className="fd3-ci-sep" />
              <div className="fd3-panel-sub-title">IMPACTED SOFTWARE</div>
              <div className="fd3-kv-table">
                <KVRow label="Package">
                  {currentFinding.packageName ? (
                    <button
                      type="button"
                      className="btn-link mono"
                      onClick={() => navigate(pathForInventoryViewWithSearch('software-identities', { query: currentFinding.packageName }))}
                    >
                      {currentFinding.packageName}
                    </button>
                  ) : (
                    <span className="mono">—</span>
                  )}
                </KVRow>
                <KVRow label="Version">
                  <span className="mono">{currentFinding.packageVersion || '—'}</span>
                </KVRow>
                {relevantFix?.softwareEntities?.[0]?.ecosystem && (
                  <KVRow label="Vendor / Ecosystem">
                    <span>{relevantFix.softwareEntities[0].ecosystem}</span>
                  </KVRow>
                )}
                {currentFinding.isEol && (
                  <KVRow label="EOL Status">
                    <span className="fd3-eol-badge">End of Life</span>
                    {currentFinding.eolDate && <span className="fd3-muted"> · {fmtDate(currentFinding.eolDate)}</span>}
                  </KVRow>
                )}
              </div>

              {/* Fix Information */}
              {relevantFix && (
                <>
                  <div className="fd3-ci-sep" />
                  <div className="fd3-panel-sub-title">FIX INFORMATION</div>
                  <div className="fd3-kv-table">
                    <KVRow label="Fix ID">
                      <span className="mono" style={{ fontWeight: 700, letterSpacing: '0.04em' }}>
                        {relevantFix.id.slice(0, 8).toUpperCase()}
                      </span>
                    </KVRow>
                    <KVRow label="Fix Type">{fmt(relevantFix.fixType)}</KVRow>
                    <KVRow label="Summary">
                      <span style={{ fontSize: 12, lineHeight: 1.5 }}>{relevantFix.summary}</span>
                    </KVRow>
                    {relevantFix.softwareEntities?.length > 0 && (
                      <KVRow label="Affected Software">
                        <span style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          {relevantFix.softwareEntities.map((e, i) => (
                            <span key={i} className="mono" style={{ fontSize: 11 }}>
                              {e.name}{e.version ? ` ${e.version}` : ''}{e.ecosystem ? ` (${e.ecosystem})` : ''}
                            </span>
                          ))}
                        </span>
                      </KVRow>
                    )}
                  </div>

                  {/* Full description — full-width, outside KVRow to avoid narrow column wrapping */}
                  {relevantFix.description && relevantFix.description !== relevantFix.summary && (
                    <details style={{ marginTop: 8 }}>
                      <summary style={{ cursor: 'pointer', color: 'var(--accent, #3b82f6)', userSelect: 'none', fontSize: 12, fontWeight: 500, listStyle: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
                        <span style={{ fontSize: 10 }}>▶</span> Show full description
                      </summary>
                      <FixDescriptionDetail description={relevantFix.description} />
                    </details>
                  )}
                </>
              )}
            </Panel>

            {/* 2. Affected Assets summary — stat cards */}
            {(() => {
              const assets = isGroupedFinding && affectedAssetsFromEvidence.length > 0
                ? affectedAssetsFromEvidence
                : null;
              const total = assets ? assets.length : 1;

              // External facing: environment contains production/external/internet/public hints
              const EXT_HINTS = ['prod', 'external', 'internet', 'public', 'dmz', 'edge', 'web'];
              const externalCount = assets
                ? assets.filter(a => EXT_HINTS.some(h => (a.environment ?? '').toLowerCase().includes(h))).length
                : (EXT_HINTS.some(h => (hostAsset?.environment ?? '').toLowerCase().includes(h)) ? 1 : 0);

              // Critical: businessCriticality === CRITICAL
              const criticalCount = assets
                ? assets.filter(a => a.businessCriticality === 'CRITICAL').length
                : (hostAsset?.businessCriticality?.toUpperCase() === 'CRITICAL' ? 1 : 0);

              const STAT: React.CSSProperties = {
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                flex: 1, padding: '12px 8px', borderRight: '1px solid var(--border)',
              };
              const NUM: React.CSSProperties = { fontSize: 28, fontWeight: 700, color: 'var(--text)', lineHeight: 1 };
              const CAP: React.CSSProperties = { fontSize: 10, fontWeight: 600, letterSpacing: '0.07em', color: 'var(--muted)', textTransform: 'uppercase', marginTop: 4, textAlign: 'center' };

              return (
                <Panel title="Affected Assets">
                  <div style={{ margin: '-12px -16px' }}>
                    <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
                      <div style={STAT}>
                        <span style={NUM}>{total}</span>
                        <span style={CAP}>Total Assets</span>
                      </div>
                      <div style={STAT}>
                        <span style={{ ...NUM, color: externalCount > 0 ? '#c53030' : 'var(--text)' }}>{externalCount}</span>
                        <span style={CAP}>External Facing</span>
                      </div>
                      <div style={{ ...STAT, borderRight: 'none' }}>
                        <span style={{ ...NUM, color: criticalCount > 0 ? '#9b2335' : 'var(--text)' }}>{criticalCount}</span>
                        <span style={CAP}>Critical Assets</span>
                      </div>
                    </div>
                    <div style={{ padding: '8px 14px' }}>
                      <button className="fd3-asset-link" style={{ fontSize: 12 }}
                        onClick={() => setActiveTab('affected-assets')}>
                        View full asset list →
                      </button>
                    </div>
                  </div>
                </Panel>
              );
            })()}

            {/* 3. Asset Ownership */}
            {ownership && (
              <Panel title="Asset Ownership">
                <div className="fd3-kv-table">
                  <KVRow label="Owner">{ownership.displayName || 'Unassigned'}</KVRow>
                  <KVRow label="Owner Team">{ownership.ownerTeam || '—'}</KVRow>
                  <KVRow label="Owner Email">{ownership.ownerEmail || '—'}</KVRow>
                  <KVRow label="Managed By">{ownership.managedBy || '—'}</KVRow>
                  <KVRow label="Department">{ownership.department || '—'}</KVRow>
                  <KVRow label="Support Group">{ownership.supportGroup || '—'}</KVRow>
                  <KVRow label="Asset Assigned To">{ownership.assignedTo || '—'}</KVRow>
                  <KVRow label="Source">{ownershipSource}</KVRow>
                  <KVRow label="Authority">{ownership.authority || '—'}</KVRow>
                  <KVRow label="Last Ownership Sync">{fmtDt(currentFinding.ownershipSyncedAt)}</KVRow>
                </div>
              </Panel>
            )}

          </div>

          {/* ── RIGHT: CVE + Remediation ──────────────────────────────── */}
          <div className="fd3-col fd3-col-right">

            <Panel title="Vulnerability">
              <div className="fd3-kv-table">
                <KVRow label="CVE ID">
                  <button className="fd3-cve-link" onClick={() => navigate(pathForVulnRepoView('org-cves' as VulnerabilityIntelRouteView, cve))}>
                    {cve}
                  </button>
                </KVRow>
                {cveDetail?.summary.description && (
                  <KVRow label="Summary">
                    <span style={{ fontSize: 12, lineHeight: 1.5 }}>{cveDetail.summary.description}</span>
                  </KVRow>
                )}
                <KVRow label="Severity">
                  <span className={`severity-pill severity-${currentFinding.severity.toLowerCase()}`}>{currentFinding.severity}</span>
                </KVRow>
                <KVRow label="Risk Score">{currentFinding.riskScore.toFixed(1)}</KVRow>
                {currentFinding.findingsScore != null && (
                  <KVRow label="Findings Score">{currentFinding.findingsScore.toFixed(1)}</KVRow>
                )}
                {cveDetail?.summary.cvssScore != null && (
                  <KVRow label="Vulnerability Score (v3)">{cveDetail.summary.cvssScore.toFixed(1)}</KVRow>
                )}
                {cveDetail?.summary.publishedAt && (
                  <KVRow label="Date Published">{fmtDate(cveDetail.summary.publishedAt)}</KVRow>
                )}
                {cveDetail?.signals && (
                  <KVRow label="Exploit Exists">{cveDetail.signals.exploitAvailable ? 'Yes' : 'No'}</KVRow>
                )}
                {currentFinding.epss != null && (
                  <KVRow label="EPSS">{(currentFinding.epss * 100).toFixed(2)}%</KVRow>
                )}
                {cveDetail?.summary.modifiedAt && (
                  <KVRow label="Last Modified">{fmtDate(cveDetail.summary.modifiedAt)}</KVRow>
                )}
              </div>
            </Panel>

            {aiSolution?.data && (
              <Panel title="Remediation Guidance">
                {aiSolution.data.bottom_line && (
                  <div className="fd3-solution-summary">
                    <p className="fd3-solution-text">{aiSolution.data.bottom_line.summary}</p>
                  </div>
                )}
                {aiSolution.data.primary_fix && (
                  <div className="fd3-kv-table" style={{ marginTop: 10 }}>
                    <KVRow label="Action">{aiSolution.data.primary_fix.action}</KVRow>
                    {aiSolution.data.primary_fix.target_version && (
                      <KVRow label="Target Version"><span className="mono">{aiSolution.data.primary_fix.target_version}</span></KVRow>
                    )}
                    {aiSolution.data.primary_fix.verification && (
                      <KVRow label="Verification">{aiSolution.data.primary_fix.verification}</KVRow>
                    )}
                    {aiSolution.data.primary_fix.reboot_required != null && (
                      <KVRow label="Reboot Required">{aiSolution.data.primary_fix.reboot_required ? 'Yes' : 'No'}</KVRow>
                    )}
                  </div>
                )}
                {aiSolution.data.timeline && aiSolution.data.timeline.length > 0 && (
                  <div className="fd3-timeline">
                    {aiSolution.data.timeline.map((t, i) => (
                      <div key={i} className="fd3-timeline-item" style={{ borderLeftColor: t.color }}>
                        <div className="fd3-timeline-window">{t.window} · {t.label}</div>
                        <ul className="fd3-timeline-actions">
                          {t.actions.map((a, j) => <li key={j}>{a}</li>)}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
                {aiSolution.data.compensating_controls && aiSolution.data.compensating_controls.length > 0 && (
                  <details className="fd3-details">
                    <summary className="fd3-details-summary">Compensating Controls ({aiSolution.data.compensating_controls.length})</summary>
                    <div className="fd3-kv-table" style={{ marginTop: 8 }}>
                      {aiSolution.data.compensating_controls.map((c, i) => (
                        <KVRow key={i} label={c.control}>
                          <span className="fd3-muted">{c.effort} effort · {c.effectiveness} effectiveness</span>
                        </KVRow>
                      ))}
                    </div>
                  </details>
                )}
              </Panel>
            )}

          </div>
        </div>
      )}

      {/* ── AFFECTED ASSETS TAB ─────────────────────────────────────────── */}
      {activeTab === 'affected-assets' && (
        <div style={{ padding: '20px 0' }}>
          <div className="fd3-panel">
            <div className="fd3-panel-title">Affected Assets</div>
            <div className="fd3-panel-body" style={{ padding: 0 }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                <thead>
                  <tr style={{ background: 'var(--panel-muted)', borderBottom: '2px solid var(--border)' }}>
                    <th style={{ padding: '8px 16px', textAlign: 'left', fontWeight: 600, fontSize: 11, color: 'var(--muted)', letterSpacing: '0.06em' }}>ASSET ID</th>
                    <th style={{ padding: '8px 16px', textAlign: 'left', fontWeight: 600, fontSize: 11, color: 'var(--muted)', letterSpacing: '0.06em' }}>HOST NAME</th>
                    <th style={{ padding: '8px 16px', textAlign: 'left', fontWeight: 600, fontSize: 11, color: 'var(--muted)', letterSpacing: '0.06em' }}>SOFTWARE</th>
                    <th style={{ padding: '8px 16px', textAlign: 'left', fontWeight: 600, fontSize: 11, color: 'var(--muted)', letterSpacing: '0.06em' }}>VERSION</th>
                    <th style={{ padding: '8px 16px', textAlign: 'left', fontWeight: 600, fontSize: 11, color: 'var(--muted)', letterSpacing: '0.06em' }}>TYPE</th>
                  </tr>
                </thead>
                <tbody>
                  {isGroupedFinding && affectedAssetsFromEvidence.length > 0
                    ? affectedAssetsFromEvidence.map((a, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border)', cursor: a.assetId ? 'pointer' : 'default' }}
                          onClick={() => a.assetId && navigate(pathForInventoryHostAsset(a.assetId))}>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 11, color: 'var(--muted)' }}>
                            {a.assetIdentifier || (a.componentId ? a.componentId.slice(0, 8).toUpperCase() : '—')}
                          </td>
                          <td style={{ padding: '10px 16px', fontWeight: 500, color: a.assetId ? 'var(--accent, #3b82f6)' : 'var(--text)' }}>
                            {a.assetName || '—'}
                          </td>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12 }}>{a.packageName || '—'}</td>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12 }}>{a.version || '—'}</td>
                          <td style={{ padding: '10px 16px', color: 'var(--muted)', fontSize: 12 }}>{fmt(a.assetType)}</td>
                        </tr>
                      ))
                    : (
                        <tr style={{ borderBottom: '1px solid var(--border)', cursor: hostAssetId ? 'pointer' : 'default' }}
                          onClick={() => hostAssetId && navigate(pathForInventoryHostAsset(hostAssetId))}>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 11, color: 'var(--muted)' }}>
                            {currentFinding.assetIdentifier || '—'}
                          </td>
                          <td style={{ padding: '10px 16px', fontWeight: 500, color: hostAssetId ? 'var(--accent, #3b82f6)' : 'var(--text)' }}>
                            {currentFinding.assetName || '—'}
                          </td>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12 }}>{currentFinding.packageName || '—'}</td>
                          <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontSize: 12 }}>{currentFinding.packageVersion || '—'}</td>
                          <td style={{ padding: '10px 16px', color: 'var(--muted)', fontSize: 12 }}>{fmt(currentFinding.assetType)}</td>
                        </tr>
                      )
                  }
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {renderModal()}
    </div>
  );
}
