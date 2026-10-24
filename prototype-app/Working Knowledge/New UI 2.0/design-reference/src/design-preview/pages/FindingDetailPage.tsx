import { useCapabilities } from '../previewContext';
import React from 'react';
import { AlertTriangle, ArrowLeft, Check, Pencil, Server, X } from 'lucide-react';
import { FINDINGS } from '../data';
import { Badge, Card, Meter, SeverityBadge, StatusBadge } from '../components/primitives';
import { Alert, FreshnessStatus } from '../components/feedback';
import { CodeBlock, PropertyList, Tabs } from '../components/disclosure';
import { Field, Select, TextInput, Textarea } from '../components/forms';
import { Modal } from '../components/overlays';

// Reference for the "record detail" pattern — FindingDetailPage (fd3-*), and by extension
// HostAssetDetailPage, SoftwareIdentityDetailPage, AiAssetDetailPage, CampaignDetailPage.
// Panels and row labels match FindingDetailPage; action set depends on status exactly as today.

type ModalKind = 'create-incident' | 'under-investigation' | 'defer' | 'resolve' | 'false-positive' | 'reopen';
const MODAL_TITLE: Record<ModalKind, string> = {
  'create-incident': 'Create Incident', 'under-investigation': 'Under Investigation', defer: 'Defer', resolve: 'Resolve', 'false-positive': 'False Positive', reopen: 'Re-open',
};

export function FindingDetailPage({ id, onNavigate }: { id: string; onNavigate: (route: string) => void }) {
  const { canTriage } = useCapabilities();
  const finding = FINDINGS.find((f) => f.id === id) ?? FINDINGS[0];
  const [tab, setTab] = React.useState<'overview' | 'affected-assets'>('overview');
  const [modal, setModal] = React.useState<ModalKind | null>(null);
  const [editingAssignee, setEditingAssignee] = React.useState(false);
  const [assignee, setAssignee] = React.useState(finding.assignedTo ?? '');
  const overdue = (finding.dueInDays ?? 1) < 0;
  const affected = FINDINGS.filter((f) => f.cve === finding.cve);

  return (
    <div className="dp-page dp-page--detail">
      <div className="dp-detail-head">
        <button type="button" className="dp-btn dp-btn--ghost dp-btn--sm" onClick={() => onNavigate('/findings')}><ArrowLeft size={14} /> Back</button>
        <div className="dp-detail-title">
          <div className="dp-detail-title-row">
            <h1 className="dp-mono">{finding.id}</h1>
            <StatusBadge status={finding.status} />
            {overdue ? <Badge tone="critical"><AlertTriangle size={11} /> Target Missed</Badge> : null}
          </div>
          <p>{finding.cve} · {finding.title} on <span className="dp-mono">{finding.asset}</span></p>
        </div>
        <fieldset className="dp-detail-actions dp-form-boundary" disabled={!canTriage}>
          <button type="button" className="dp-btn dp-btn--sm" onClick={() => setModal('create-incident')}>+ Create Incident</button>
          {finding.status === 'OPEN' ? (
            <>
              <button type="button" className="dp-btn dp-btn--sm" onClick={() => setModal('under-investigation')}>Under Investigation</button>
              <button type="button" className="dp-btn dp-btn--sm" onClick={() => setModal('defer')}>Defer</button>
              <button type="button" className="dp-btn dp-btn--sm dp-btn--primary" onClick={() => setModal('resolve')}>Resolve</button>
              <button type="button" className="dp-btn dp-btn--sm dp-btn--danger-ghost" onClick={() => setModal('false-positive')}>False Positive</button>
            </>
          ) : (
            <button type="button" className="dp-btn dp-btn--sm" onClick={() => setModal('reopen')}>Re-open</button>
          )}
        </fieldset>
      </div>
      <FreshnessStatus updatedAt="Oct 24, 2026, 10:46 AM" refreshLabel="Loading supporting investigation context while keeping the finding visible…" />

      <Tabs
        label="Finding sections"
        value={tab}
        onChange={setTab}
        tabs={[{ value: 'overview', label: 'Overview' }, { value: 'affected-assets', label: 'Affected Assets', count: affected.length }]}
      />

      {tab === 'overview' ? (
        <div className="dp-detail-body">
          <div className="dp-detail-col">
            <Card title="Details">
              <PropertyList items={[
                ['Status', <StatusBadge key="s" status={finding.status} />],
                ['Created By', finding.creationSource === 'MANUAL' ? 'Manual' : 'Automatic'],
                ['S.AI Priority', <span key="p" className="dp-cell-title"><Meter value={finding.priority} /><span className="dp-muted dp-text-sm">KEV · EPSS {Math.round(finding.epss * 100)}% · SLA proximity</span></span>],
                ['Risk Score', finding.risk.toFixed(1)],
                ['Due Date', finding.dueInDays === null ? <span key="d" className="dp-muted">—</span> : <span key="d" className={overdue ? 'dp-text-critical' : ''}>2026-11-{String(Math.max(1, Math.min(28, 4 + (finding.dueInDays ?? 0)))).padStart(2, '0')}{overdue ? ' ⚠' : ''}</span>],
                ['Assigned To', editingAssignee ? (
                  <span key="a" className="dp-inline-edit">
                    <TextInput autoFocus value={assignee} placeholder="username or email" onChange={(e) => setAssignee(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') setEditingAssignee(false); if (e.key === 'Escape') setEditingAssignee(false); }} />
                    <button type="button" className="dp-icon-btn sm" aria-label="Save assignee" onClick={() => setEditingAssignee(false)}><Check size={13} /></button>
                    <button type="button" className="dp-icon-btn sm" aria-label="Cancel" onClick={() => { setAssignee(finding.assignedTo ?? ''); setEditingAssignee(false); }}><X size={13} /></button>
                  </span>
                ) : (
                  <button key="a" type="button" className="dp-editable" disabled={!canTriage} onClick={() => setEditingAssignee(true)}>{assignee || 'Unassigned'} <Pencil size={11} /></button>
                )],
                ['Assignment Group', finding.ownerGroup ?? '—'],
                ['Incident ID', finding.incidentId ? <span key="i" className="dp-mono">{finding.incidentId}</span> : '—'],
                ['First Observed', finding.firstObserved],
                ['Last Observed', finding.lastObserved],
              ]} />
            </Card>
            <Card title="Asset Ownership">
              <PropertyList items={[
                ['Owner', finding.owner ?? '—'],
                ['Owner Team', finding.ownerGroup ?? '—'],
                ['Owner Email', finding.owner ? `${finding.owner.toLowerCase().replace(/\s+/g, '.')}@acme.example` : '—'],
                ['Support Group', finding.supportGroup ?? '—'],
                ['Managed By', 'ServiceNow CMDB'],
                ['Last Ownership Sync', '2026-10-24 08:00'],
              ]} />
            </Card>
          </div>
          <div className="dp-detail-col">
            <Card title="Vulnerability">
              <PropertyList items={[
                ['CVE ID', <button key="c" type="button" className="dp-link dp-mono" onClick={() => onNavigate('/x/vuln-repo/org-cves')}>{finding.cve}</button>],
                ['Severity', <SeverityBadge key="sv" severity={finding.severity} />],
                ['Vulnerability Score (v3)', finding.risk.toFixed(1)],
                ['EPSS', `${(finding.epss * 100).toFixed(1)}%`],
                ['Exploit Exists', finding.kev ? <Badge key="k" tone="critical">Yes · CISA KEV</Badge> : 'No'],
                ['Package', <span key="pk" className="dp-mono">{finding.package}</span>],
                ['Date Published', '2026-09-30'],
                ['Summary', finding.title],
              ]} />
            </Card>
            <Card title="Remediation Guidance">
              {finding.fixedIn ? (
                <>
                  <PropertyList items={[
                    ['Fix Type', 'Vendor patch'],
                    ['Target Version', <span key="t" className="dp-mono">{finding.fixedIn}</span>],
                    ['Reboot Required', 'No'],
                    ['Verification', 'Re-scan SBOM after deploy'],
                  ]} />
                  <CodeBlock language="shell" code={`# Upgrade ${finding.package.split('@')[0]}\nmvn versions:use-dep-version -Dincludes=*:${finding.package.split('@')[0]} -DdepVersion=${finding.fixedIn}`} />
                </>
              ) : (
                <Alert tone="warning" title="No vendor fix available">Apply a compensating control and track via a deferral.</Alert>
              )}
            </Card>
          </div>
        </div>
      ) : (
        <Card title="Affected Assets">
          <div className="dp-table-scroll">
            <table className="dp-table">
              <thead><tr><th>Asset</th><th>Type</th><th>Package</th><th>Version</th><th>Status</th></tr></thead>
              <tbody>
                {affected.map((f) => (
                  <tr key={f.id} className="static">
                    <td><span className="dp-cell-title"><Server size={13} className="dp-muted" /><span className="dp-mono">{f.asset}</span></span></td>
                    <td className="dp-muted">{f.assetType.replace('_', ' ').toLowerCase()}</td>
                    <td className="dp-mono">{f.package.split('@')[0]}</td>
                    <td className="dp-mono">{f.package.split('@')[1]}</td>
                    <td><StatusBadge status={f.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Modal
        open={modal !== null}
        onClose={() => setModal(null)}
        title={modal ? MODAL_TITLE[modal] : ''}
        footer={<><button type="button" className="dp-btn" onClick={() => setModal(null)}>Cancel</button><button type="button" className="dp-btn dp-btn--primary" onClick={() => setModal(null)}>Confirm</button></>}
      >
        {modal === 'create-incident' ? (
          <div className="dp-form">
            <Field label="Priority" htmlFor="d-priority"><Select id="d-priority"><option>2 - High</option><option>1 - Critical</option></Select></Field>
            <Field label="Notes" htmlFor="d-notes"><Textarea id="d-notes" rows={3} /></Field>
          </div>
        ) : (
          <Field label="Comment" htmlFor="d-comment" hint="Recorded in the finding audit history."><Textarea id="d-comment" rows={3} /></Field>
        )}
      </Modal>
    </div>
  );
}
