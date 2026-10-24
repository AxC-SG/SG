import React from 'react';
import { RefreshCw } from 'lucide-react';
import { TENANTS } from '../data';
import { Badge, StatTile } from '../components/primitives';
import { Alert, Spinner, useToast } from '../components/feedback';
import { Checkbox, PasswordInput, TextInput } from '../components/forms';
import { Modal } from '../components/overlays';

// Reference for the "console" pattern — PlatformConsolePage + TenantLifecyclePanel.
// Keeps: secondary rail with helper text, inline create form (no new click to reach it),
// PROVISIONING notice, per-row action buttons visible inline, extension dialog.

const RAIL = [
  { group: 'Tenant Management', items: [
    { label: 'Tenants', helper: 'Lifecycle and workspace metadata', active: true },
    { label: 'Users', helper: 'Provision and manage platform-owner identities' },
    { label: 'Platform Audit', helper: 'Review platform-user identity changes and setup history' },
    { label: 'Demo Requests', helper: 'Review, provision, and invite customer demo tenants' },
  ] },
];

function TenantStatus({ status }: { status: string }) {
  if (status === 'ACTIVE') return <Badge tone="success" dot>ACTIVE</Badge>;
  if (status === 'SUSPENDED') return <Badge tone="warning" dot>SUSPENDED</Badge>;
  if (status === 'PROVISIONING') return <Badge tone="accent"><Spinner size={10} /> PROVISIONING</Badge>;
  if (status === 'PROVISIONING_FAILED') return <Badge tone="critical" dot>PROVISIONING_FAILED</Badge>;
  return <Badge dot>{status}</Badge>;
}

export function PlatformTenantsPage() {
  const toast = useToast();
  const [extending, setExtending] = React.useState<string | null>(null);
  const [creating, setCreating] = React.useState(false);

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    setCreating(true);
    window.setTimeout(() => { setCreating(false); toast('info', 'Tenant queued — status PROVISIONING until bootstrap verifies it.'); }, 700);
  };

  return (
    <div className="dp-page dp-page--wide">
      <div className="dp-console">
        <aside className="dp-console-rail" aria-label="Platform views">
          <div className="dp-console-rail-title">Platform workspace</div>
          {RAIL.map((group) => (
            <section key={group.group} aria-label={group.group}>
              <div className="dp-nav-title">{group.group}</div>
              {group.items.map((item) => (
                <button key={item.label} type="button" className={`dp-console-link${item.active ? ' active' : ''}`} title={item.helper}>
                  <span>{item.label}</span>
                  <small>{item.helper}</small>
                </button>
              ))}
            </section>
          ))}
        </aside>

        <div className="dp-console-content">
          <div className="dp-section-head dp-row-between">
            <div><h2>Tenant Lifecycle</h2><p>Create, provision and manage tenant workspaces.</p></div>
            <button type="button" className="dp-btn dp-btn--sm"><RefreshCw size={13} /> Refresh</button>
          </div>

          <div className="dp-kpi-grid dp-kpi-grid--4">
            <StatTile label="Active" value="2" tone="low" />
            <StatTile label="Provisioning" value="1" tone="accent" />
            <StatTile label="Needs attention" value="1" sub="Provisioning failed" tone="critical" />
            <StatTile label="Demo tenants" value="1" sub="Expires Nov 7" tone="warning" />
          </div>

          <form className="dp-card dp-inline-form" onSubmit={submit}>
            <div className="dp-inline-form-fields">
              <TextInput name="name" placeholder="Tenant name" aria-label="Tenant name" />
              <TextInput name="slug" placeholder="tenant-slug" aria-label="Tenant slug" className="dp-mono" />
              <TextInput name="billingRef" placeholder="Billing reference" aria-label="Billing reference" />
              <TextInput name="ownerEmail" type="email" placeholder="Demo owner email (optional)" aria-label="Demo owner email" />
              <PasswordInput name="ownerPassword" placeholder="Demo password (8+ chars)" aria-label="Demo owner password" autoComplete="new-password" />
              <Checkbox name="addDemoData" label="Add demo data" />
            </div>
            <button type="submit" className="dp-btn dp-btn--primary" disabled={creating}>{creating ? 'Creating...' : 'Create Tenant'}</button>
          </form>

          <Alert tone="info" role="status">
            New tenants remain in <strong>PROVISIONING</strong> until the controlled production bootstrap runs.
            Workspace access and tenant operations are enabled only after verification changes the tenant to <strong>ACTIVE</strong>.
            Expired and blocked tenants retain their data until a platform owner deletes them manually.
          </Alert>

          <div className="dp-table-card">
            <div className="dp-table-scroll">
              <table className="dp-table">
                <thead>
                  <tr>
                    <th>Tenant</th><th>Owner Email</th><th>Slug</th><th>Status</th><th>Demo Data</th><th>Workspace</th>
                    <th>Daily Exposure Refreshes</th><th>Demo Expires</th><th>Created</th><th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {TENANTS.map((t) => (
                    <tr key={t.id} className="static">
                      <td><span className="dp-cell-title"><span className="dp-ws-mark sm" style={{ background: t.color }}>{t.initials}</span><strong>{t.name}</strong></span></td>
                      <td className="dp-muted">{t.owner}</td>
                      <td><code className="dp-code-inline">{t.slug}</code></td>
                      <td>
                        <div className="dp-cell-stack">
                          <TenantStatus status={t.status} />
                          {t.status === 'PROVISIONING' ? <small className="dp-muted">Awaiting controlled bootstrap</small> : null}
                          {t.status === 'PROVISIONING_FAILED' ? <small className="dp-text-critical">Provisioning failed. Review the bootstrap report.</small> : null}
                          <small className="dp-muted">Schema {t.schema}</small>
                        </div>
                      </td>
                      <td className="dp-mono dp-muted">{t.demo}</td>
                      <td>{t.plan}</td>
                      <td className="dp-num">{t.refreshes}</td>
                      <td className="dp-num">{t.expires ?? '-'}</td>
                      <td className="dp-num dp-muted">{t.created}</td>
                      <td>
                        <div className="dp-cell-actions">
                          {t.status === 'PROVISIONING_FAILED' ? <button type="button" className="dp-btn dp-btn--sm">Retry provisioning</button> : null}
                          {t.expires ? <button type="button" className="dp-btn dp-btn--sm" onClick={() => setExtending(t.name)}>Extend</button> : null}
                          {t.status === 'ACTIVE' ? <button type="button" className="dp-btn dp-btn--sm">Block access</button> : null}
                          {t.status === 'SUSPENDED' ? <button type="button" className="dp-btn dp-btn--sm">Restore access</button> : null}
                          <button type="button" className="dp-btn dp-btn--sm">{t.owner !== '-' ? 'Reset owner credential' : 'Set owner credential'}</button>
                          <button type="button" className="dp-btn dp-btn--sm dp-btn--danger-ghost" disabled title="Tenant deletion is temporarily unavailable. Expiry and access controls remain available.">Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <Modal
        open={extending !== null}
        onClose={() => setExtending(null)}
        title={`Extend ${extending ?? ''}`}
        description="Choose a new demo expiry. Must be in the future."
        size="sm"
        footer={<><button type="button" className="dp-btn" onClick={() => setExtending(null)}>Cancel</button><button type="button" className="dp-btn dp-btn--primary" onClick={() => setExtending(null)}>Extend</button></>}
      >
        <label className="dp-field"><span className="dp-label">New expiry</span><TextInput type="datetime-local" defaultValue="2026-11-21T17:00" aria-label="New expiry" /></label>
      </Modal>
    </div>
  );
}
