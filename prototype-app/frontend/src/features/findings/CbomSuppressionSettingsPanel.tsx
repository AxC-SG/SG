import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api, type CbomSuppressionSettingsUpdate } from '../../api/client';
import { useActor } from '../auth/context';
import { hasRole } from '../auth/roles';

const LIMITS: Array<{ key: keyof Pick<CbomSuppressionSettingsUpdate, 'lowSuppressionMaxDays' | 'mediumSuppressionMaxDays' | 'highSuppressionMaxDays' | 'criticalSuppressionMaxDays'>; label: string; max: number }> = [
  { key: 'lowSuppressionMaxDays', label: 'Low', max: 365 },
  { key: 'mediumSuppressionMaxDays', label: 'Medium', max: 180 },
  { key: 'highSuppressionMaxDays', label: 'High', max: 90 },
  { key: 'criticalSuppressionMaxDays', label: 'Critical', max: 30 },
];

export function CbomSuppressionSettingsPanel() {
  const actor = useActor();
  const isTenantAdmin = hasRole(actor, 'TENANT_ADMIN');
  const query = useQuery({
    queryKey: ['cbom-suppression-settings'],
    queryFn: api.getCbomSuppressionSettings,
    enabled: isTenantAdmin,
  });
  const [form, setForm] = React.useState<CbomSuppressionSettingsUpdate | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [message, setMessage] = React.useState('');

  React.useEffect(() => {
    if (!query.data) return;
    setForm({
      requireDistinctSuppressionApprover: query.data.requireDistinctSuppressionApprover,
      suppressionRequestDeadlineDays: query.data.suppressionRequestDeadlineDays,
      lowSuppressionMaxDays: query.data.lowSuppressionMaxDays,
      mediumSuppressionMaxDays: query.data.mediumSuppressionMaxDays,
      highSuppressionMaxDays: query.data.highSuppressionMaxDays,
      criticalSuppressionMaxDays: query.data.criticalSuppressionMaxDays,
    });
  }, [query.data]);

  if (!isTenantAdmin) return null;

  async function save() {
    if (!form) return;
    setSaving(true); setMessage('');
    try {
      const saved = await api.updateCbomSuppressionSettings(form);
      setForm({
        requireDistinctSuppressionApprover: saved.requireDistinctSuppressionApprover,
        suppressionRequestDeadlineDays: saved.suppressionRequestDeadlineDays,
        lowSuppressionMaxDays: saved.lowSuppressionMaxDays,
        mediumSuppressionMaxDays: saved.mediumSuppressionMaxDays,
        highSuppressionMaxDays: saved.highSuppressionMaxDays,
        criticalSuppressionMaxDays: saved.criticalSuppressionMaxDays,
      });
      setMessage('Suppression policy saved.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Suppression policy could not be saved.');
    } finally { setSaving(false); }
  }

  return (
    <section className="panel" aria-labelledby="cbom-suppression-policy-title">
      <div className="panel-header">
        <div>
          <h3 id="cbom-suppression-policy-title">CBOM Suppression Policy</h3>
          <span className="panel-caption">Tenant-owned approval deadlines and maximum exception periods.</span>
        </div>
      </div>
      {query.isPending ? <p className="panel-caption" style={{ padding: '0 16px 16px' }}>Loading suppression policy…</p>
        : query.isError || !form ? <div className="notice error" role="alert" style={{ margin: '0 16px 16px' }}>Suppression policy could not be loaded.</div>
        : <div className="ingestion-form" style={{ display: 'grid', gap: 12 }}>
            <label style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input type="checkbox" checked={form.requireDistinctSuppressionApprover}
                onChange={event => setForm(current => current ? { ...current, requireDistinctSuppressionApprover: event.target.checked } : current)} />
              Require a different tenant admin to approve suppression requests
            </label>
            <label className="form-field">
              <span>Decision deadline (days)</span>
              <input className="form-input" type="number" min={1} max={14} value={form.suppressionRequestDeadlineDays}
                onChange={event => setForm(current => current ? { ...current, suppressionRequestDeadlineDays: Number(event.target.value) } : current)} />
            </label>
            <div className="form-grid">
              {LIMITS.map(limit => (
                <label className="form-field" key={limit.key}>
                  <span>{limit.label} maximum (days)</span>
                  <input className="form-input" type="number" min={1} max={limit.max} value={form[limit.key]}
                    onChange={event => setForm(current => current ? { ...current, [limit.key]: Number(event.target.value) } : current)} />
                </label>
              ))}
            </div>
            {message && <div className={message.includes('saved') ? 'notice success' : 'notice error'} role="status">{message}</div>}
            <div><button type="button" className="btn btn-primary" disabled={saving} onClick={() => void save()}>{saving ? 'Saving…' : 'Save policy'}</button></div>
          </div>}
    </section>
  );
}
