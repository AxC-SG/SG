import { useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api, type CbomRuleConfigurationRequest, type CbomRuleImpactPreview } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { useActor } from '../auth/context';
import { hasRole } from '../auth/roles';
import { formatDate, titleCase } from './labels';

/** Tenant CBOM rule package selection: version policy, parameters, impact preview and audited activation. */
export function CbomRulesPanel() {
  const actor = useActor();
  const isTenantAdmin = hasRole(actor, 'TENANT_ADMIN');
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['cbom-rule-configuration'], queryFn: () => api.getCbomRuleConfiguration() });
  const config = query.data;
  const [draft, setDraft] = React.useState<CbomRuleConfigurationRequest | null>(null);
  const [preview, setPreview] = React.useState<{ key: string; result: CbomRuleImpactPreview } | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<{ tone: 'success' | 'error'; text: string } | null>(null);

  React.useEffect(() => {
    if (config && !draft) {
      setDraft({ versionPolicy: config.versionPolicy, pinnedVersion: config.pinnedVersion, parameters: { ...config.parameters }, reason: '' });
    }
  }, [config, draft]);

  const draftKey = draft ? JSON.stringify({ ...draft, reason: undefined }) : '';
  const previewed = preview?.key === draftKey;
  const pinnable = (config?.availableVersions ?? []).filter((version) => version.pinnable);

  async function run(action: 'preview' | 'activate') {
    if (!draft) return;
    setBusy(true);
    setMessage(null);
    try {
      if (action === 'preview') {
        setPreview({ key: draftKey, result: await api.previewCbomRuleConfiguration(draft) });
      } else {
        await api.updateCbomRuleConfiguration(draft);
        setMessage({ tone: 'success', text: 'Rule configuration activated. Affected CBOMs are reassessed by the assessment worker.' });
        setDraft(null);
        setPreview(null);
        await client.invalidateQueries({ queryKey: ['cbom-rule-configuration'] });
      }
    } catch (failure) {
      setMessage({ tone: 'error', text: failure instanceof Error ? failure.message : 'The rule configuration could not be saved.' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel cbom-rules-panel">
      <div className="panel-header">
        <h3>CBOM rule package</h3>
        {config && <span className="panel-caption">{config.packageId} · effective {config.effectiveVersion ?? 'unavailable'} · {titleCase(config.pinState)}</span>}
      </div>
      <AsyncSection state={query.isPending ? 'pending' : query.isError ? 'error' : 'ready'} loadingLabel="Loading rule configuration…"
        errorMessage="The CBOM rule configuration could not be loaded." onRetry={() => void query.refetch()} retryLabel="Retry rule configuration">
        {config && draft && (
          <>
            {config.remediation && <div className={`notice ${config.pinState === 'UNSUPPORTED' ? 'error' : 'warning'}`} role="status">{config.remediation}</div>}
            <form className="crypto-campaign-form" onSubmit={(event) => { event.preventDefault(); void run(previewed ? 'activate' : 'preview'); }}>
              <fieldset disabled={!isTenantAdmin || busy}>
                <legend>Version policy</legend>
                <label><input type="radio" name="cbom-version-policy" checked={draft.versionPolicy === 'FOLLOW_LATEST'}
                  onChange={() => setDraft({ ...draft, versionPolicy: 'FOLLOW_LATEST', pinnedVersion: null })} /> Follow the latest released package</label>
                <label><input type="radio" name="cbom-version-policy" checked={draft.versionPolicy === 'PINNED'}
                  onChange={() => setDraft({ ...draft, versionPolicy: 'PINNED', pinnedVersion: draft.pinnedVersion ?? pinnable[pinnable.length - 1]?.version ?? null })} /> Pin a version</label>
                {draft.versionPolicy === 'PINNED' && (
                  <label>Pinned version
                    <select value={draft.pinnedVersion ?? ''} onChange={(event) => setDraft({ ...draft, pinnedVersion: event.target.value })}>
                      {pinnable.map((version) => <option key={version.version} value={version.version}>{version.version} — {version.title}</option>)}
                    </select>
                  </label>
                )}
              </fieldset>
              <fieldset disabled={!isTenantAdmin || busy}>
                <legend>Parameters</legend>
                {Object.entries(draft.parameters).map(([name, value]) => (
                  <label key={name}>{titleCase(name.replace(/([A-Z])/g, '_$1'))}
                    <input type="number" value={value} onChange={(event) => setDraft({ ...draft, parameters: { ...draft.parameters, [name]: Number(event.target.value) } })} />
                  </label>
                ))}
              </fieldset>
              {isTenantAdmin && (
                <label>Reason for the change
                  <textarea value={draft.reason} onChange={(event) => setDraft({ ...draft, reason: event.target.value })} rows={2} disabled={busy} />
                </label>
              )}
              {preview && previewed && (
                <div className="notice" role="status">
                  <div>
                    Impact over {preview.result.activeComponents} active components: RSA key-size findings {preview.result.currentRsaFindings}
                    {' → '}{preview.result.projectedRsaFindings}; expiring-certificate findings {preview.result.currentExpiringCertificateFindings}
                    {' → '}{preview.result.projectedExpiringCertificateFindings}.
                  </div>
                  <div>Package {preview.result.fromVersion ?? 'none'} → {preview.result.toVersion}
                    {preview.result.addedRules.length > 0 ? `; adds ${preview.result.addedRules.join(', ')}` : ''}
                    {preview.result.removedRules.length > 0 ? `; removes ${preview.result.removedRules.join(', ')}` : ''}
                    {preview.result.changedRuleModes.length > 0 ? `; mode changes ${preview.result.changedRuleModes.join(', ')}` : ''}.</div>
                  {Object.keys(preview.result.changedParameters).length > 0 && (
                    <div>Parameters: {Object.entries(preview.result.changedParameters).map(([name, [before, after]]) => `${name} ${before ?? '—'} → ${after}`).join('; ')}.</div>
                  )}
                  <div className="panel-caption">Bounds: {preview.result.safetyBounds.join(', ')}.</div>
                </div>
              )}
              {message && <div className={`notice ${message.tone}`} role={message.tone === 'error' ? 'alert' : 'status'}>{message.text}</div>}
              {isTenantAdmin ? (
                <div className="cbom-report-actions">
                  <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void run('preview')}>Preview impact</button>
                  <button type="submit" className="btn btn-primary btn-sm" disabled={busy || !previewed || !draft.reason.trim()}>Activate configuration</button>
                  {!previewed && <span className="panel-caption">Preview the impact of these settings before activating them.</span>}
                </div>
              ) : <p className="panel-caption">Only a tenant administrator can change the rule configuration.</p>}
            </form>
            {config.history.length > 0 && (
              <section aria-labelledby="cbom-rule-history">
                <h4 id="cbom-rule-history">Selection history</h4>
                <ul className="cbom-claim-list">
                  {config.history.map((entry) => (
                    <li key={entry.id}>
                      <strong>{titleCase(entry.action)}</strong> {entry.fromVersion ?? '—'} → {entry.toVersion ?? '—'} by {entry.actor}, {formatDate(entry.createdAt)}
                      <div className="panel-caption">{entry.reason}</div>
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </AsyncSection>
    </div>
  );
}
