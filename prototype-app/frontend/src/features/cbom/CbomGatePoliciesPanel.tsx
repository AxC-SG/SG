import { useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { useActor } from '../auth/context';
import { hasRole } from '../auth/roles';
import type { CbomGatePolicy } from './types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/** Environment-specific CI gate policies for CBOM pushes. Pipelines read results with their single-job gate token. */
export function CbomGatePoliciesPanel() {
  const isAdmin = hasRole(useActor(), 'TENANT_ADMIN');
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['cbom-gate-policies'], queryFn: () => api.listCbomGatePolicies() });
  const [environment, setEnvironment] = React.useState('production');
  const [severities, setSeverities] = React.useState<string[]>(['CRITICAL', 'HIGH']);
  const [minimum, setMinimum] = React.useState('0.8');
  const [blockOnInvalid, setBlockOnInvalid] = React.useState(true);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const existing: CbomGatePolicy | undefined = (query.data ?? []).find((policy) => policy.environment === environment.trim().toLowerCase());

  function edit(policy: CbomGatePolicy) {
    setEnvironment(policy.environment);
    setSeverities(policy.failOnSeverities);
    setMinimum(String(policy.minimumCompleteness));
    setBlockOnInvalid(policy.blockOnInvalid);
    setMessage(null);
  }

  async function save(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      await api.saveCbomGatePolicy(environment.trim().toLowerCase(), {
        failOnSeverities: severities, minimumCompleteness: Number(minimum), blockOnInvalid, version: existing?.version,
      });
      setMessage({ tone: 'success', text: `Gate policy for ${environment.trim().toLowerCase()} saved.` });
      await client.invalidateQueries({ queryKey: ['cbom-gate-policies'] });
    } catch (failure) {
      setMessage({ tone: 'error', text: failure instanceof Error ? failure.message : 'The gate policy could not be saved.' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel cbom-rules-panel">
      <div className="panel-header">
        <h3>CI gate policies</h3>
        <span className="panel-caption">Push with <code>environment=</code>; poll the status URL with the returned <code>X-Scout-Gate-Token</code>.</span>
      </div>
      <AsyncSection state={query.isPending ? 'pending' : query.isError ? 'error' : 'ready'} loadingLabel="Loading gate policies…"
        errorMessage="Gate policies could not be loaded." onRetry={() => void query.refetch()} retryLabel="Retry gate policies">
        {(query.data ?? []).length === 0 ? (
          <p className="panel-caption">No environment policy is configured; pipelines use the default (fail on critical or high findings, completeness at least 80%).</p>
        ) : (
          <ul className="cbom-claim-list">
            {(query.data ?? []).map((policy) => (
              <li key={policy.environment}>
                <strong>{policy.environment}</strong>: fail on {policy.failOnSeverities.join(', ')}; completeness ≥ {Math.round(policy.minimumCompleteness * 100)}%;
                {policy.blockOnInvalid ? ' invalid documents block' : ' invalid documents do not block'}
                {isAdmin && <> {' '}<button type="button" className="btn btn-ghost btn-sm" onClick={() => edit(policy)} aria-label={`Edit ${policy.environment} gate policy`}>Edit</button></>}
              </li>
            ))}
          </ul>
        )}
        {isAdmin ? (
          <form className="crypto-campaign-form" onSubmit={(event) => void save(event)}>
            <label>Environment<input value={environment} onChange={(event) => setEnvironment(event.target.value)} required pattern="[a-z0-9][a-z0-9-]{0,39}" /></label>
            <fieldset>
              <legend>Fail on open findings of severity</legend>
              {SEVERITIES.map((severity) => (
                <label key={severity}>
                  <input type="checkbox" checked={severities.includes(severity)}
                    onChange={() => setSeverities((current) => current.includes(severity) ? current.filter((value) => value !== severity) : [...current, severity])} />
                  {' '}{severity.charAt(0) + severity.slice(1).toLowerCase()}
                </label>
              ))}
            </fieldset>
            <label>Minimum completeness (0–1)<input type="number" min={0} max={1} step={0.05} value={minimum} onChange={(event) => setMinimum(event.target.value)} required /></label>
            <label><input type="checkbox" checked={blockOnInvalid} onChange={(event) => setBlockOnInvalid(event.target.checked)} /> Invalid CBOM documents block the gate</label>
            {message && <div className={`notice ${message.tone}`} role={message.tone === 'error' ? 'alert' : 'status'}>{message.text}</div>}
            <div className="cbom-report-actions">
              <button type="submit" className="btn btn-primary btn-sm" disabled={busy || severities.length === 0}>{existing ? 'Update policy' : 'Create policy'}</button>
            </div>
          </form>
        ) : <p className="panel-caption">Only a tenant administrator can change gate policies.</p>}
      </AsyncSection>
    </div>
  );
}
