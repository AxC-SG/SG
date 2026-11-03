import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { Dialog } from '../../components/Dialog';
import { formatDate, percent } from './labels';

const GROUPS = [
  { value: 'department', label: 'Business unit' },
  { value: 'ownerTeam', label: 'Owner team' },
  { value: 'environment', label: 'Environment' },
  { value: 'businessCriticality', label: 'Business criticality' },
];

/** Portfolio rollups and post-quantum migration progress. */
export function CbomPortfolioPanel({ canManage }: { canManage: boolean }) {
  const [groupBy, setGroupBy] = React.useState('department');
  const portfolio = useQuery({ queryKey: ['cbom-portfolio', groupBy], queryFn: () => api.getCbomPortfolio(groupBy) });
  const pqc = useQuery({ queryKey: ['cbom-pqc-progress'], queryFn: () => api.getCbomPqcProgress() });
  const [open, setOpen] = React.useState(false);
  const [created, setCreated] = React.useState<{ id: string; name: string } | null>(null);

  return (
    <div className="cbom-overview">
      <section className="panel" aria-labelledby="cbom-pqc-heading">
        <h3 id="cbom-pqc-heading">Post-quantum migration</h3>
        {created && <div className="notice success" role="status">Campaign <Link to={`/vuln-repo/campaigns/${encodeURIComponent(created.id)}`}>{created.name}</Link> created.</div>}
        <AsyncSection state={pqc.isPending ? 'pending' : pqc.isError ? 'error' : 'ready'} loadingLabel="Loading PQC progress…"
          errorMessage="PQC migration progress could not be loaded." onRetry={() => void pqc.refetch()} retryLabel="Retry PQC progress">
          {pqc.data && (
            <>
              <p>{pqc.data.openQuantumVulnerable} open quantum-vulnerable findings: {pqc.data.inCampaigns} in migration campaigns, {pqc.data.notInCampaign} not yet planned.</p>
              {canManage && pqc.data.notInCampaign > 0 && (
                <button type="button" className="btn btn-primary btn-sm" onClick={() => setOpen(true)}>Plan a PQC migration campaign</button>
              )}
              {pqc.data.campaigns.length > 0 && (
                <div className="table-scroll">
                  <table className="data-table">
                    <thead><tr><th>Campaign</th><th>Owners</th><th>Due</th><th>Progress</th><th>Open</th><th>Overdue</th></tr></thead>
                    <tbody>
                      {pqc.data.campaigns.map((campaign) => (
                        <tr key={campaign.campaignId}>
                          <td><Link to={`/vuln-repo/campaigns/${encodeURIComponent(campaign.campaignId)}`}>{campaign.name}</Link> <span className="panel-caption">{campaign.status}</span></td>
                          <td>{campaign.owners.length === 0 ? 'Unassigned' : campaign.owners.join(', ')}</td>
                          <td>{formatDate(campaign.dueAt)}</td>
                          <td>{percent(campaign.percentComplete)} ({campaign.resolved} of {campaign.findings})</td>
                          <td>{campaign.open}</td>
                          <td>{campaign.overdue}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </AsyncSection>
      </section>

      <section className="panel" aria-labelledby="cbom-portfolio-heading">
        <h3 id="cbom-portfolio-heading">Portfolio rollup</h3>
        <label>Group by
          <select value={groupBy} onChange={(event) => setGroupBy(event.target.value)}>
            {GROUPS.map((group) => <option key={group.value} value={group.value}>{group.label}</option>)}
          </select>
        </label>
        <AsyncSection state={portfolio.isPending ? 'pending' : portfolio.isError ? 'error' : (portfolio.data?.groups.length ?? 0) === 0 ? 'empty' : 'ready'}
          loadingLabel="Loading portfolio…" errorMessage="The portfolio rollup could not be loaded." onRetry={() => void portfolio.refetch()}
          retryLabel="Retry portfolio rollup" emptyMessage="No assets have active cryptographic inventory yet.">
          <div className="table-scroll">
            <table className="data-table">
              <thead><tr><th>Group</th><th>Assets</th><th>Crypto assets</th><th>Critical</th><th>High</th><th>Quantum-vulnerable</th><th>Open crypto findings</th><th>Overdue</th><th>Avg posture</th></tr></thead>
              <tbody>
                {(portfolio.data?.groups ?? []).map((group) => (
                  <tr key={group.group}>
                    <td>{group.group}</td><td>{group.assets}</td><td>{group.components}</td><td>{group.openCritical}</td><td>{group.openHigh}</td>
                    <td>{group.quantumVulnerable}</td><td>{group.openCryptoFindings}</td><td>{group.overdueCryptoFindings}</td>
                    <td>{group.averagePostureScore ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </AsyncSection>
      </section>
      <PqcCampaignDialog isOpen={open} onClose={() => setOpen(false)}
        onCreated={(campaign) => { setOpen(false); setCreated(campaign); void pqc.refetch(); }} />
    </div>
  );
}

function PqcCampaignDialog({ isOpen, onClose, onCreated }: { isOpen: boolean; onClose: () => void; onCreated: (c: { id: string; name: string }) => void }) {
  const [name, setName] = React.useState('');
  const [due, setDue] = React.useState('');
  const [owner, setOwner] = React.useState('');
  const [environment, setEnvironment] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const response = await api.createCbomPqcCampaign({ name: name.trim(), dueAt: new Date(`${due}T23:59:59Z`).toISOString(),
        assignedTo: owner.trim() || undefined, environment: environment.trim() || undefined });
      onCreated({ id: response.summary.id, name: response.summary.name });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The campaign could not be created.');
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog isOpen={isOpen} onClose={onClose} title="Plan a PQC migration campaign" busy={busy} busyMessage="Creating campaign…">
      <form className="crypto-campaign-form" onSubmit={(event) => void submit(event)}>
        <p className="panel-caption">Every open quantum-vulnerable crypto finding in scope is linked to the campaign.</p>
        <label>Campaign name<input value={name} onChange={(event) => setName(event.target.value)} required autoFocus /></label>
        <label>Migration due date<input type="date" value={due} onChange={(event) => setDue(event.target.value)} required /></label>
        <label>Owner (optional)<input value={owner} onChange={(event) => setOwner(event.target.value)} /></label>
        <label>Environment scope (optional)<input value={environment} onChange={(event) => setEnvironment(event.target.value)} placeholder="All environments" /></label>
        {error && <div className="notice error" role="alert">{error}</div>}
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || !name.trim() || !due}>Create campaign</button>
        </div>
      </form>
    </Dialog>
  );
}
