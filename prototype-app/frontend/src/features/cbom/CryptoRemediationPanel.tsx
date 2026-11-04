import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link } from 'react-router-dom';
import { pathForFindingDetail } from '../../app/routes';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { CryptoCampaignDialog } from './CryptoCampaignDialog';
import { formatDate, percent, severityBadgeClass, titleCase } from './labels';
import type { CryptoQueueItem } from './types';

const EFFECTIVENESS_DAYS = 90;

/** Crypto remediation operations: verification queue, overdue work, SLA by severity and effectiveness. */
export function CryptoRemediationPanel({ canManage }: { canManage: boolean }) {
  const queueQuery = useQuery({ queryKey: ['crypto-remediation-queue'], queryFn: () => api.getCryptoRemediationQueue() });
  const effectivenessQuery = useQuery({
    queryKey: ['crypto-remediation-effectiveness', EFFECTIVENESS_DAYS],
    queryFn: () => api.getCryptoRemediationEffectiveness(EFFECTIVENESS_DAYS),
  });
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [created, setCreated] = React.useState<{ id: string; name: string } | null>(null);
  const queue = queueQuery.data;
  const queueState = queueQuery.isPending ? 'pending' : queueQuery.isError ? 'error'
    : queue && queue.slaBySeverity.length === 0 ? 'empty' : 'ready';
  const effectiveness = effectivenessQuery.data;

  const toggle = (id: string) => setSelected((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  return (
    <div className="cbom-overview">
      {created && (
        <div className="notice success" role="status">
          Campaign <Link to={`/vuln-repo/campaigns/${encodeURIComponent(created.id)}`}>{created.name}</Link> created.
        </div>
      )}
      <AsyncSection state={queueState} loadingLabel="Loading crypto remediation queue…"
        errorMessage="The crypto remediation queue could not be loaded." onRetry={() => void queueQuery.refetch()}
        retryLabel="Retry crypto remediation queue" retrying={queueQuery.isFetching}
        emptyMessage="There are no open CRYPTO findings to remediate.">
        {queue && (
          <>
            <section className="panel" aria-labelledby="crypto-sla-heading">
              <h3 id="crypto-sla-heading">SLA by severity</h3>
              <div className="table-scroll">
                <table className="data-table">
                  <thead><tr><th>Severity</th><th>Open</th><th>Overdue</th><th>Due within 7 days</th><th>Unassigned</th></tr></thead>
                  <tbody>
                    {queue.slaBySeverity.map((row) => (
                      <tr key={row.severity}>
                        <td><span className={`status-badge ${severityBadgeClass(row.severity)}`}>{row.severity}</span></td>
                        <td>{row.open}</td><td>{row.overdue}</td><td>{row.dueWithin7Days}</td><td>{row.unassigned}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
            <QueueTable title="Awaiting verification" id="crypto-verification-queue" items={queue.verificationQueue}
              empty="No verification requests are waiting." selected={selected} onToggle={canManage ? toggle : undefined} showTarget />
            <QueueTable title="Overdue" id="crypto-overdue-queue" items={queue.overdue}
              empty="No CRYPTO findings are past their due date." selected={selected} onToggle={canManage ? toggle : undefined} />
            {canManage && (
              <div className="cbom-report-actions">
                <button type="button" className="btn btn-primary btn-sm" disabled={selected.size === 0} onClick={() => setDialogOpen(true)}>
                  Create campaign from {selected.size} selected
                </button>
                {selected.size > 0 && <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>Clear selection</button>}
              </div>
            )}
          </>
        )}
      </AsyncSection>

      <section className="panel" aria-labelledby="crypto-effectiveness-heading">
        <h3 id="crypto-effectiveness-heading">Remediation effectiveness (last {EFFECTIVENESS_DAYS} days)</h3>
        <AsyncSection state={effectivenessQuery.isPending ? 'pending' : effectivenessQuery.isError ? 'error' : 'ready'}
          loadingLabel="Loading remediation effectiveness…" errorMessage="Remediation effectiveness could not be loaded."
          onRetry={() => void effectivenessQuery.refetch()} retryLabel="Retry remediation effectiveness">
          {effectiveness && (
            <>
              <dl className="cbom-definition-list">
                <dt>Opened</dt><dd>{effectiveness.opened}</dd>
                <dt>Closed</dt><dd>{effectiveness.closed} ({effectiveness.verifiedClosures} by verified reassessment)</dd>
                <dt>Reopened</dt><dd>{effectiveness.reopened}</dd>
                <dt>Verification acceptance</dt>
                <dd>{percent(effectiveness.verificationAcceptanceRate)} ({effectiveness.verificationsAccepted} accepted, {effectiveness.verificationsRejected} rejected)</dd>
              </dl>
              {effectiveness.bySeverity.length > 0 && (
                <div className="table-scroll">
                  <table className="data-table">
                    <thead><tr><th>Severity</th><th>Closed</th><th>Mean days to close</th><th>Closed within SLA</th></tr></thead>
                    <tbody>
                      {effectiveness.bySeverity.map((row) => (
                        <tr key={row.severity}>
                          <td>{row.severity}</td><td>{row.closed}</td><td>{row.meanDaysToClose ?? '—'}</td><td>{percent(row.closedWithinSla)}</td>
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

      <CryptoCampaignDialog isOpen={dialogOpen} findingIds={[...selected]} onClose={() => setDialogOpen(false)}
        onCreated={(campaign) => { setDialogOpen(false); setSelected(new Set()); setCreated(campaign); void queueQuery.refetch(); }} />
    </div>
  );
}

function QueueTable({ title, id, items, empty, selected, onToggle, showTarget = false }: {
  title: string; id: string; items: CryptoQueueItem[]; empty: string; selected: Set<string>;
  onToggle?: (id: string) => void; showTarget?: boolean;
}) {
  return (
    <section className="panel" aria-labelledby={id}>
      <h3 id={id}>{title} ({items.length})</h3>
      {items.length === 0 ? <p className="panel-caption">{empty}</p> : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                {onToggle && <th><span className="panel-caption">Select</span></th>}
                <th>Finding</th><th>Severity</th><th>Owner</th><th>Due</th>{showTarget ? <th>Target state</th> : <th>Workflow</th>}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.findingId}>
                  {onToggle && (
                    <td><input type="checkbox" checked={selected.has(item.findingId)} onChange={() => onToggle(item.findingId)}
                      aria-label={`Select ${item.displayId}`} /></td>
                  )}
                  <td><Link to={pathForFindingDetail(item.findingId)}>{item.displayId}</Link> {item.title}</td>
                  <td><span className={`status-badge ${severityBadgeClass(item.severity)}`}>{item.severity ?? 'UNKNOWN'}</span></td>
                  <td>{item.assignedTo ?? item.ownerGroup ?? 'Unassigned'}</td>
                  <td>{formatDate(item.dueAt)}{item.overdue ? ' (overdue)' : ''}</td>
                  <td>{showTarget ? item.targetState ?? '—' : titleCase(item.workflowSubstate ?? item.status)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
