import React from 'react';
import { AsyncSection } from '../../components/AsyncSection';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { ownershipErrorText } from './errors';
import { useAuthorityTransitionMutation, useOwnershipQualificationQuery } from './queries';
import type { OwnershipAuthorityState } from './types';

const STATE_TEXT: Record<OwnershipAuthorityState, string> = {
  LEGACY: 'Legacy ownership rules are authoritative. The canonical model is not running.',
  DARK: 'Dark qualification: sources publish canonical claims for review, but readers still see legacy ownership.',
  CANONICAL: 'Canonical ownership is authoritative. The automatic rollback window is closed; recovery is source pause and a forward fix.'
};

const CHECK_LABELS: Record<string, string> = {
  unlinkedAssets: 'Assets not linked to a subject',
  unlinkedFindings: 'Vulnerability findings not linked',
  queuedResolutions: 'Queued re-resolutions',
  unsweptExpiredClaims: 'Expired claims not yet swept',
  staleResolverVersions: 'Assignments on an old resolver version',
  inheritanceErrors: 'Inheritance errors',
  openProducerAnomalies: 'Open producer anomalies',
  openConflicts: 'Open conflicts',
  openUnmappedValues: 'Open unmapped values',
  effectiveCacheBacklog: 'Effective-cache backlog'
};

type Pending = { to: OwnershipAuthorityState; reportHash?: string } | null;

/** CORE authority switch (plan §15.3): LEGACY→DARK, DARK→LEGACY (no-go) and DARK→CANONICAL (go, bound to the report). */
export function CutoverPanel() {
  const report = useOwnershipQualificationQuery(true);
  const transition = useAuthorityTransitionMutation();
  const [pending, setPending] = React.useState<Pending>(null);
  const data = report.data;

  const confirmText = pending?.to === 'DARK'
    ? 'Ownership producers start publishing canonical claims and the populate step links assets and findings to subjects. Readers keep seeing legacy ownership.'
    : pending?.to === 'LEGACY'
      ? 'Returns core ownership to the legacy model. Allowed only while no canonical change has been accepted.'
      : `Core inventory and vulnerability findings switch to canonical ownership. This closes the automatic rollback window and cannot be undone from here. Approving report ${data?.reportHash.slice(0, 12) ?? ''}….`;

  return (
    <section className="ownership-coverage" aria-label="Core ownership cutover">
      <h3>Core ownership cutover</h3>
      <AsyncSection
        state={report.isPending ? 'pending' : report.isError && !data ? 'error' : 'ready'}
        loadingLabel="Running the qualification report…"
        errorMessage={ownershipErrorText(report.error, 'The qualification report could not be loaded.')}
        onRetry={() => void report.refetch()}
        retrying={report.isFetching}
        isRefreshing={report.isFetching && !report.isPending}
      >
        {data && (
          <>
            <p>
              <span className={`status-pill ${data.state === 'CANONICAL' ? 'status-success' : data.state === 'DARK' ? 'status-investigating' : 'status-unknown'}`}>
                {data.state}
              </span>{' '}
              {STATE_TEXT[data.state]}
            </p>
            {data.state === 'DARK' && (
              data.passed
                ? <div className="notice success" role="status">Qualification passed. Review the comparison before accepting.</div>
                : (
                  <div className="notice warning" role="status">
                    <strong>Blocked:</strong>
                    <ul>{data.blockers.map((blocker) => <li key={blocker}>{blocker}</li>)}</ul>
                  </div>
                )
            )}
            {data.state !== 'LEGACY' && (
              <dl className="ownership-counts">
                {Object.entries(data.checks).map(([key, value]) => (
                  <div key={key}>
                    <dt>{CHECK_LABELS[key] ?? key}</dt>
                    <dd>{value.toLocaleString()}</dd>
                  </div>
                ))}
                <div><dt>Legacy and canonical agree</dt><dd>{data.comparison.match.toLocaleString()}</dd></div>
                <div><dt>Legacy and canonical differ</dt><dd>{data.comparison.mismatch.toLocaleString()}</dd></div>
                <div><dt>Legacy owner only</dt><dd>{data.comparison.legacyOnly.toLocaleString()}</dd></div>
                <div><dt>Canonical owner only</dt><dd>{data.comparison.canonicalOnly.toLocaleString()}</dd></div>
              </dl>
            )}
            {transition.isError && <div className="notice error" role="alert">{ownershipErrorText(transition.error, 'The switch was not made.')}</div>}
            <div className="button-row">
              {data.state === 'LEGACY' && (
                <button type="button" className="btn btn-secondary" onClick={() => { transition.reset(); setPending({ to: 'DARK' }); }}>
                  Start dark qualification
                </button>
              )}
              {data.state === 'DARK' && (
                <>
                  <button type="button" className="btn btn-secondary" disabled={report.isFetching} onClick={() => void report.refetch()}>
                    {report.isFetching ? 'Refreshing…' : 'Refresh report'}
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={() => { transition.reset(); setPending({ to: 'LEGACY' }); }}>
                    Return to legacy (no-go)
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={!data.passed || report.isFetching}
                    onClick={() => { transition.reset(); setPending({ to: 'CANONICAL', reportHash: data.reportHash }); }}
                  >
                    Accept and switch to canonical
                  </button>
                </>
              )}
            </div>
          </>
        )}
      </AsyncSection>
      <ConfirmDialog
        isOpen={pending !== null}
        title={pending?.to === 'CANONICAL' ? 'Switch core ownership to canonical?' : pending?.to === 'DARK' ? 'Start dark qualification?' : 'Return to legacy ownership?'}
        message={
          <>
            {confirmText}
            {transition.isError && <div className="notice error" role="alert">{ownershipErrorText(transition.error, 'The switch was not made.')}</div>}
          </>
        }
        confirmLabel={pending?.to === 'CANONICAL' ? 'Switch to canonical' : pending?.to === 'DARK' ? 'Start qualification' : 'Return to legacy'}
        busy={transition.isPending}
        busyMessage="Applying the switch…"
        onConfirm={() => pending && transition.mutate({ state: pending.to, reportHash: pending.reportHash }, { onSuccess: () => setPending(null) })}
        onCancel={() => setPending(null)}
      />
    </section>
  );
}
