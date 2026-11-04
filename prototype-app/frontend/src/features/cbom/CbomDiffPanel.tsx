import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { COMPONENT_CHANGES, FINDING_OUTCOMES, severityBadgeClass, titleCase } from './labels';

const OUTCOME_ORDER = ['INTRODUCED', 'PERSISTING', 'REMEDIATED', 'NOT_OBSERVED', 'WITHDRAWN', 'ACCEPTED_RISK', 'AMBIGUOUS'];

/** Semantic diff against the predecessor CBOM; outcomes keep remediation, omission, withdrawal and accepted risk distinct. */
export function CbomDiffPanel({ bomId }: { bomId: string }) {
  const query = useQuery({ queryKey: ['cbom-semantic-diff', bomId], queryFn: () => api.getCbomSemanticDiff(bomId) });
  const diff = query.data;
  const state = query.isPending ? 'pending' : query.isError ? 'error' : diff?.baselineSource === 'NONE' ? 'empty' : 'ready';

  return (
    <div className="panel cbom-diff-panel">
      <div className="panel-header">
        <h3>Changes from the previous version</h3>
        {diff?.baselineBomId && <span className="panel-caption">Compared with document {diff.baselineBomId}</span>}
      </div>
      <AsyncSection state={state} loadingLabel="Comparing with the previous CBOM…" errorMessage="The CBOM comparison could not be loaded."
        onRetry={() => void query.refetch()} retryLabel="Retry CBOM comparison" retrying={query.isFetching}
        emptyMessage="This is the first version of this CBOM, so there is nothing to compare yet.">
        {diff && (
          <>
            <section aria-labelledby="cbom-diff-outcomes">
              <h4 id="cbom-diff-outcomes">Finding outcomes</h4>
              <ul className="cbom-outcome-summary">
                {OUTCOME_ORDER.filter((key) => diff.findingSummary[key]).map((key) => (
                  <li key={key}>
                    <strong>{FINDING_OUTCOMES[key].label}: {diff.findingSummary[key]}</strong>
                    <div className="panel-caption">{FINDING_OUTCOMES[key].description}</div>
                  </li>
                ))}
                {Object.keys(diff.findingSummary).length === 0 && <li className="panel-caption">No findings in either version.</li>}
              </ul>
              <p className="panel-caption">
                Open findings {diff.posture.openBefore} → {diff.posture.openAfter}
                {Object.entries(diff.componentSummary).map(([key, count]) => ` · ${COMPONENT_CHANGES[key] ?? titleCase(key)} components ${count}`).join('')}
              </p>
            </section>

            {diff.ambiguous.length > 0 && (
              <div className="notice warning" role="status">
                {diff.ambiguous.length} component {diff.ambiguous.length === 1 ? 'identity matches' : 'identities match'} more than one asset;
                {' '}their changes are not guessed. Give each asset a unique bom-ref to compare them.
              </div>
            )}

            {diff.findingOutcomes.length > 0 && (
              <div className="table-scroll">
                <table className="data-table">
                  <caption className="panel-caption">Per-finding outcomes</caption>
                  <thead><tr><th>Outcome</th><th>Component</th><th>Rule</th><th>Severity</th><th>Finding status</th></tr></thead>
                  <tbody>
                    {diff.findingOutcomes.map((outcome) => (
                      <tr key={`${outcome.outcome}-${outcome.baselineFindingId ?? ''}-${outcome.currentFindingId ?? ''}`}>
                        <td>{FINDING_OUTCOMES[outcome.outcome]?.label ?? titleCase(outcome.outcome)}</td>
                        <td>{outcome.componentName}</td>
                        <td>{outcome.title} <span className="panel-caption">{outcome.ruleId}</span></td>
                        <td>
                          <span className={`status-badge ${severityBadgeClass(outcome.severityAfter ?? outcome.severityBefore)}`}>
                            {outcome.severityAfter ?? outcome.severityBefore}
                          </span>
                          {outcome.severityBefore && outcome.severityAfter && outcome.severityBefore !== outcome.severityAfter
                            ? <span className="panel-caption"> (was {outcome.severityBefore})</span> : null}
                        </td>
                        <td>{outcome.canonicalStatus ? titleCase(outcome.canonicalStatus) : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {diff.componentChanges.length > 0 && (
              <div className="table-scroll">
                <table className="data-table">
                  <caption className="panel-caption">Component changes</caption>
                  <thead><tr><th>Change</th><th>Component</th><th>Details</th></tr></thead>
                  <tbody>
                    {diff.componentChanges.map((change) => (
                      <tr key={`${change.changeType}-${change.identity}`}>
                        <td>{COMPONENT_CHANGES[change.changeType] ?? titleCase(change.changeType)}</td>
                        <td>{change.name} <span className="panel-caption">{titleCase(change.assetType)}</span></td>
                        <td>
                          {change.fields.length === 0 ? '—' : change.fields.map((field) => (
                            <div key={field.field}>{field.field}: {field.before ?? '—'} → {field.after ?? '—'}
                              <span className="panel-caption"> ({titleCase(field.category)})</span></div>
                          ))}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {diff.assuranceChanges.length > 0 && (
              <ul className="cbom-assurance-changes" aria-label="Claim assurance changes">
                {diff.assuranceChanges.map((change) => (
                  <li key={`${change.identity}-${change.claim}`}>
                    {change.identity} · {change.claim}: assurance {titleCase(change.before)} → {titleCase(change.after)} ({titleCase(change.direction)})
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </AsyncSection>
    </div>
  );
}
