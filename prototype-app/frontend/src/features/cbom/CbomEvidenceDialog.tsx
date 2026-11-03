import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { CbomBlastRadius } from './CbomBlastRadius';
import { Link } from 'react-router-dom';
import { pathForFindingDetail } from '../../app/routes';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { Dialog } from '../../components/Dialog';
import { assuranceLabel, formatDate, presenceLabel, severityBadgeClass, titleCase } from './labels';

/** Evidence drawer: provenance, claim assurance, explainable findings and relationships for one component. */
export function CbomEvidenceDialog({ componentId, onClose }: { componentId: string | null; onClose: () => void }) {
  const detailQuery = useQuery({
    queryKey: ['cbom-component-detail', componentId],
    queryFn: () => api.getCbomComponentDetail(componentId as string),
    enabled: componentId != null,
  });
  const detail = detailQuery.data;
  const [showRadius, setShowRadius] = React.useState(false);
  React.useEffect(() => { setShowRadius(false); }, [componentId]);
  const state = detailQuery.isPending ? 'pending' : detailQuery.isError ? 'error' : 'ready';

  return (
    <Dialog isOpen={componentId != null} onClose={onClose} title={detail ? `Evidence: ${detail.component.name}` : 'Component evidence'}
      className="cbom-evidence-dialog">
      <AsyncSection
        state={state}
        loadingLabel="Loading component evidence…"
        errorMessage="Component evidence could not be loaded."
        onRetry={() => void detailQuery.refetch()}
        retryLabel="Retry component evidence"
        retrying={detailQuery.isFetching}
      >
        {detail && (
          <div className="cbom-evidence">
            <section aria-labelledby="cbom-evidence-provenance">
              <h3 id="cbom-evidence-provenance">Source provenance</h3>
              {detail.provenance ? (
                <dl className="cbom-definition-list">
                  <dt>Document</dt><dd>{detail.provenance.documentName ?? '—'} ({titleCase(detail.provenance.bomStatus)})</dd>
                  <dt>Serial number</dt><dd className="monospace">{detail.provenance.serialNumber ?? '—'}</dd>
                  <dt>SHA-256</dt><dd className="monospace cbom-wrap">{detail.provenance.checksumSha256 ?? '—'}</dd>
                  <dt>Source</dt><dd>{[detail.provenance.sourceMethod, detail.provenance.sourceType, detail.provenance.sourceLabel].filter(Boolean).join(' · ') || '—'}</dd>
                  <dt>Ingested</dt><dd>{formatDate(detail.provenance.ingestedAt)}</dd>
                  <dt>Rule package</dt><dd>{detail.provenance.rulePackage ?? 'Not yet assessed'}</dd>
                  <dt>Evaluator</dt><dd>{detail.provenance.evaluatorVersion ?? '—'}</dd>
                  <dt>Assessed</dt><dd>{formatDate(detail.provenance.assessedAt)}</dd>
                </dl>
              ) : <p className="panel-caption">The source document is no longer available.</p>}
            </section>

            <section aria-labelledby="cbom-evidence-claims">
              <h3 id="cbom-evidence-claims">Important claims</h3>
              {detail.claims.length === 0 ? (
                <p className="panel-caption">No assessed claims yet. Run an assessment to record claim assurance.</p>
              ) : (
                <ul className="cbom-claim-list">
                  {detail.claims.map((claim) => (
                    <li key={claim.claimPath}>
                      <code>{claim.claimPath}</code>{' '}
                      <span className="tag" title="How strongly ScoutGrid has verified this claim">{assuranceLabel(claim.assuranceLevel)}</span>{' '}
                      <span className="tag" title="Whether the source document still supports this claim">{presenceLabel(claim.evidenceState)}</span>
                      <div className="panel-caption">{claim.explanation}</div>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section aria-labelledby="cbom-evidence-findings">
              <h3 id="cbom-evidence-findings">Findings ({detail.findings.length})</h3>
              {detail.findings.length === 0 ? <p className="panel-caption">No findings were raised for this component.</p> : (
                <ul className="cbom-finding-list">
                  {detail.findings.map((finding) => (
                    <li key={finding.id}>
                      <span className={`status-badge ${severityBadgeClass(finding.severity)}`}>{finding.severity}</span>{' '}
                      <strong>{finding.title}</strong> <span className="panel-caption">{finding.ruleId}{finding.ruleVersion ? ` v${finding.ruleVersion}` : ''}</span>
                      <div>{finding.detail}</div>
                      {finding.recommendation && <div><strong>Recommendation:</strong> {finding.recommendation}</div>}
                      <div className="panel-caption">
                        {presenceLabel(finding.evidenceState)} · Source status {titleCase(finding.status)}
                        {finding.canonical ? (
                          <> · <Link to={pathForFindingDetail(finding.canonical.id)}>{finding.canonical.displayId}</Link>
                            {' '}({titleCase(finding.canonical.status)}{finding.canonical.assignedTo ? `, owner ${finding.canonical.assignedTo}` : ''})</>
                        ) : ' · Not yet in the Findings queue'}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section aria-labelledby="cbom-evidence-blast-radius">
              <h3 id="cbom-evidence-blast-radius">Blast radius</h3>
              {showRadius ? <CbomBlastRadius componentId={detail.component.id} /> : (
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowRadius(true)}>Show blast radius</button>
              )}
            </section>

            <section aria-labelledby="cbom-evidence-relationships">
              <h3 id="cbom-evidence-relationships">Relationships</h3>
              {detail.relationships.length === 0 ? <p className="panel-caption">No declared relationships.</p> : (
                <ul>
                  {detail.relationships.map((relationship) => (
                    <li key={`${relationship.direction}-${relationship.otherId}-${relationship.relationshipType}`}>
                      {relationship.direction === 'OUTBOUND' ? 'Depends on' : 'Used by'} {relationship.otherName ?? relationship.otherId}
                      {' '}<span className="panel-caption">({titleCase(relationship.evidenceKind)})</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        )}
      </AsyncSection>
      <div className="confirm-dialog-actions">
        <button type="button" className="btn btn-secondary" onClick={onClose}>Close</button>
      </div>
    </Dialog>
  );
}
