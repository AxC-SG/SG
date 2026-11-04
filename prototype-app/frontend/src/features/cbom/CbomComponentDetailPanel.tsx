import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { pathForCbomComponent, pathForFindingDetail } from '../../app/routes';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { timeAgo } from '../../lib/time';
import { CbomBlastRadius } from './CbomBlastRadius';
import { assuranceLabel, formatDate, presenceLabel, severityBadgeClass, titleCase } from './labels';
import type { CbomComponentDetail } from './types';

type Tab = 'overview' | 'findings' | 'evidence' | 'relationships';

const CRYPTO_FIELDS: Array<{ label: string; value: (d: CbomComponentDetail) => unknown }> = [
  { label: 'Primitive / algorithm', value: (d) => d.component.primitive },
  { label: 'Parameter set', value: (d) => d.properties.parameterSetIdentifier },
  { label: 'Key size', value: (d) => d.component.keySize == null ? null : `${d.component.keySize} bits` },
  { label: 'Curve', value: (d) => d.component.curve },
  { label: 'Padding', value: (d) => d.properties.padding },
  { label: 'Protocol version', value: (d) => d.component.protocolVersion },
  { label: 'Key usage', value: (d) => d.properties.keyUsage },
  { label: 'Format', value: (d) => d.properties.format },
  { label: 'Custody / storage', value: (d) => d.component.storageLocation },
  { label: 'Transmission', value: (d) => d.properties.transmission },
  { label: 'Sensitivity', value: (d) => d.properties.sensitivity },
  { label: 'Used in', value: (d) => d.properties.usedIn },
  { label: 'Subject', value: (d) => d.properties.subject },
  { label: 'Issuer', value: (d) => d.properties.issuer },
  { label: 'Serial number', value: (d) => d.properties.serialNumber },
  { label: 'Signature algorithm', value: (d) => d.properties.signatureAlgorithm },
  { label: 'Not before', value: (d) => d.properties.notBefore },
  { label: 'Not after', value: (d) => d.component.notAfter },
];

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="cbom-detail-row">
      <dt>{label}</dt>
      <dd>{children == null || children === '' ? '—' : children}</dd>
    </div>
  );
}

/** CBOM cryptographic asset page, the CBOM counterpart of the SBOM / AI BOM component detail. */
export function CbomComponentDetailPanel({ componentId, applicationName, onClose, backLabel = '← Back to BOM Components' }: {
  componentId: string; applicationName?: string | null; onClose: () => void; backLabel?: string;
}) {
  const query = useQuery({ queryKey: ['cbom-component-detail', componentId], queryFn: () => api.getCbomComponentDetail(componentId) });
  const location = useLocation();
  // Related components open their own page and return here.
  const currentPath = `${location.pathname}${location.search}`;
  const [tab, setTab] = React.useState<Tab>('overview');
  React.useEffect(() => { setTab('overview'); }, [componentId]);
  const d = query.data;
  const open = d ? d.findings.filter((f) => f.status === 'OPEN' && f.evidenceState !== 'WITHDRAWN') : [];
  const count = (severity: string) => open.filter((f) => f.severity === severity).length;
  const tabs: Array<{ key: Tab; label: string }> = [
    { key: 'overview', label: 'Overview' },
    { key: 'findings', label: `Findings (${d?.findings.length ?? 0})` },
    { key: 'evidence', label: `Evidence & claims (${d?.claims.length ?? 0})` },
    { key: 'relationships', label: `Relationships (${d?.relationships.length ?? 0})` },
  ];

  return (
    <div className="cbom-component-page">
      <div><button type="button" className="btn btn-secondary btn-sm" onClick={onClose}>{backLabel}</button></div>
      <AsyncSection state={query.isPending ? 'pending' : query.isError && !d ? 'error' : 'ready'} loadingLabel="Loading cryptographic asset…"
        errorMessage="The cryptographic asset could not be loaded." onRetry={() => void query.refetch()} retryLabel="Retry cryptographic asset"
        retrying={query.isFetching}>
        {d && (
          <>
            <div className="panel cbom-component-header">
              <div>
                <div className="cbom-component-title">
                  <h2>{d.component.name}</h2>
                  {d.component.highestSeverity
                    ? <span className={`status-badge ${severityBadgeClass(d.component.highestSeverity)}`}>{d.component.highestSeverity}</span>
                    : <span className="status-pill status-auto_closed">No open findings</span>}
                </div>
                {d.properties.bomRef && <div className="mono panel-caption">{String(d.properties.bomRef)}</div>}
                <div className="cbom-component-tags">
                  <span className="tag">CBOM</span>
                  <span className="status-pill status-auto_closed">{titleCase(d.component.assetType)}</span>
                  {d.properties.active === false && <span className="status-pill status-failure">Inactive</span>}
                </div>
              </div>
              <div className="cbom-component-stats">
                <div className="panel"><strong>{open.length}</strong><span className="panel-caption">Open findings</span></div>
                <div className="panel"><strong>{count('CRITICAL')}</strong><span className="panel-caption">Critical</span></div>
                <div className="panel"><strong>{count('HIGH')}</strong><span className="panel-caption">High</span></div>
                <div className="panel"><strong>{d.component.riskScore == null ? '—' : d.component.riskScore.toFixed(2)}</strong><span className="panel-caption">Risk score</span></div>
              </div>
            </div>

            <div className="cbom-component-tabs" role="tablist" aria-label="Cryptographic asset sections">
              {tabs.map((item) => (
                <button key={item.key} type="button" role="tab" id={`cbom-tab-${item.key}`} aria-selected={tab === item.key}
                  aria-controls="cbom-component-tabpanel" className={tab === item.key ? 'active' : undefined} onClick={() => setTab(item.key)}>
                  {item.label}
                </button>
              ))}
            </div>

            <div id="cbom-component-tabpanel" role="tabpanel" aria-labelledby={`cbom-tab-${tab}`}>
              {tab === 'overview' && (
                <div className="cbom-component-grid">
                  <section className="panel" aria-labelledby="cbom-details-heading">
                    <h4 id="cbom-details-heading">Details</h4>
                    <dl>
                      <Row label="Name">{d.component.name}</Row>
                      <Row label="bom-ref"><span className="mono cbom-wrap">{d.properties.bomRef as string}</span></Row>
                      <Row label="Asset type">{titleCase(d.component.assetType)}</Row>
                      <Row label="Component type">{d.properties.componentType as string}</Row>
                      <Row label="State">{d.properties.state as string}</Row>
                      <Row label="Description">{d.properties.description as string}</Row>
                      <Row label="Application">{d.component.assetName ?? applicationName}{d.component.environment ? ` (${d.component.environment})` : ''}</Row>
                      <Row label="Source document">{d.component.sourceDocument}</Row>
                      <Row label="BOM types"><span className="tag">CBOM</span></Row>
                      <Row label="Ingested">{d.properties.createdAt ? timeAgo(String(d.properties.createdAt)) : null}</Row>
                      <Row label="Last observed">{d.properties.updatedAt ? timeAgo(String(d.properties.updatedAt)) : null}</Row>
                      <Row label="Fingerprint"><span className="mono cbom-wrap">{d.properties.componentFingerprint as string}</span></Row>
                    </dl>
                  </section>
                  <section className="panel" aria-labelledby="cbom-crypto-heading">
                    <h4 id="cbom-crypto-heading">Cryptographic properties</h4>
                    <dl>
                      {CRYPTO_FIELDS.map((field) => {
                        const value = field.value(d);
                        return <Row key={field.label} label={field.label}>{value == null ? null : String(value)}</Row>;
                      })}
                    </dl>
                  </section>
                </div>
              )}

              {tab === 'findings' && (d.findings.length === 0 ? <div className="empty-state"><p>No findings were raised for this cryptographic asset.</p></div> : (
                <div className="table-scroll">
                  <table className="data-table">
                    <thead><tr><th>Severity</th><th>Finding</th><th>Recommendation</th><th>Evidence</th><th>Status</th><th>Finding queue</th><th>Last seen</th></tr></thead>
                    <tbody>
                      {d.findings.map((finding) => (
                        <tr key={finding.id}>
                          <td><span className={`status-badge ${severityBadgeClass(finding.severity)}`}>{finding.severity}</span></td>
                          <td><strong>{finding.title}</strong><div className="panel-caption">{finding.ruleId}{finding.ruleVersion ? ` v${finding.ruleVersion}` : ''} · {titleCase(finding.riskClass)}</div>
                            {finding.detail && <div>{finding.detail}</div>}</td>
                          <td>{finding.recommendation ?? '—'}</td>
                          <td>{presenceLabel(finding.evidenceState)}</td>
                          <td>{titleCase(finding.status)}</td>
                          <td>{finding.canonical ? (
                            <><Link to={pathForFindingDetail(finding.canonical.id)}>{finding.canonical.displayId}</Link>
                              <div className="panel-caption">{titleCase(finding.canonical.status)}{finding.canonical.assignedTo ? ` · ${finding.canonical.assignedTo}` : ''}
                                {finding.canonical.dueAt ? ` · due ${formatDate(finding.canonical.dueAt)}` : ''}</div></>
                          ) : <span className="panel-caption">Not yet in the queue</span>}</td>
                          <td>{finding.lastSeenAt ? timeAgo(finding.lastSeenAt) : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}

              {tab === 'evidence' && (
                <div className="cbom-component-grid">
                  <section className="panel" aria-labelledby="cbom-provenance-heading">
                    <h4 id="cbom-provenance-heading">Source provenance</h4>
                    {d.provenance ? (
                      <dl>
                        <Row label="Document">{d.provenance.documentName}</Row>
                        <Row label="Document status">{titleCase(d.provenance.bomStatus)}</Row>
                        <Row label="Serial number"><span className="mono cbom-wrap">{d.provenance.serialNumber}</span></Row>
                        <Row label="SHA-256"><span className="mono cbom-wrap">{d.provenance.checksumSha256}</span></Row>
                        <Row label="Source">{[d.provenance.sourceMethod, d.provenance.sourceType, d.provenance.sourceLabel].filter(Boolean).join(' · ')}</Row>
                        <Row label="Ingested">{formatDate(d.provenance.ingestedAt)}</Row>
                        <Row label="Rule package">{d.provenance.rulePackage ?? 'Not yet assessed'}</Row>
                        <Row label="Package digest"><span className="mono cbom-wrap">{d.provenance.rulePackageDigest}</span></Row>
                        <Row label="Evaluator">{d.provenance.evaluatorVersion}</Row>
                        <Row label="Assessed">{formatDate(d.provenance.assessedAt)}</Row>
                      </dl>
                    ) : <p className="panel-caption">The source document is no longer available.</p>}
                  </section>
                  <section className="panel" aria-labelledby="cbom-claims-heading">
                    <h4 id="cbom-claims-heading">Important claims</h4>
                    {d.claims.length === 0 ? <p className="panel-caption">No assessed claims yet. Run an assessment to record claim assurance.</p> : (
                      <ul className="cbom-claim-list">
                        {d.claims.map((claim) => (
                          <li key={claim.claimPath}>
                            <code>{claim.claimPath}</code>{' '}
                            <span className="tag">{assuranceLabel(claim.assuranceLevel)}</span>{' '}
                            <span className="tag">{presenceLabel(claim.evidenceState)}</span>
                            <div className="panel-caption">{claim.explanation}</div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </section>
                </div>
              )}

              {tab === 'relationships' && (
                <div className="cbom-component-grid">
                  <section className="panel" aria-labelledby="cbom-relationships-heading">
                    <h4 id="cbom-relationships-heading">Declared relationships</h4>
                    {d.relationships.length === 0 ? <p className="panel-caption">This asset declares no relationships.</p> : (
                      <div className="table-scroll">
                        <table className="data-table">
                          <thead><tr><th>Direction</th><th>Relationship</th><th>Related asset</th><th>Evidence</th></tr></thead>
                          <tbody>
                            {d.relationships.map((relationship) => (
                              <tr key={`${relationship.direction}-${relationship.relationshipType}-${relationship.otherId}`}>
                                <td>{relationship.direction === 'OUTBOUND' ? 'Outbound' : 'Inbound'}</td>
                                <td>{titleCase(relationship.relationshipType)}</td>
                                <td>
                                  {relationship.otherType === 'COMPONENT' ? (
                                    <Link to={pathForCbomComponent(relationship.otherId, currentPath)}>{relationship.otherName ?? relationship.otherId}</Link>
                                  ) : (relationship.otherName ?? relationship.otherId)}
                                  {' '}<span className="panel-caption">{relationship.otherType === 'ASSET' ? 'Application' : titleCase(relationship.otherType)}</span>
                                </td>
                                <td>{titleCase(relationship.evidenceKind)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </section>
                  <section className="panel" aria-labelledby="cbom-radius-heading">
                    <h4 id="cbom-radius-heading">Blast radius</h4>
                    <CbomBlastRadius componentId={d.component.id} returnTo={currentPath} />
                  </section>
                </div>
              )}
            </div>
          </>
        )}
      </AsyncSection>
    </div>
  );
}
