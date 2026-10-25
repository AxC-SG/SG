import React from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { pathForVulnRepoView } from '../app/routes';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import { usePlatformVulnIntelDetailQuery } from '../features/vuln-repo-dashboard/queries';
import type { PlatformVulnIntelSourceObservation } from '../features/vuln-repo-dashboard/types';
import { severityClassName } from '../features/cve-workbench/formatting';

function formatLabel(value: string): string {
  if (!value) return '';
  return value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();
}

function formatDate(value?: string): string {
  if (!value) return '—';
  const d = new Date(value);
  if (isNaN(d.getTime())) return value;
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function SourceBadge({ name }: { name: string }) {
  return (
    <span className="status-pill" style={{ textTransform: 'uppercase', letterSpacing: '0.04em', fontSize: 11 }}>
      {name}
    </span>
  );
}

function SourceObservationCard({ obs }: { obs: PlatformVulnIntelSourceObservation }) {
  return (
    <div className="panel" style={{ padding: '14px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8, marginBottom: 8 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <SourceBadge name={obs.sourceSystem} />
          {obs.sourceRecordId && obs.sourceRecordId !== obs.sourceSystem && (
            <span className="mono" style={{ fontSize: 12, color: 'var(--muted)' }}>{obs.sourceRecordId}</span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
          {obs.severity && obs.severity !== 'UNKNOWN' && (
            <span className={severityClassName(obs.severity)} style={{ fontSize: 11 }}>
              {formatLabel(obs.severity)}
            </span>
          )}
          {obs.cvssScore != null && (
            <span style={{ fontSize: 12, fontWeight: 600 }}>CVSS {obs.cvssScore.toFixed(1)}</span>
          )}
        </div>
      </div>

      {obs.title && (
        <p style={{ margin: '0 0 6px', fontWeight: 600, fontSize: 13 }}>{obs.title}</p>
      )}

      {obs.description && (
        <p style={{ margin: '0 0 8px', fontSize: 13, lineHeight: 1.6, color: 'var(--text-secondary, var(--muted))' }}>
          {obs.description}
        </p>
      )}

      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 12, color: 'var(--muted)' }}>
        {obs.cvssVector && (
          <span className="mono" title="CVSS Vector" style={{ fontSize: 11 }}>{obs.cvssVector}</span>
        )}
        {obs.publishedAt && <span>Published: {formatDate(obs.publishedAt)}</span>}
        {obs.lastModifiedAt && <span>Modified: {formatDate(obs.lastModifiedAt)}</span>}
      </div>

      {obs.sourceUrl && (
        <div style={{ marginTop: 8 }}>
          <span className="panel-caption" style={{ fontSize: 11, wordBreak: 'break-all' }}>{obs.sourceUrl}</span>
        </div>
      )}
    </div>
  );
}

export function PlatformVulnIntelDetailPage() {
  const { externalId } = useParams<{ externalId: string }>();
  const navigate = useNavigate();
  const query = usePlatformVulnIntelDetailQuery(externalId ?? '');
  const detail = query.data;
  const refreshing = query.isFetching && !!detail;

  const bestDescription = detail?.fullDescription || detail?.description;

  return (
    <div className="page-grid">
      <div style={{ marginBottom: 8 }}>
        <button
          type="button"
          className="btn-link"
          onClick={() => navigate(pathForVulnRepoView('vulnerabilities'))}
        >
          ← Back to Intelligence
        </button>
      </div>

      <PageFreshnessStatus
        updatedAt={query.dataUpdatedAt}
        isRefreshing={refreshing}
        refreshLabel="Refreshing vulnerability intelligence while keeping current details visible…"
      />

      {query.isPending && !detail ? (
        <div className="panel"><div className="panel-caption">Loading...</div></div>
      ) : null}

      {!detail && !query.isPending && query.error ? (
        <div className="panel">
          <div className="notice error">
            {query.error instanceof Error ? query.error.message : 'Failed to load vulnerability details'}
          </div>
        </div>
      ) : null}

      {detail && query.error ? (
        <div className="notice error">
          Using current vulnerability details while refresh failed: {query.error instanceof Error ? query.error.message : 'Failed to refresh vulnerability details'}
        </div>
      ) : null}

      {detail ? (
        <>
          {/* Header */}
          <section className="panel">
            <div className="panel-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <h2 className="mono" style={{ margin: 0, fontSize: '1.15rem' }}>{detail.externalId}</h2>
                {detail.euvdId && (
                  <span className="mono euvd-id-badge" title="EUVD ID">{detail.euvdId}</span>
                )}
                {detail.jvndbId && (
                  <span className="mono euvd-id-badge" title="JVNDB ID">{detail.jvndbId}</span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span className={severityClassName(detail.severity)}>{formatLabel(detail.severity)}</span>
                {detail.inKev && <span className="status-pill status-warning">CISA KEV</span>}
              </div>
            </div>

            {detail.title && detail.title !== detail.externalId && (
              <h3 style={{ margin: '12px 0 6px', fontSize: '1rem' }}>{detail.title}</h3>
            )}

            {bestDescription ? (
              <p style={{ margin: '4px 0 0', lineHeight: 1.7, fontSize: 14, whiteSpace: 'pre-wrap', color: 'var(--text-secondary, inherit)' }}>
                {bestDescription}
              </p>
            ) : null}
          </section>

          {/* Scores + Timeline + KEV + Sources */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
            <section className="panel">
              <div className="panel-header"><h3>Scores</h3></div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <tbody>
                  <tr>
                    <td className="panel-caption" style={{ padding: '6px 0', width: '45%' }}>CVSS Score</td>
                    <td style={{ padding: '6px 0', fontWeight: 600 }}>
                      {detail.cvssScore != null ? detail.cvssScore.toFixed(1) : '—'}
                    </td>
                  </tr>
                  {detail.cvssVector ? (
                    <tr>
                      <td className="panel-caption" style={{ padding: '6px 0' }}>CVSS Vector</td>
                      <td className="mono" style={{ padding: '6px 0', fontSize: 11, wordBreak: 'break-all' }}>{detail.cvssVector}</td>
                    </tr>
                  ) : null}
                  <tr>
                    <td className="panel-caption" style={{ padding: '6px 0' }}>EPSS Score</td>
                    <td style={{ padding: '6px 0', fontWeight: 600 }}>
                      {detail.epssScore != null ? `${(detail.epssScore * 100).toFixed(2)}%` : '—'}
                    </td>
                  </tr>
                  {detail.cweIds ? (
                    <tr>
                      <td className="panel-caption" style={{ padding: '6px 0' }}>CWE IDs</td>
                      <td className="mono" style={{ padding: '6px 0', fontSize: 12 }}>{detail.cweIds}</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </section>

            <section className="panel">
              <div className="panel-header"><h3>Timeline</h3></div>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <tbody>
                  <tr>
                    <td className="panel-caption" style={{ padding: '6px 0', width: '45%' }}>Published</td>
                    <td style={{ padding: '6px 0' }}>{formatDate(detail.publishedAt)}</td>
                  </tr>
                  <tr>
                    <td className="panel-caption" style={{ padding: '6px 0' }}>Last Modified</td>
                    <td style={{ padding: '6px 0' }}>{formatDate(detail.modifiedAt)}</td>
                  </tr>
                </tbody>
              </table>
            </section>

            {detail.inKev ? (
              <section className="panel">
                <div className="panel-header"><h3>CISA KEV</h3></div>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <tbody>
                    <tr>
                      <td className="panel-caption" style={{ padding: '6px 0', width: '45%' }}>Date Added</td>
                      <td style={{ padding: '6px 0' }}>{formatDate(detail.kevDateAdded)}</td>
                    </tr>
                    <tr>
                      <td className="panel-caption" style={{ padding: '6px 0' }}>Due Date</td>
                      <td style={{ padding: '6px 0' }}>{formatDate(detail.kevDueDate)}</td>
                    </tr>
                    {detail.kevRequiredAction ? (
                      <tr>
                        <td className="panel-caption" style={{ padding: '6px 0', verticalAlign: 'top' }}>Required Action</td>
                        <td style={{ padding: '6px 0', lineHeight: 1.5 }}>{detail.kevRequiredAction}</td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </section>
            ) : null}

            <section className="panel">
              <div className="panel-header"><h3>Intelligence Sources</h3></div>
              {detail.sources.length === 0 ? (
                <div className="empty-state">No source data available.</div>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '8px 0' }}>
                  {detail.sources.map((src) => (
                    <SourceBadge key={src} name={src} />
                  ))}
                </div>
              )}
            </section>
          </div>

          {/* CPEs */}
          {detail.cpes.length > 0 ? (
            <section className="panel">
              <div className="panel-header">
                <h3>Affected Platforms (CPE)</h3>
                <span className="panel-caption">{detail.cpes.length} entries</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 320, overflowY: 'auto' }}>
                {detail.cpes.map((cpe) => (
                  <div key={cpe} className="mono" style={{ fontSize: 12, padding: '4px 8px', background: 'var(--panel-muted)', borderRadius: 4 }}>
                    {cpe}
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          {/* Per-source observations */}
          {detail.observations.length > 0 ? (
            <section className="panel">
              <div className="panel-header">
                <h3>Source Details</h3>
                <span className="panel-caption">{detail.observations.length} source{detail.observations.length !== 1 ? 's' : ''}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {detail.observations.map((obs) => (
                  <SourceObservationCard key={`${obs.sourceSystem}-${obs.sourceRecordId}`} obs={obs} />
                ))}
              </div>
            </section>
          ) : null}

          {/* References */}
          {detail.references.length > 0 ? (
            <section className="panel">
              <div className="panel-header">
                <h3>References</h3>
                <span className="panel-caption">{detail.references.length} link{detail.references.length !== 1 ? 's' : ''}</span>
              </div>
              <ul style={{ margin: 0, padding: '4px 0', listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
                {detail.references.map((url) => (
                  <li key={url} className="mono" style={{ fontSize: 12, wordBreak: 'break-all', padding: '3px 0', borderBottom: '1px solid var(--border)' }}>
                    {url}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
