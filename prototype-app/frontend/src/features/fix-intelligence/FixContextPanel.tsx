import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { formatTimestamp } from '../../lib/time';
import { fixIntelligenceApi } from './api';
import { fixTypeLabel, providerLabel, severityClass, titleCase } from './format';

type Props = {
  cveId?: string | null;
  assetId?: string | null;
};

/**
 * Patches, workarounds and controls that apply to a CVE and/or an asset, with the asset's
 * deployment state. Context only: nothing here changes a finding's status.
 */
export function FixContextPanel({ cveId, assetId }: Props): React.ReactElement | null {
  const enabled = Boolean(cveId || assetId);
  const contextQuery = useQuery({
    queryKey: ['fix-intelligence', 'context', cveId ?? null, assetId ?? null],
    queryFn: () => fixIntelligenceApi.context({ cveId, assetId }),
    enabled
  });
  if (!enabled) return null;

  const fixes = contextQuery.data?.fixes ?? [];
  return (
    <section className="panel fi-context ui2-fix-family" aria-label="Remediation options">
      <h2>Remediation options</h2>
      {contextQuery.isLoading && <p className="muted">Loading fixes…</p>}
      {contextQuery.isError && <p className="muted">Fix Intelligence is unavailable right now.</p>}
      {contextQuery.isSuccess && fixes.length === 0 && (
        <p className="muted">No patch, workaround or compensating control is recorded for this {assetId && !cveId ? 'asset' : 'CVE'}.</p>
      )}
      {fixes.length > 0 && (
        <ul>
          {fixes.map((fix) => (
            <li key={fix.fixId}>
              <span className={severityClass(fix.severity)}>{fix.severity ? titleCase(fix.severity) : 'Unrated'}</span>
              <Link to={`/fix-intelligence/details/${encodeURIComponent(fix.fixId)}`}>{fix.title}</Link>
              <span className="muted">{fixTypeLabel(fix.fixType)} · {fix.displayId}</span>
              {fix.status !== 'ACTIVE' && <span className="fi-status-tag">{titleCase(fix.status)}</span>}
              {fix.assetStatus && (
                <span className="status-pill" title={fix.assetProvider ? `Reported by ${providerLabel(fix.assetProvider)}` : undefined}>
                  {titleCase(fix.assetStatus)}
                  {fix.assetStatus === 'SCHEDULED' && fix.scheduledAt && ` · ${formatTimestamp(fix.scheduledAt)}`}
                  {fix.assetStatus === 'INSTALLED' && fix.installedAt && ` · ${formatTimestamp(fix.installedAt)}`}
                </span>
              )}
              {!assetId && fix.coveragePercent != null && <span className="muted">{fix.coveragePercent}% deployed</span>}
            </li>
          ))}
        </ul>
      )}
      <p className="panel-caption">Fix status is shown for context and does not change finding status.</p>
    </section>
  );
}
