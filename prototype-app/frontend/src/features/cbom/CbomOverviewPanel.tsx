import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { MetricValue } from '../../components/MetricValue';
import { StatCard } from '../../components/StatCard';
import { formatDate, percent, titleCase } from './labels';
import type { CbomTrendPoint } from './types';

const TREND_DAYS = 90;

function Ratio({ value, reason }: { value: number | null; reason: string }) {
  return <MetricValue availability={value == null ? 'unavailable' : 'available'} value={value == null ? null : value * 100}
    format={(n) => `${Math.round(n)}%`} unavailableReason={reason} />;
}

/** Executive cryptographic posture: risk, assurance, remediation, rotation outlook, PQC and trend. */
export function CbomOverviewPanel() {
  const overviewQuery = useQuery({ queryKey: ['cbom-overview'], queryFn: () => api.getCbomOverview() });
  const trendsQuery = useQuery({ queryKey: ['cbom-trends', TREND_DAYS], queryFn: () => api.getCbomTrends(TREND_DAYS) });
  const overview = overviewQuery.data;
  const totalComponents = overview ? Object.values(overview.componentsByType).reduce((sum, value) => sum + value, 0) : 0;
  const state = overviewQuery.isPending ? 'pending'
    : overviewQuery.isError && !overview ? 'error'
      : totalComponents === 0 && (overview?.assurance.activeArtifacts ?? 0) === 0 ? 'empty'
        : 'ready';

  return (
    <div className="cbom-overview">
      <AsyncSection
        state={state}
        loadingLabel="Loading cryptographic posture…"
        errorMessage="Cryptographic posture could not be loaded."
        onRetry={() => void overviewQuery.refetch()}
        retryLabel="Retry cryptographic posture"
        retrying={overviewQuery.isFetching}
        emptyMessage="No active CBOM has been ingested yet. Cryptographic posture appears after the first CBOM is assessed."
      >
        {overview && (
          <>
            <div className="panel-caption">As of {formatDate(overview.observedAt)}</div>
            <div className="cbom-stat-grid">
              <StatCard title="Open critical" value={overview.risk.openCritical} tone={overview.risk.openCritical > 0 ? 'critical' : 'neutral'} caption="Supported CBOM findings" />
              <StatCard title="Open high" value={overview.risk.openHigh} tone={overview.risk.openHigh > 0 ? 'warn' : 'neutral'} caption="Supported CBOM findings" />
              <StatCard title="Production assets at risk" value={overview.risk.productionAssetsWithCriticalOrHigh}
                tone={overview.risk.productionAssetsWithCriticalOrHigh > 0 ? 'critical' : 'neutral'} caption={`${overview.risk.assetsWithCriticalOrHigh} assets in any environment`} />
              <StatCard title="Quantum-vulnerable" value={overview.pqc.quantumVulnerableComponents} caption={`${overview.pqc.quantumVulnerableFindings} open PQC findings`} />
              <StatCard title="Overdue crypto findings" value={overview.remediation.overdue} tone={overview.remediation.overdue > 0 ? 'warn' : 'neutral'} caption={`${overview.remediation.open} open in the Findings queue`} />
              <StatCard title="Suppressed" value={overview.remediation.suppressed} caption={`${overview.remediation.suppressionsExpiringIn30Days} expire within 30 days`} />
            </div>

            <div className="cbom-overview-grid">
              <section className="panel" aria-labelledby="cbom-assurance-heading">
                <h3 id="cbom-assurance-heading">Assurance and completeness</h3>
                <dl className="cbom-definition-list">
                  <dt>Assessment coverage</dt>
                  <dd><Ratio value={overview.assurance.assessmentCoverage} reason="No active CBOM artifacts" />
                    {' '}({overview.assurance.assessedArtifacts} of {overview.assurance.activeArtifacts} CBOMs)</dd>
                  <dt>Average confidence</dt><dd><Ratio value={overview.assurance.averageConfidence} reason="No successful assessment yet" /></dd>
                  <dt>Average completeness</dt><dd><Ratio value={overview.assurance.averageCompleteness} reason="No successful assessment yet" /></dd>
                  <dt>Claims by assurance</dt>
                  <dd>{Object.keys(overview.assurance.claimsByAssurance).length === 0 ? '—'
                    : Object.entries(overview.assurance.claimsByAssurance).map(([level, count]) => `${titleCase(level)} ${count}`).join(' · ')}</dd>
                </dl>
              </section>
              <section className="panel" aria-labelledby="cbom-remediation-heading">
                <h3 id="cbom-remediation-heading">Remediation SLA</h3>
                <dl className="cbom-definition-list">
                  <dt>Within SLA</dt><dd><Ratio value={overview.remediation.slaCompliance} reason="No open crypto findings" /></dd>
                  <dt>Resolved in the last 30 days</dt><dd>{overview.remediation.resolvedLast30Days}</dd>
                </dl>
              </section>
              <section className="panel" aria-labelledby="cbom-rotation-heading">
                <h3 id="cbom-rotation-heading">Certificate and key rotation outlook</h3>
                <dl className="cbom-definition-list">
                  <dt>Expired</dt><dd>{overview.rotation.expired}</dd>
                  <dt>Within 30 days</dt><dd>{overview.rotation.expiringIn30Days}</dd>
                  <dt>Within 60 days</dt><dd>{overview.rotation.expiringIn60Days}</dd>
                  <dt>Within 90 days</dt><dd>{overview.rotation.expiringIn90Days}</dd>
                </dl>
              </section>
            </div>

            {overview.productionAssetsAtRisk.length > 0 && (
              <section className="panel" aria-labelledby="cbom-production-heading">
                <h3 id="cbom-production-heading">Production assets with critical or high crypto findings</h3>
                <div className="table-scroll">
                  <table className="data-table">
                    <thead><tr><th>Asset</th><th>Environment</th><th>Critical</th><th>High</th></tr></thead>
                    <tbody>
                      {overview.productionAssetsAtRisk.map((asset) => (
                        <tr key={asset.assetId}><td>{asset.name}</td><td>{asset.environment ?? '—'}</td><td>{asset.critical}</td><td>{asset.high}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            <TrendSection points={trendsQuery.data?.points} pending={trendsQuery.isPending} failed={trendsQuery.isError}
              onRetry={() => void trendsQuery.refetch()} />
            <p className="panel-caption">{overview.cryptoExposureNote}</p>
          </>
        )}
      </AsyncSection>
    </div>
  );
}

function TrendSection({ points, pending, failed, onRetry }: { points?: CbomTrendPoint[]; pending: boolean; failed: boolean; onRetry: () => void }) {
  const rows = points ?? [];
  const state = pending ? 'pending' : failed ? 'error' : rows.length <= 1 ? 'empty' : 'ready';
  return (
    <section className="panel" aria-labelledby="cbom-trend-heading">
      <h3 id="cbom-trend-heading">{TREND_DAYS}-day trend</h3>
      <AsyncSection state={state} loadingLabel="Loading posture trend…" errorMessage="The posture trend could not be loaded."
        onRetry={onRetry} retryLabel="Retry posture trend"
        emptyMessage="Daily posture snapshots start after the first nightly run; only today's live value is available.">
        <div className="table-scroll">
          <table className="data-table">
            <caption className="panel-caption">Daily snapshots, newest last; the final row is today's live value.</caption>
            <thead>
              <tr><th>Date</th><th>Open critical</th><th>Open high</th><th>Quantum-vulnerable</th><th>Confidence</th><th>Completeness</th><th>Overdue</th></tr>
            </thead>
            <tbody>
              {rows.slice(-14).map((point) => (
                <tr key={`${point.date}-${point.live}`}>
                  <td>{point.date}{point.live ? ' (live)' : ''}</td><td>{point.openCritical}</td><td>{point.openHigh}</td>
                  <td>{point.quantumVulnerable}</td><td>{percent(point.averageConfidence)}</td><td>{percent(point.averageCompleteness)}</td>
                  <td>{point.overdueCryptoFindings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AsyncSection>
    </section>
  );
}
