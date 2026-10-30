import React from 'react';
import { Navigate } from 'react-router-dom';

type ErrorBoundaryState = { error: Error | null };

class OperationsSectionErrorBoundary extends React.Component<
  { children: React.ReactNode; viewKey: string },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode; viewKey: string }) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidUpdate(prevProps: { viewKey: string }) {
    if (prevProps.viewKey !== this.props.viewKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="panel">
          <div className="panel-header">
            <h3>Failed to render section</h3>
          </div>
          <div className="notice">{this.state.error.message}</div>
        </div>
      );
    }
    return this.props.children;
  }
}
import {
  OperationalApiReadPath,
  OperationalEndpointMetric,
  OperationalFreshnessDrift,
  OperationalIngestionEfficiency,
  OperationalIngestionSourceMetric,
  OperationalMetricDefinition,
  PerformanceResourceCeilingItem,
  PerformanceRouteScorecardItem,
  PerformanceScorecard,
  OperationalSectionResponse,
  OperationalSourceFreshness,
  SloStatus
} from '../features/operations/types';
import { MetricInfoIcon } from '../components/MetricInfoIcon';
import { PageFreshnessStatus, latestFreshnessValue } from '../components/PageFreshnessStatus';
import { StatCard } from '../components/StatCard';
import { MetricValue } from '../components/MetricValue';
import { AsyncSection } from '../components/AsyncSection';
import {
  type PipelinePayload,
  type PlatformHealthPayload,
  useOperationsViewQuery
} from '../features/operations/queries';

export type OperationsViewKey =
  | 'quality'
  | 'pipeline'
  | 'platform-health';

const OPERATIONS_NAV_ITEMS: Array<{ key: OperationsViewKey; label: string }> = [
  { key: 'pipeline', label: 'Pipeline' },
  { key: 'platform-health', label: 'Platform Health' }
];

const LEGACY_VIEW_ALIASES: Record<string, OperationsViewKey> = {
  dashboard: 'pipeline',
  overview: 'pipeline',
  quality: 'quality',
  pipeline: 'pipeline',
  'ingestion-efficiency': 'pipeline',
  ingestion: 'pipeline',
  'normalization-quality': 'pipeline',
  normalization: 'pipeline',
  'correlation-effectiveness': 'pipeline',
  correlation: 'pipeline',
  'noise-lifecycle': 'pipeline',
  noise: 'pipeline',
  lifecycle: 'pipeline',
  freshness: 'pipeline',
  'freshness-drift': 'pipeline',
  'platform-health': 'platform-health',
  'api-read-path': 'platform-health',
  readPath: 'platform-health',
  'metric-catalog': 'platform-health',
  catalog: 'platform-health',
  slo: 'platform-health',
  scorecard: 'platform-health',
  'performance-scorecard': 'platform-health'
};

function normalizeOperationsView(value: string | null | undefined): OperationsViewKey {
  if (!value) {
    return 'pipeline';
  }
  if (OPERATIONS_NAV_ITEMS.some((item) => item.key === value)) {
    return value as OperationsViewKey;
  }
  return LEGACY_VIEW_ALIASES[value] ?? 'pipeline';
}

type OperationalDashboardPageProps = {
  selectedView: OperationsViewKey;
  redirectSearch?: string;
};

const METRIC_HELP: Record<string, string> = {
  'Ingestion Success (24h)': 'Percent of SBOM ingestions and source sync runs that completed successfully in the last 24 hours.',
  'Sync Runs (24h)': 'Total connector and source synchronization runs processed in the last 24 hours.',
  'Projection Refresh P95 (ms)': 'P95 processing time for the background projection refresh worker.',
  'Normalization Coverage': 'Share of active components with enough normalized identity and version data for reliable matching.',
  'Noise Reduction': 'Percent of potential findings filtered out before they became analyst backlog.',
  'Open Critical': 'Count of currently critical findings that need attention.',
  'Open Findings': 'Count of findings that are currently unresolved.',
  'Stale Sources': 'Count of sources that are older than the configured freshness threshold.',
  'SBOM Ingestions (24h)': 'Total SBOM ingestion runs processed in the last 24 hours.',
  'SBOM / Hour': 'Average SBOM ingestion rate over the last 24 hours.',
  'SBOM Success Rate': 'Percent of SBOM ingestions that completed successfully.',
  'Sync Success Rate': 'Percent of source and connector sync runs that completed successfully.',
  'Queued/Running Sync Jobs': 'Current number of sync jobs that are queued or still running.',
  'Records Fetched': 'Total source records fetched during the last 24 hours.',
  'Records Inserted': 'Total new records inserted during the last 24 hours.',
  'Records Updated': 'Total existing records updated during the last 24 hours.',
  'Active Components': 'Count of active inventory components currently in scope for matching.',
  'Name Coverage': 'Share of active components with normalized product naming.',
  'Version Coverage': 'Share of active components with usable version information.',
  'Identity Coverage': 'Share of active components linked to a software identity.',
  'CPE Coverage (Active Components)': 'Share of active components that have at least one CPE identifier available for highest-confidence correlation.',
  'CPE Eligible Components': 'Active components with at least one CPE identifier and therefore eligible for direct CPE-based matching.',
  'CPE Ineligible Components': 'Active components with no CPE identifier and therefore limited to lower-confidence fallback matching methods.',
  'Open Findings via CPE': 'Open findings currently backed by CPE-based correlation methods.',
  'Direct vs Fallback': 'How many CPE-backed open findings used precise direct matching versus broader fallback matching.',
  'Direct Share': 'Percent of CPE-backed open findings using direct CPE matching rather than fallback methods.',
  'Fallback Share': 'Percent of CPE-backed open findings using fallback CPE matching methods.',
  'Average Open CPE Confidence': 'Average confidence score for currently open findings that were matched through CPE-based correlation.',
  'CPE Created (24h)': 'New findings created in the last 24 hours through CPE-based correlation.',
  'Other Methods Created (24h)': 'New findings created in the last 24 hours through non-CPE correlation methods.',
  'High Confidence Affected': 'Share of open affected findings backed by high-confidence matching evidence.',
  'Unknown Decision Rate': 'Share of open findings still stuck in an unknown or under-investigation state.',
  'Filtered Not Applicable': 'Total exposures filtered out as not applicable before or after finding creation.',
  'Never Opened': 'Filtered exposures that never became findings in the first place.',
  'Auto Resolved': 'Findings automatically resolved because the underlying evidence no longer supports them.',
  Deferred: 'Applicable matches deferred because the vendor is still under investigation.',
  'Filtered Rate': 'Share of potential findings that were filtered out as noise.',
  'Reopen Rate': 'Share of previously auto-resolved findings that later reopened.',
  'Summary Coverage': 'Percent of canonical CVEs represented in the summary read model.',
  'Summary Model': 'Whether the summary read model is ready to serve the UI.',
  'Cache Hit Ratio': 'Percent of eligible read-path requests served from cache.',
  'Failing SLOs': 'Count of tracked service-level objectives that are currently failing.',
  'Canonical CVEs': 'Count of canonical CVEs in the source-of-truth dataset.',
  'Summary CVEs': 'Count of CVEs currently materialized in the serving summary model.',
  'Noise Projection': 'Whether the noise-reduction projection is ready to serve dashboard reads.',
  'Projection Age': 'How long it has been since the noise-reduction projection was last recomputed.',
  'Projection Last Computed': 'Timestamp of the last completed noise-reduction projection refresh.',
  'Projection Refresh P95': 'P95 processing time for the background projection refresh worker.',
  'Projection Refresh Failures': 'Number of failed projection refresh attempts in the current metrics sample.',
  'Findings Projection Drift': 'Difference between canonical findings and the current findings workspace projection row count.',
  'Findings Projection Count': 'Rows currently materialized in the findings workspace projection.',
  'Findings Source Count': 'Canonical findings count used to validate the projection.',
  'Findings Projection Last Rebuild': 'Duration of the most recent tenant-scoped findings projection rebuild.',
  'Filter Cache State': 'Whether the read-path filter cache is warm and serving requests.',
  'Filter Cache Hit Ratio': 'Percent of filter-cache eligible requests served from cache.',
  'Stale Threshold (h)': 'Configured freshness threshold, in hours, before a source is treated as stale.',
  'Stale Source Count': 'Count of sources that are currently beyond the freshness threshold.',
  'Normalization Drift (7d)': 'Seven-day change in normalization coverage.',
  'CPE Fallback Drift (7d)': 'Seven-day change in the share of findings relying on fallback CPE matching.',
  'SLOs Defined': 'Total number of tracked service-level objectives.',
  'SLOs Passing': 'Number of tracked service-level objectives currently meeting target.',
  'SLOs Failing': 'Number of tracked service-level objectives currently breaching target.',
  'Enterprise Scale Profile': 'Target enterprise workload profile the scorecard is validating against.',
  'Route Budget Failures': 'Number of interactive routes currently breaching their target latency envelope.',
  'Route Budget No Data': 'Number of interactive routes without enough recent samples to score yet.',
  'Freshness Failures': 'Number of freshness and mixed-load guardrails currently outside target.',
  'Resource Ceiling Failures': 'Number of runtime resource ceilings currently exceeding target.',
  'Resource Ceiling No Data': 'Number of resource ceilings that could not be measured in the current runtime.',
  'Enterprise Scorecard': 'Overall pass/fail state for the current enterprise performance certification snapshot.'
};

function formatPercent(value: number): string {
  return `${(value ?? 0).toFixed(1)}%`;
}

function formatMetricValue(value: number, unit: string): string {
  if (unit === '%') {
    return formatPercent(value);
  }
  if (unit === 'ms') {
    return `${value.toFixed(1)} ms`;
  }
  if (unit === 'threads') {
    return `${Math.round(value).toLocaleString()} threads`;
  }
  return `${value.toLocaleString()}${unit ? ` ${unit}` : ''}`;
}

function statusClass(status: string): string {
  return status === 'PASS' ? 'slo-pass' : 'slo-fail';
}

function isCreatorAccessError(error: string): boolean {
  const normalized = error.toLowerCase();
  return normalized.includes('403') || normalized.includes('forbidden');
}

function formatGeneratedAt(generatedAt: string): string {
  return `Last updated ${new Date(generatedAt).toLocaleString()}`;
}

function SummaryMetricCard({ label, value }: { label: string; value: React.ReactNode }) {
  const description = METRIC_HELP[label];
  return (
    <div className="noise-summary-item">
      <div className="metric-label-row">
        <div className="noise-summary-label">{label}</div>
        {description ? <MetricInfoIcon label={label} description={description} /> : null}
      </div>
      <div className="noise-summary-value">{value}</div>
    </div>
  );
}

function IngestionSourceTable({ rows = [] }: { rows?: OperationalIngestionSourceMetric[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No ingestion runs observed in the last 24 hours.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Source</span>
        <span>Runs</span>
        <span>Success %</span>
        <span>Fetched</span>
        <span>Inserted</span>
        <span>Updated</span>
      </div>
      {rows.map((row) => (
        <div key={row.source} className="ops-table-row">
          <span>{row.source}</span>
          <span>{row.runs.toLocaleString()}</span>
          <span>{formatPercent(row.successRatePercent)}</span>
          <span>{row.fetched.toLocaleString()}</span>
          <span>{row.inserted.toLocaleString()}</span>
          <span>{row.updated.toLocaleString()}</span>
        </div>
      ))}
    </div>
  );
}

function FreshnessTable({ rows = [] }: { rows?: OperationalSourceFreshness[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No source freshness records yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Source</span>
        <span>Last Success</span>
        <span>Age (h)</span>
        <span>State</span>
      </div>
      {rows.map((row) => (
        <div key={row.source} className="ops-table-row">
          <span>{row.source}</span>
          <span>{row.lastSuccessfulAt ? new Date(row.lastSuccessfulAt).toLocaleString() : 'Never'}</span>
          <span>{row.ageHours >= 0 ? row.ageHours.toLocaleString() : '-'}</span>
          <span>{row.stale ? 'Stale' : 'Fresh'}</span>
        </div>
      ))}
    </div>
  );
}

function EndpointMetricsTable({ rows = [] }: { rows?: OperationalEndpointMetric[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No API endpoint metrics observed yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Endpoint</span>
        <span>Requests</span>
        <span>Errors</span>
        <span>Avg ms</span>
        <span>P95 ms</span>
        <span>P99 ms</span>
      </div>
      {rows.map((row) => (
        <div key={row.key} className="ops-table-row">
          <span>{row.label}</span>
          <span>{row.requestCount.toLocaleString()}</span>
          <span>{row.errorCount.toLocaleString()}</span>
          <span>{row.averageMs.toFixed(1)}</span>
          <span>{row.p95Ms.toFixed(1)}</span>
          <span>{row.p99Ms.toFixed(1)}</span>
        </div>
      ))}
    </div>
  );
}

function RouteScorecardTable({ rows = [] }: { rows?: PerformanceRouteScorecardItem[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No route scorecard entries available yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Route</span>
        <span>Category</span>
        <span>Requests</span>
        <span>P95 / Target</span>
        <span>P99 / Target</span>
        <span>Status</span>
        <span>Note</span>
      </div>
      {rows.map((row) => (
        <div key={row.key} className="ops-table-row ops-table-row-wide">
          <span>{row.label}</span>
          <span>{row.category}</span>
          <span>{row.requestCount.toLocaleString()}</span>
          <span>{row.currentP95Ms.toFixed(1)} / {row.targetP95Ms.toFixed(0)} ms</span>
          <span>{row.currentP99Ms.toFixed(1)} / {row.targetP99Ms.toFixed(0)} ms</span>
          <span className={statusClass(row.status)}>{row.status}</span>
          <span>{row.note}</span>
        </div>
      ))}
    </div>
  );
}

function ResourceCeilingsTable({ rows = [] }: { rows?: PerformanceResourceCeilingItem[] }) {
  if (rows.length === 0) {
    return <div className="panel-caption">No resource ceiling entries available yet.</div>;
  }
  return (
    <div className="ops-table">
      <div className="ops-table-header">
        <span>Resource</span>
        <span>Category</span>
        <span>Target</span>
        <span>Current</span>
        <span>Status</span>
        <span>Note</span>
      </div>
      {rows.map((row) => (
        <div key={row.key} className="ops-table-row ops-table-row-wide">
          <span>{row.label}</span>
          <span>{row.category}</span>
          <span>{formatMetricValue(row.targetValue, row.unit)}</span>
          <span>{formatMetricValue(row.currentValue, row.unit)}</span>
          <span className={statusClass(row.status)}>{row.status}</span>
          <span>{row.note}</span>
        </div>
      ))}
    </div>
  );
}

function renderIngestion(payload: OperationalSectionResponse<OperationalIngestionEfficiency>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Ingestion Efficiency</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Ingestion Efficiency</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Sync Runs (24h)" value={(data.syncRunsLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Sync Success Rate" value={formatPercent(data.syncSuccessRatePercent ?? 0)} />
          <SummaryMetricCard label="Queued/Running Sync Jobs" value={(data.queueBacklog ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Fetched" value={(data.recordsFetchedLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Inserted" value={(data.recordsInsertedLast24h ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Records Updated" value={(data.recordsUpdatedLast24h ?? 0).toLocaleString()} />
        </div>
        <IngestionSourceTable rows={data.sourceBreakdown} />
      </section>
    </div>
  );
}

function renderReadPath(payload: OperationalSectionResponse<OperationalApiReadPath>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>API and Read-Path Performance</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>API and Read-Path Performance</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Canonical CVEs" value={(data.canonicalCveCount ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Summary CVEs" value={(data.summaryCveCount ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Summary Coverage" value={formatPercent(data.summaryCoveragePercent)} />
          <SummaryMetricCard label="Summary Model" value={data.summaryReadModelReady ? 'Ready' : 'Rebuilding'} />
          <SummaryMetricCard label="Filter Cache State" value={data.filterCacheActive ? 'Warm' : 'Cold'} />
          <SummaryMetricCard label="Filter Cache Hit Ratio" value={formatPercent(data.filterCacheHitRatioPercent)} />
        </div>
        <p className="panel-caption">Recent requests on this application instance, up to {data.maximumSamplesPerMetric ?? 500} samples per metric. These readings are not fleet totals or a fixed time window.</p>
        <EndpointMetricsTable rows={data.endpointMetrics ?? []} />
      </section>
    </div>
  );
}

function renderFreshness(payload: OperationalSectionResponse<OperationalFreshnessDrift>) {
  const data = payload.data;
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Data Freshness and Drift</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Data Freshness and Drift</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Stale Threshold (h)" value={(data.staleThresholdHours ?? 0).toLocaleString()} />
          <SummaryMetricCard label="Stale Source Count" value={(data.staleSourceCount ?? 0).toLocaleString()} />
        </div>
        <FreshnessTable rows={data.sourceFreshness ?? []} />
      </section>
    </div>
  );
}

function renderCatalog(payload: OperationalSectionResponse<OperationalMetricDefinition[]>) {
  const data = Array.isArray(payload.data) ? payload.data : [];
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Metric Catalog</h3>
          <span className="panel-caption">{formatGeneratedAt(payload.generatedAt)}</span>
        </div>
        <div className="ops-table">
          <div className="ops-table-header">
            <span>Section</span>
            <span>Key</span>
            <span>Label</span>
            <span>Description</span>
          </div>
          {data.map((metric) => (
            <div key={metric.key} className="ops-table-row ops-table-row-wide">
              <span>{metric.section}</span>
              <span>{metric.key}</span>
              <span>{metric.label}</span>
              <span>{metric.description}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function renderSlo(data: SloStatus) {
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>SLO Status</h3></div><div className="panel-caption">No data available.</div></div>;
  }
  const slos = data.slos ?? [];
  return (
    <div className="page-grid">
      <div className="stats-grid">
        <StatCard title="SLOs Defined" value={slos.length} description={METRIC_HELP['SLOs Defined']} />
        <StatCard title="SLOs Passing" value={slos.filter((s) => s.compliant).length} description={METRIC_HELP['SLOs Passing']} />
        <StatCard title="SLOs Failing" value={slos.filter((s) => !s.compliant).length} tone={slos.some((s) => !s.compliant) ? 'critical' : undefined} description={METRIC_HELP['SLOs Failing']} />
      </div>

      <section className="panel">
        <div className="panel-header">
          <h3>SLO Status <span className={data.overallCompliant ? 'slo-pass' : 'slo-fail'}>{data.overallCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}</span></h3>
          <span className="panel-caption">Evaluated {new Date(data.evaluatedAt).toLocaleString()}</span>
        </div>
        <div className="ops-table">
          <div className="ops-table-header">
            <span>SLO</span>
            <span>Description</span>
            <span>Window</span>
            <span>Target</span>
            <span>Current</span>
            <span>Status</span>
          </div>
          {slos.map((slo) => (
            <div key={slo.name} className="ops-table-row ops-table-row-wide">
              <span>{slo.name}</span>
              <span>{slo.description}</span>
              <span>{slo.window}</span>
              <span>{slo.target}{slo.unit ? ` ${slo.unit}` : ''}</span>
              <span>{slo.current}{slo.unit ? ` ${slo.unit}` : ''}</span>
              <span className={slo.compliant ? 'slo-pass' : 'slo-fail'}>{slo.compliant ? 'PASS' : 'FAIL'}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function renderPerformanceScorecard(data: PerformanceScorecard) {
  if (!data) {
    return <div className="panel"><div className="panel-header"><h3>Enterprise Performance Scorecard</h3></div><div className="panel-caption">No data available.</div></div>;
  }

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <h3>Enterprise Performance Scorecard <span className={data.overallCompliant ? 'slo-pass' : 'slo-fail'}>{data.overallCompliant ? 'PASSING' : 'FAILING'}</span></h3>
          <span className="panel-caption">{formatGeneratedAt(data.generatedAt)}</span>
        </div>
        <div className="noise-summary-grid">
          <SummaryMetricCard label="Enterprise Scale Profile" value={data.scaleProfile} />
          <SummaryMetricCard label="Route Budget Failures" value={data.routeFailureCount.toLocaleString()} />
          <SummaryMetricCard label="Freshness Failures" value={data.freshnessFailureCount.toLocaleString()} />
          <SummaryMetricCard label="Resource Ceiling Failures" value={data.resourceFailureCount.toLocaleString()} />
          <SummaryMetricCard label="Route Budget No Data" value={data.routeNoDataCount.toLocaleString()} />
          <SummaryMetricCard label="Resource Ceiling No Data" value={data.resourceNoDataCount.toLocaleString()} />
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Interactive Route Budgets</h3>
          <span className="panel-caption">Target p95/p99 latency validation for tracked API routes.</span>
        </div>
        <RouteScorecardTable rows={data.routeItems ?? []} />
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Runtime Resource Ceilings</h3>
          <span className="panel-caption">Current runtime ceilings for heap, DB pool, and worker executors.</span>
        </div>
        <ResourceCeilingsTable rows={data.resourceItems ?? []} />
      </section>
    </div>
  );
}

// A section that returned no data is unknown, not zero: a missing freshness section must not read as "0 stale".
function UnavailableStatCard({ title, reason }: { title: string; reason: string }) {
  return (
    <div className="stat-card stat-neutral">
      <div className="stat-title-row"><div className="stat-title">{title}</div></div>
      <div className="stat-value"><MetricValue availability="unavailable" unavailableReason={reason} /></div>
      <div className="stat-caption">{reason}</div>
    </div>
  );
}

function renderPipeline(payload: PipelinePayload) {
  const ingestion = payload.ingestion.data;
  const freshness = payload.freshness.data;

  return (
    <div className="page-grid ui2-experience-family">
      {ingestion ? (
        <div className="stats-grid">
          <StatCard title="Sync Runs (24h)" value={ingestion.syncRunsLast24h ?? 0} description={METRIC_HELP['Sync Runs (24h)']} />
          <StatCard title="Sync Success Rate" value={Math.round(ingestion.syncSuccessRatePercent ?? 0)} caption="Percent" description={METRIC_HELP['Sync Success Rate']} />
          <StatCard title="Queued/Running Sync Jobs" value={ingestion.queueBacklog ?? 0} description={METRIC_HELP['Queued/Running Sync Jobs']} />
          {freshness ? (
            <StatCard title="Stale Sources" value={freshness.staleSourceCount ?? 0} tone={(freshness.staleSourceCount ?? 0) > 0 ? 'critical' : undefined} description={METRIC_HELP['Stale Sources']} />
          ) : (
            <UnavailableStatCard title="Stale Sources" reason="Freshness data unavailable" />
          )}
        </div>
      ) : null}

      {renderIngestion(payload.ingestion)}
      {renderFreshness(payload.freshness)}
    </div>
  );
}

function renderPlatformHealth(payload: PlatformHealthPayload) {
  const readPath = payload.readPath.data;
  const sloItems = payload.slo?.slos ?? [];
  const performanceScorecard = payload.performanceScorecard;

  return (
    <div className="page-grid ui2-experience-family">
      {readPath ? (
        <div className="stats-grid">
          <StatCard title="Summary Coverage" value={Math.round(readPath.summaryCoveragePercent)} caption="Percent" description={METRIC_HELP['Summary Coverage']} />
          <StatCard
            title="Summary Model"
            value={readPath.summaryReadModelReady ? 1 : 0}
            caption={readPath.summaryReadModelReady ? 'Ready' : 'Rebuilding'}
            tone={readPath.summaryReadModelReady ? undefined : 'critical'}
            description={METRIC_HELP['Summary Model']}
          />
          <StatCard title="Cache Hit Ratio" value={Math.round(readPath.filterCacheHitRatioPercent)} caption="Percent" description={METRIC_HELP['Cache Hit Ratio']} />
          {payload.slo ? (
            <StatCard title="Failing SLOs" value={sloItems.filter((item) => !item.compliant).length} tone={sloItems.some((item) => !item.compliant) ? 'critical' : undefined} description={METRIC_HELP['Failing SLOs']} />
          ) : (
            <UnavailableStatCard title="Failing SLOs" reason="SLO evaluation unavailable" />
          )}
          {performanceScorecard ? (
            <StatCard title="Resource Ceiling Failures" value={performanceScorecard.resourceFailureCount ?? 0} tone={(performanceScorecard.resourceFailureCount ?? 0) > 0 ? 'critical' : undefined} description={METRIC_HELP['Resource Ceiling Failures']} />
          ) : (
            <UnavailableStatCard title="Resource Ceiling Failures" reason="Scorecard unavailable" />
          )}
        </div>
      ) : null}

      {renderReadPath(payload.readPath)}
      {renderSlo(payload.slo)}
      {renderPerformanceScorecard(payload.performanceScorecard)}
      {renderCatalog(payload.catalog)}
    </div>
  );
}

export function OperationalDashboardPage({ selectedView, redirectSearch = '' }: OperationalDashboardPageProps) {
  const normalizedView = normalizeOperationsView(selectedView);
  const operationsViewQuery = useOperationsViewQuery(normalizedView);
  const payload = operationsViewQuery.data ?? null;
  const error = operationsViewQuery.error instanceof Error ? operationsViewQuery.error.message : null;
  const latestOperationalUpdate = React.useMemo(() => {
    if (!payload) {
      return operationsViewQuery.dataUpdatedAt;
    }
    if (normalizedView === 'pipeline') {
      const pipelinePayload = payload as PipelinePayload;
      return latestFreshnessValue([
        pipelinePayload.ingestion.generatedAt,
        pipelinePayload.freshness.generatedAt,
        operationsViewQuery.dataUpdatedAt,
      ]);
    }
    const platformHealthPayload = payload as PlatformHealthPayload;
    return latestFreshnessValue([
      platformHealthPayload.readPath.generatedAt,
      platformHealthPayload.catalog.generatedAt,
      platformHealthPayload.performanceScorecard.generatedAt,
      platformHealthPayload.slo?.evaluatedAt,
      operationsViewQuery.dataUpdatedAt,
    ]);
  }, [normalizedView, operationsViewQuery.dataUpdatedAt, payload]);
  const operationalDelayMessage = React.useMemo(() => {
    if (!payload) {
      return null;
    }
    if (normalizedView === 'pipeline') {
      const pipelinePayload = payload as PipelinePayload;
      const staleCount = pipelinePayload.freshness.data?.staleSourceCount ?? 0;
      return staleCount > 0
        ? 'Some shared sources are stale, so operational data may lag until those refreshes complete.'
        : null;
    }
    const platformHealthPayload = payload as PlatformHealthPayload;
    return (platformHealthPayload.performanceScorecard?.freshnessFailureCount ?? 0) > 0
      ? 'Some freshness guardrails are outside target, so health signals may update more slowly than expected.'
      : null;
  }, [normalizedView, payload]);
  const freshnessStrip = payload ? (
    <PageFreshnessStatus
      updatedAt={latestOperationalUpdate}
      isRefreshing={operationsViewQuery.isFetching}
      delayedMessage={operationalDelayMessage}
      refreshLabel={normalizedView === 'pipeline' ? 'Refreshing pipeline analytics…' : 'Refreshing platform health signals…'}
    />
  ) : null;

  if (normalizedView === 'quality') {
    const nextParams = new URLSearchParams(redirectSearch);
    const domain = (nextParams.get('domain') ?? '').trim().toUpperCase();
    const tab = domain === 'CORRELATION'
      ? 'quality-correlation'
      : domain === 'EOL'
        ? 'quality-eol'
        : domain === 'VEX'
          ? 'quality-vex'
          : 'quality-normalization';
    nextParams.delete('domain');
    nextParams.set('inventoryTabs', tab);
    nextParams.set('inventoryActiveTab', tab);
    const nextSearch = nextParams.toString();
    return <Navigate to={`/inventory${nextSearch ? `?${nextSearch}` : ''}`} replace />;
  }

  if (error) {
    if (payload) {
      let content: React.ReactNode;
      switch (normalizedView) {
        case 'pipeline':
          content = renderPipeline(payload as PipelinePayload);
          break;
        case 'platform-health':
          content = renderPlatformHealth(payload as PlatformHealthPayload);
          break;
        default:
          content = renderPipeline(payload as PipelinePayload);
      }

      return (
        <OperationsSectionErrorBoundary viewKey={normalizedView}>
          <div className="page-grid ui2-experience-family">
            <div className="panel">
              <AsyncSection
                state="ready"
                refreshError={`The latest refresh failed (${error}). Showing the last loaded operational data, which may be stale.`}
                onRetry={() => void operationsViewQuery.refetch()}
                retrying={operationsViewQuery.isFetching}
              />
            </div>
            {freshnessStrip}
            {content}
          </div>
        </OperationsSectionErrorBoundary>
      );
    }

    if (isCreatorAccessError(error)) {
      return (
        <section className="panel ui2-experience-family">
          <div className="panel-header">
            <h3>Operations Workspace Access Required</h3>
            <span className="panel-caption">Platform owner access is required</span>
          </div>
          <p>Sign in with an authorized platform owner account. If access was recently granted, sign in again.</p>
        </section>
      );
    }
    return (
      <div className="panel ui2-experience-family">
        <AsyncSection
          state="error"
          errorMessage={`Failed to load operational section: ${error}`}
          onRetry={() => void operationsViewQuery.refetch()}
          retrying={operationsViewQuery.isFetching}
        />
      </div>
    );
  }

  if (!payload) {
    return <div className="panel ui2-experience-family">Loading operational section...</div>;
  }

  let content: React.ReactNode;
  switch (normalizedView) {
    case 'pipeline':
      content = renderPipeline(payload as PipelinePayload);
      break;
    case 'platform-health':
      content = renderPlatformHealth(payload as PlatformHealthPayload);
      break;
    default:
      content = renderPipeline(payload as PipelinePayload);
  }

  return (
    <OperationsSectionErrorBoundary viewKey={normalizedView}>
      <div className="ops-context-bar ui2-experience-family">
        <span className="ops-context-label">Operations</span>
        <span className="ops-context-view">{normalizedView === 'pipeline' ? 'Pipeline Analytics' : 'Platform Health'}</span>
      </div>
      {freshnessStrip}
      {content}
    </OperationsSectionErrorBoundary>
  );
}
