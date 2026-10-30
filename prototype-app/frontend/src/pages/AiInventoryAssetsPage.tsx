import { shouldPollAiRuns } from '../features/ai-security/assessment';
import { useQuery } from '@tanstack/react-query';
import React from 'react';
import { Link, Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { AsyncSection } from '../components/AsyncSection';
import { PageFreshnessStatus } from '../components/PageFreshnessStatus';
import { Pager, ResultScope } from '../components/QueueControls';
import { AI_ARTIFACT_CATEGORIES, AI_AGENT_VERSION_KINDS, legacyAgentRosterRedirect, combinedNativeKindFilterValue, stripProviderPrefix } from '../features/ai-security/categories';
import { ProviderLogo } from '../features/ai-security/ProviderLogo';
import { FindingSeverityChips } from '../features/findings/components/FindingSeverityChips';
import { InventoryShell } from '../features/inventory/InventoryShell';
import { pathForInventoryAiAsset } from '../app/routes';
import { RUN_QUEUE_REFRESH_INTERVAL_MS } from '../lib/polling';
import type { AiProvider } from '../features/ai-security/types';

const ALL_KIND = 'ALL';
const CATEGORIZED_NATIVE_KINDS = new Set(AI_ARTIFACT_CATEGORIES.flatMap((category) => category.nativeKinds));
const DEDICATED_NATIVE_KINDS = combinedNativeKindFilterValue([...CATEGORIZED_NATIVE_KINDS, ...AI_AGENT_VERSION_KINDS]);
const DEDICATED_ARTIFACT_TYPES = 'DATA_STORE,MCP_SERVER';



export function AiInventoryAssetsPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const [nativeKind, setNativeKind] = React.useState<string>(searchParams.get('nativeKind') ?? ALL_KIND);
  const [severity, setSeverity] = React.useState<string | undefined>(searchParams.get('severity') ?? undefined);
  const [provider, setProvider] = React.useState<'' | AiProvider>(
    ['AWS', 'AZURE', 'MICROSOFT_COPILOT'].includes(searchParams.get('provider') ?? '')
      ? (searchParams.get('provider') as AiProvider)
      : '',
  );
  const [page, setPage] = React.useState(0);
  const pageSize = 50;
  const isAgentsView = location.pathname === '/inventory/ai/agents';
  const [search, setSearch] = React.useState('');
  const subscription = searchParams.get('subscription') ?? undefined;
  const redirect = legacyAgentRosterRedirect(location.search);
  const isOthersView = searchParams.get('view') === 'others';

  React.useEffect(() => {
    setNativeKind(searchParams.get('nativeKind') ?? ALL_KIND);
    setSeverity(searchParams.get('severity') ?? undefined);
    setProvider(['AWS', 'AZURE', 'MICROSOFT_COPILOT'].includes(searchParams.get('provider') ?? '')
      ? searchParams.get('provider') as AiProvider
      : '');
    setPage(0);
  }, [searchParams]);

  const runsQuery = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: () => api.listAiSecurityRuns(),
    refetchInterval: (query) => shouldPollAiRuns(query.state.data as Array<{ status: string; assessmentStatus?: 'PENDING' | 'RUNNING' | 'COMPLETE' | 'PARTIAL' | 'FAILED' }> | undefined)
      ? RUN_QUEUE_REFRESH_INTERVAL_MS
      : false,
  });
  const shouldPoll = shouldPollAiRuns(runsQuery.data);
  const artifactsQuery = useQuery({
    queryKey: ['ai-artifact-summaries', isAgentsView, isOthersView, nativeKind, provider, subscription, severity, search, page],
    queryFn: () => isAgentsView
      ? api.listAiArtifactSummaries(undefined, page, pageSize, provider || undefined, subscription, undefined,
        undefined, undefined, undefined, 'AGENTS', search || undefined)
      : isOthersView
      ? api.listAiArtifactSummaries(
        undefined,
        page,
        pageSize,
        provider || undefined,
        undefined,
        nativeKind === ALL_KIND ? undefined : nativeKind,
        severity,
        DEDICATED_NATIVE_KINDS,
        DEDICATED_ARTIFACT_TYPES,
        'OTHERS',
      )
      : api.listAiArtifactSummaries(
        undefined,
        page,
        pageSize,
        provider || undefined,
        undefined,
        nativeKind === ALL_KIND ? undefined : nativeKind,
        severity,
      ),
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
    refetchInterval: shouldPoll ? RUN_QUEUE_REFRESH_INTERVAL_MS : false,
  });

  const items = artifactsQuery.data?.items ?? [];
  const total = artifactsQuery.data?.total ?? 0;
  const summary = summaryQuery.data;
  const totalArtifacts = Object.values(summary?.artifactCounts ?? {}).reduce((total, count) => total + count, 0);
  const nativeKindCounts = summary?.nativeKindCounts ?? {};
  const categoryOptions = AI_ARTIFACT_CATEGORIES.map((category) => ({
    key: combinedNativeKindFilterValue(category.nativeKinds),
    label: category.label,
    count: category.nativeKinds.reduce((total, kind) => total + (nativeKindCounts[kind] ?? 0), 0),
  }));
  const remainingKindOptions = Object.entries(nativeKindCounts)
    .filter(([kind]) => !CATEGORIZED_NATIVE_KINDS.has(kind) && !AI_AGENT_VERSION_KINDS.includes(kind))
    .sort(([, a], [, b]) => b - a)
    .map(([kind, count]) => ({ key: kind, label: stripProviderPrefix(kind), count }));

  // An empty page under a user-chosen filter is a filter result, not an empty AI estate.
  const hasUserFilters = Boolean(provider || severity || search || subscription || (nativeKind !== ALL_KIND && !isAgentsView && !isOthersView));
  const clearFilters = () => {
    setProvider('');
    setSeverity(undefined);
    setSearch('');
    setNativeKind(ALL_KIND);
    setPage(0);
  };
  const listState = artifactsQuery.isPending ? 'pending'
    : artifactsQuery.isError && !artifactsQuery.data ? 'error'
      : items.length === 0 && hasUserFilters ? 'filtered-empty'
        : 'ready';

  if (redirect) return <Navigate to={redirect} replace />;

  return (
    <InventoryShell
      eyebrow="AWS and Azure AI estate"
      title={isAgentsView ? 'Agents' : isOthersView ? 'Other AI Artifacts' : 'AI Asset Inventory'}
      description={isAgentsView ? 'All discovered logical agents, regardless of deployment status.' : isOthersView
        ? 'Discovered AI resources whose native type does not have a dedicated AI Inventory sidebar view.'
        : 'Every discovered AI artifact across AWS and Azure, filterable by kind, provider, and severity.'}
      legacyClassName="ai-security-page"
    >
      <PageFreshnessStatus updatedAt={summary?.lastCompleteSnapshotAt} />

      <div className="inventory-fpl-toolbar">
        {isAgentsView && <label className="findings-filter-chip">Search <input aria-label="Search agents" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></label>}
        {!isOthersView && !isAgentsView && (
          <label className="findings-filter-chip">
            <span className="panel-caption">Artifact kind</span>
            <select value={nativeKind} onChange={(event) => { setNativeKind(event.target.value); setPage(0); }} aria-label="Artifact kind">
              <option value={ALL_KIND}>All AI Assets ({totalArtifacts.toLocaleString()})</option>
              {categoryOptions.map((option) => (
                <option key={option.key} value={option.key}>{option.label} ({option.count.toLocaleString()})</option>
              ))}
              {remainingKindOptions.map((option) => (
                <option key={option.key} value={option.key}>{option.label} ({option.count.toLocaleString()})</option>
              ))}
            </select>
          </label>
        )}
        <label className="findings-filter-chip">
          <span className="panel-caption">Provider</span>
          <select value={provider} onChange={(event) => { setProvider(event.target.value as '' | AiProvider); setPage(0); }} aria-label="Cloud provider">
            <option value="">All providers</option>
            <option value="AWS">AWS</option>
            <option value="AZURE">Azure</option>
            <option value="MICROSOFT_COPILOT">Microsoft Copilot</option>
          </select>
        </label>
        {severity ? (
          <div className="fpl-active-chips">
            <span className="fpl-chip">
              Severity: {severity}
              <button type="button" onClick={() => { setSeverity(undefined); setPage(0); }} aria-label="Clear severity filter">×</button>
            </span>
          </div>
        ) : null}
        <button
          type="button"
          className="btn btn-secondary inventory-refresh-btn"
          onClick={() => {
            void artifactsQuery.refetch();
            void summaryQuery.refetch();
          }}
        >
          Refresh
        </button>
      </div>

      {listState !== 'ready' ? (
        <section className="panel">
          <AsyncSection
            state={listState}
            loadingLabel="Loading AI inventory…"
            errorMessage="AI inventory could not be loaded."
            onRetry={() => void artifactsQuery.refetch()}
            retryLabel="Retry AI inventory"
            retrying={artifactsQuery.isFetching}
            filteredEmptyMessage="No AI assets match the current filters."
            onClearFilters={clearFilters}
          />
        </section>
      ) : items.length === 0 ? (
        <section className="ai-security-empty">
          <div className="ai-security-empty-mark">AI</div>
          <h3>No AI assets discovered</h3>
          <p>Connect an AWS or Azure account and run AI discovery. Empty inventory never hides this workspace.</p>
          <button className="btn btn-primary" type="button" onClick={() => navigate('/connect/connectors')}>
            Configure AI connector
          </button>
        </section>
      ) : (
        <section className="panel ai-security-table-panel">
          <div className="panel-header">
            <div>
              <h3>AI asset inventory</h3>
              <ResultScope offset={page * pageSize} count={items.length} total={total} noun="asset" filtered={hasUserFilters} />
            </div>
          </div>
          {artifactsQuery.isError && (
            <div className="notice warning" role="status">AI inventory could not be refreshed; showing the last loaded page.</div>
          )}
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr><th>Name</th>{isAgentsView && <th>Deployment</th>}<th>Native type</th><th>Provider</th><th>Account / Region</th><th>Findings</th><th>Policies (Failed/Total)</th></tr>
              </thead>
              <tbody>
                {items.map((artifact) => {
                  const otherFindings = Math.max(0, artifact.totalFindings - artifact.criticalFindings - artifact.highFindings);
                  return (
                    <tr key={artifact.id}>
                      <td>
                        <Link to={pathForInventoryAiAsset(artifact.id, `${location.pathname}${location.search}`)}>
                          <strong>{artifact.name}</strong>
                        </Link>
                      </td>
                      {isAgentsView && <td title={artifact.deployment?.reasonCode ?? 'NO_EVIDENCE'}>{artifact.deployment?.status === 'SERVED' ? 'Served' : artifact.deployment?.status === 'NOT_CURRENTLY_SERVED' ? 'Not currently served' : 'Deployment unverified'}</td>}
                      <td>{stripProviderPrefix(artifact.nativeKind)}</td>
                      <td><ProviderLogo provider={artifact.provider} /></td>
                      <td>{artifact.accountId}<small>{artifact.region}</small></td>
                      <td>
                        <FindingSeverityChips critical={artifact.criticalFindings} high={artifact.highFindings} other={otherFindings} />
                      </td>
                      <td><strong>{artifact.policiesFailed.toLocaleString()}/{artifact.policiesTotal.toLocaleString()}</strong></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            totalPages={Math.max(1, Math.ceil(total / pageSize))}
            onPrevious={() => setPage((current) => current - 1)}
            onNext={() => setPage((current) => current + 1)}
            disabled={artifactsQuery.isFetching}
            label="AI asset pages"
          />
        </section>
      )}
    </InventoryShell>
  );
}
