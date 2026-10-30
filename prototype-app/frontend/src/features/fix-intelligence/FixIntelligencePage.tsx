import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
import { usePageHeader } from '../../app/pageHeaderState';
import { AsyncSection, type AsyncSectionState } from '../../components/AsyncSection';
import { DataTable, type DataTableColumn, type DataTableRow } from '../../components/DataTable';
import { MetricValue, type MetricAvailability } from '../../components/MetricValue';
import { ActiveFilterChips, Pager, ResultScope, type ActiveFilter } from '../../components/QueueControls';
import { useActor } from '../auth/context';
import { canManageFixControls } from '../auth/roles';
import { useDebouncedValue } from '../../hooks/useDebouncedValue';
import { fixIntelligenceApi } from './api';
import { FixControlForm } from './FixControlForm';
import {
  ECOSYSTEM_ORDER,
  SEVERITY_ORDER,
  coverageLabel,
  ecosystemLabel,
  fixTypeLabel,
  providerLabel,
  safePercent,
  severityClass,
  titleCase,
  viewLabel
} from './format';
import type { FixListItem, FixSummary, FixView } from './types';

const PAGE_SIZE = 50;
const VIEW_DESCRIPTIONS: Record<FixView, string> = {
  all: 'Patches, workarounds and compensating controls across your environment.',
  patches: 'Track imported patches, deployment coverage and the ecosystems they protect.',
  workarounds: 'Manage temporary mitigations and configuration changes while permanent fixes are prepared.',
  'compensating-controls': 'Manage additional safeguards and review the residual risk they address.'
};
const EMPTY_MESSAGES: Record<FixView, string> = {
  all: 'No fixes yet. Connect a patch source or create a workaround to get started.',
  patches: 'No patches yet. Connect a supported patch source under Connectors.',
  workarounds: 'No workarounds yet. Create a workaround to document a temporary mitigation.',
  'compensating-controls': 'No compensating controls yet. Create a control to document an additional safeguard.'
};

const detailPath = (fix: FixListItem) => `/fix-intelligence/details/${encodeURIComponent(fix.id)}`;

function fixColumns(view: FixView): DataTableColumn[] {
  return [
    { id: 'id', label: 'ID', header: 'ID', initialSize: 150, minWidth: 120, priority: 'essential' },
    { id: 'title', label: 'Title', header: 'Title', initialSize: 300, minWidth: 220, priority: 'essential' },
    { id: 'severity', label: 'Severity', header: 'Severity', initialSize: 110, minWidth: 100, priority: 'essential' },
    ...(view === 'all' ? [{ id: 'type', label: 'Type', header: 'Type', initialSize: 160, minWidth: 120, priority: 'optional' as const }] : []),
    { id: 'ecosystem', label: 'Ecosystem', header: 'Ecosystem', initialSize: 130, minWidth: 110, priority: 'optional' },
    { id: 'source', label: 'Source', header: 'Source', initialSize: 130, minWidth: 100, priority: 'optional' },
    { id: 'coverage', label: 'Coverage', header: 'Coverage', initialSize: 130, minWidth: 110, priority: 'optional' }
  ];
}

function fixRows(items: FixListItem[], view: FixView): DataTableRow[] {
  return items.map((fix) => ({
    id: fix.id,
    cells: {
      id: { content: <Link to={detailPath(fix)}>{fix.displayId}</Link>, props: { className: 'mono' } },
      title: { content: <>{fix.title}{fix.status !== 'ACTIVE' && <span className="fi-status-tag">{titleCase(fix.status)}</span>}</> },
      severity: { content: <span className={severityClass(fix.severity)}>{fix.severity ? titleCase(fix.severity) : 'Unrated'}</span> },
      ...(view === 'all' ? { type: { content: fixTypeLabel(fix.fixType) } } : {}),
      ecosystem: { content: ecosystemLabel(fix.ecosystem) },
      source: { content: fix.sources.length ? fix.sources.map(providerLabel).join(', ') : '—' },
      coverage: { content: coverageLabel(fix.remediatedAssets, fix.applicableAssets, fix.coveragePercent) }
    }
  }));
}

export function FixIntelligencePage({ view }: { view: FixView }): React.ReactElement {
  const navigate = useNavigate();
  const actor = useActor();
  const [search, setSearch] = React.useState('');
  const [severity, setSeverity] = React.useState('');
  const [ecosystem, setEcosystem] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [creating, setCreating] = React.useState(false);
  const debouncedSearch = useDebouncedValue(search, 300);

  React.useEffect(() => {
    setPage(0);
  }, [view, debouncedSearch, severity, ecosystem]);

  React.useEffect(() => { setCreating(false); }, [view]);

  const summaryQuery = useQuery({
    queryKey: ['fix-intelligence', 'summary', view],
    queryFn: () => fixIntelligenceApi.summary(view)
  });
  const listQuery = useQuery({
    queryKey: ['fix-intelligence', 'list', view, debouncedSearch, severity, ecosystem, page],
    queryFn: () => fixIntelligenceApi.list({
      view, search: debouncedSearch, severity: severity || undefined, ecosystem: ecosystem || undefined, page, size: PAGE_SIZE
    })
  });

  const canCreate = view !== 'patches' && canManageFixControls(actor);
  const summary = summaryQuery.data;
  const list = listQuery.data;
  const hasFilters = Boolean(search || severity || ecosystem);
  // The results reflect the debounced search, so the filtered/unfiltered empty state does too.
  const resultsFiltered = Boolean(debouncedSearch || severity || ecosystem);
  const clearFilters = () => { setSearch(''); setSeverity(''); setEcosystem(''); setPage(0); };

  // The shell renders the only route H1; the selected view names it.
  usePageHeader({ title: viewLabel(view) });

  const summaryAvailability: MetricAvailability = summary ? 'available' : summaryQuery.isError ? 'unavailable' : 'pending';
  const listState: AsyncSectionState = list
    ? list.items.length > 0 ? 'ready' : resultsFiltered ? 'filtered-empty' : 'empty'
    : listQuery.isError ? 'error' : 'pending';
  const activeFilters: ActiveFilter[] = [
    ...(search ? [{ key: 'search', label: 'Search', value: search, onRemove: () => setSearch('') }] : []),
    ...(severity ? [{ key: 'severity', label: 'Severity', value: titleCase(severity), onRemove: () => setSeverity('') }] : []),
    ...(ecosystem ? [{ key: 'ecosystem', label: 'Ecosystem', value: ecosystemLabel(ecosystem), onRemove: () => setEcosystem('') }] : [])
  ];

  return (
    <div className="page-grid fi-page ui2-fix-family">
      <header className="fi-header">
        <div>
          <span className="fi-eyebrow">Fix Intelligence</span>
          <p className="muted">
            {VIEW_DESCRIPTIONS[view]}
          </p>
        </div>
        {canCreate && (
          <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
            {view === 'compensating-controls' ? 'New compensating control' : 'New workaround'}
          </button>
        )}
      </header>
      <p className="fi-context-note">Fixes provide remediation context and do not change finding status.</p>

      {creating && (
        <FixControlForm
          defaultType={view === 'compensating-controls' ? 'COMPENSATING_CONTROL' : 'WORKAROUND'}
          onCancel={() => setCreating(false)}
          onSaved={(fix) => {
            setCreating(false);
            navigate(`/fix-intelligence/details/${encodeURIComponent(fix.id)}`);
          }}
        />
      )}

      {summaryQuery.isError && (
        <AsyncSection
          state={summary ? 'ready' : 'error'}
          errorMessage="Fix summary could not be loaded. Try again to refresh the metrics."
          refreshError="Fix summary could not be refreshed. Showing the last loaded metrics."
          onRetry={() => void summaryQuery.refetch()}
          retryLabel="Retry summary"
          retrying={summaryQuery.isFetching}
        />
      )}
      <KpiCards summary={summary} availability={summaryAvailability} />

      {view === 'patches' && summary && (
        <div className="fi-ecosystem-strip" aria-label="Patches by ecosystem">
          {ECOSYSTEM_ORDER.map((key) => {
            const bucket = summary.ecosystems.find((item) => item.key === key);
            return (
              <button
                key={key}
                type="button"
                className={ecosystem === key ? 'panel fi-ecosystem active' : 'panel fi-ecosystem'}
                onClick={() => setEcosystem(ecosystem === key ? '' : key)}
                aria-pressed={ecosystem === key}
              >
                <span className="fi-ecosystem-name">{ecosystemLabel(key)}</span>
                <span className="fi-ecosystem-count">{bucket?.count ?? 0}</span>
              </button>
            );
          })}
        </div>
      )}

      <div className="fi-filters" role="search" aria-label="Filter fixes">
        <label className="fi-field fi-search">Search
          <input
            className="input"
            type="search"
            placeholder="Search by title, KB, or ID"
            aria-label="Search fixes"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <label className="fi-field">Severity
          <select className="input" aria-label="Severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All severities</option>
            {SEVERITY_ORDER.map((key) => <option key={key} value={key}>{titleCase(key)}</option>)}
          </select>
        </label>
        <label className="fi-field">Ecosystem
          <select className="input" aria-label="Ecosystem" value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
            <option value="">All ecosystems</option>
            {ECOSYSTEM_ORDER.map((key) => <option key={key} value={key}>{ecosystemLabel(key)}</option>)}
          </select>
        </label>
      </div>
      <ActiveFilterChips filters={activeFilters} onClearAll={hasFilters ? clearFilters : undefined} label="Active fix filters" />
      <div className="fi-body">
        <section className="panel fi-table-panel" aria-label="Fixes">
          <div className="fi-section-heading">
            <h2>Fix catalog</h2>
            {list && (
              <ResultScope offset={list.page * list.size} count={list.items.length} total={list.totalItems} noun="fix" pluralNoun="fixes" filtered={resultsFiltered} />
            )}
          </div>
          <AsyncSection
            state={listState}
            loadingLabel="Loading fixes…"
            emptyMessage={EMPTY_MESSAGES[view]}
            filteredEmptyMessage="No fixes match these filters."
            errorMessage="Fixes could not be loaded."
            refreshError={listQuery.isError && list ? 'Fixes could not be refreshed. Showing the last loaded page.' : undefined}
            onRetry={() => void listQuery.refetch()}
            retryLabel="Retry fixes"
            retrying={listQuery.isFetching}
          >
            {list && (
              <DataTable storageKey={`fix-intelligence-${view}-columns`} columns={fixColumns(view)} rows={fixRows(list.items, view)} label="Fix results" />
            )}
          </AsyncSection>
          {list && list.totalPages > 1 && (
            <Pager page={page} totalPages={list.totalPages} onPrevious={() => setPage(page - 1)} onNext={() => setPage(page + 1)} disabled={listQuery.isFetching} label="Fix pages" />
          )}
        </section>

        <section className="panel fi-distribution" aria-label="Severity distribution">
          <h2>Severity distribution</h2>
          <p className="fi-section-caption">All fixes in this view</p>
          <AsyncSection
            state={summary ? 'ready' : summaryQuery.isError ? 'unavailable' : 'pending'}
            loadingLabel="Loading severity distribution…"
            unavailableMessage="Severity distribution is unavailable until the fix summary loads."
          >
            <div className="severity-meter">
              {[...SEVERITY_ORDER, 'UNKNOWN'].map((key) => {
                const bucket = summary?.severityDistribution.find((item) => item.key === key);
                const percent = safePercent(bucket?.percent);
                return (
                  <div key={key} className="severity-row">
                    <span className="severity-label">{key === 'UNKNOWN' ? 'Unrated' : titleCase(key)}</span>
                    <div className="severity-bar-track" role="presentation">
                      <div className={`severity-bar severity-bar-${key.toLowerCase()}`} style={{ width: `${percent}%` }} />
                    </div>
                    <span className="severity-value">{`${bucket?.count ?? 0} · ${percent}%`}</span>
                  </div>
                );
              })}
            </div>
          </AsyncSection>
        </section>
      </div>
    </div>
  );
}

function KpiCards({ summary, availability }: { summary: FixSummary | undefined; availability: MetricAvailability }): React.ReactElement {
  const cards = [
    { label: 'Total Fixes', value: summary?.totalFixes },
    { label: 'Critical Severity', value: summary?.criticalSeverity, tone: 'critical' },
    { label: 'High Priority', value: summary?.highPriority, tone: 'high', hint: 'Critical or high, and in KEV or not yet remediated anywhere' },
    { label: 'Ecosystems Covered', value: summary?.ecosystemsCovered }
  ];
  return (
    <div className="fi-kpis">
      {cards.map((card) => (
        <div key={card.label} className={`panel fi-kpi${card.tone ? ` fi-kpi--${card.tone}` : ''}`} title={card.hint}>
          <span className="fi-kpi-label">{card.label}</span>
          <span className="fi-kpi-value">
            <MetricValue availability={availability} value={card.value} unavailableReason="Fix summary unavailable" />
          </span>
        </div>
      ))}
    </div>
  );
}
