import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from 'react-router-dom';
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
import type { FixSummary, FixView } from './types';

const PAGE_SIZE = 50;
const VIEW_DESCRIPTIONS: Record<FixView, string> = {
  all: 'Patches, workarounds and compensating controls across your environment.',
  patches: 'Track imported patches, deployment coverage and the ecosystems they protect.',
  workarounds: 'Manage temporary mitigations and configuration changes while permanent fixes are prepared.',
  'compensating-controls': 'Manage additional safeguards and review the residual risk they address.'
};

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
  const clearFilters = () => { setSearch(''); setSeverity(''); setEcosystem(''); setPage(0); };

  return (
    <div className="page-grid fi-page ui2-fix-family">
      <header className="fi-header">
        <div>
          <span className="fi-eyebrow">Fix Intelligence</span>
          <h2>{viewLabel(view)}</h2>
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
        <div className="notice error fi-error" role="alert">
          <span>Fix summary could not be loaded. Try again to refresh the metrics.</span>
          <button type="button" className="btn" disabled={summaryQuery.isFetching} onClick={() => void summaryQuery.refetch()}>Retry summary</button>
        </div>
      )}
      <KpiCards summary={summary} />

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
        {hasFilters && <button type="button" className="btn" onClick={clearFilters}>Clear filters</button>}
      </div>
      <div className="fi-body">
        <section className="panel fi-table-panel" aria-label="Fixes">
          <div className="fi-section-heading">
            <h3>Fix catalog</h3>
            <span className="muted" role="status">{list ? `${list.totalItems.toLocaleString()} fixes` : listQuery.isError ? 'Unavailable' : 'Loading fixes…'}</span>
          </div>
          {listQuery.isError && <div className="notice error fi-error" role="alert">
            <span>Fixes could not be loaded.</span>
            <button type="button" className="btn" disabled={listQuery.isFetching} onClick={() => void listQuery.refetch()}>Retry fixes</button>
          </div>}
          {listQuery.isLoading && <p className="muted">Loading fixes…</p>}
          {list && list.items.length === 0 && (
            <p className="muted fi-empty">
              {hasFilters ? 'No fixes match these filters.'
                : view === 'patches' ? 'No patches yet. Connect a supported patch source under Connectors.'
                : view === 'all' ? 'No fixes yet. Connect a patch source or create a workaround to get started.'
                : view === 'workarounds' ? 'No workarounds yet. Create a workaround to document a temporary mitigation.'
                : 'No compensating controls yet. Create a control to document an additional safeguard.'}
            </p>
          )}
          {list && list.items.length > 0 && (
            <div className="fi-table-scroll" role="region" aria-label="Fix results" tabIndex={0}>
              <table className="data-table fi-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Severity</th>
                    {view === 'all' && <th>Type</th>}
                    <th>Ecosystem</th>
                    <th>Source</th>
                    <th>Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {list.items.map((fix) => (
                    <tr
                      key={fix.id}
                      className="table-row-clickable"
                      tabIndex={0}
                      onClick={() => navigate(`/fix-intelligence/details/${encodeURIComponent(fix.id)}`)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' && event.target === event.currentTarget) navigate(`/fix-intelligence/details/${encodeURIComponent(fix.id)}`);
                      }}
                    >
                      <td className="mono"><Link to={`/fix-intelligence/details/${encodeURIComponent(fix.id)}`} onClick={(event) => event.stopPropagation()}>{fix.displayId}</Link></td>
                      <td>{fix.title}{fix.status !== 'ACTIVE' && <span className="fi-status-tag">{titleCase(fix.status)}</span>}</td>
                      <td><span className={severityClass(fix.severity)}>{fix.severity ? titleCase(fix.severity) : 'Unrated'}</span></td>
                      {view === 'all' && <td>{fixTypeLabel(fix.fixType)}</td>}
                      <td>{ecosystemLabel(fix.ecosystem)}</td>
                      <td>{fix.sources.length ? fix.sources.map(providerLabel).join(', ') : '—'}</td>
                      <td>{coverageLabel(fix.remediatedAssets, fix.applicableAssets, fix.coveragePercent)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {list && list.totalPages > 1 && (
            <div className="fi-pagination">
              <button type="button" className="btn" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="muted">Page {page + 1} of {list.totalPages} · {list.totalItems} fixes</span>
              <button type="button" className="btn" disabled={page + 1 >= list.totalPages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          )}
        </section>

        <section className="panel fi-distribution" aria-label="Severity distribution">
          <h3>Severity distribution</h3>
          <p className="fi-section-caption">All fixes in this view</p>
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
                  <span className="severity-value">{summary ? `${bucket?.count ?? 0} · ${percent}%` : '—'}</span>
                </div>
              );
            })}
          </div>
        </section>
      </div>
    </div>
  );
}

function KpiCards({ summary }: { summary: FixSummary | undefined }): React.ReactElement {
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
          <span className="fi-kpi-value">{card.value?.toLocaleString() ?? '—'}</span>
        </div>
      ))}
    </div>
  );
}
