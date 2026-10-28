import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
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

  return (
    <div className="page-grid fi-page ui2-fix-family">
      <div className="fi-header">
        <div>
          <h2>{viewLabel(view)}</h2>
          <p className="muted">
            Patches from your patch tools, plus workarounds and compensating controls your team maintains.
            Fixes give remediation context; they never change a finding&apos;s status.
          </p>
        </div>
        {canCreate && (
          <button type="button" className="btn btn-primary" onClick={() => setCreating(true)}>
            {view === 'compensating-controls' ? 'New compensating control' : 'New workaround'}
          </button>
        )}
      </div>

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

      {summaryQuery.isError && <div className="notice error">Fix summary could not be loaded.</div>}
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

      <div className="fi-body">
        <section className="panel fi-table-panel">
          <div className="fi-filters">
            <input
              className="input fi-search"
              type="search"
              placeholder="Search by title, KB, or ID"
              aria-label="Search fixes"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <select className="input" aria-label="Severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">All severities</option>
              {SEVERITY_ORDER.map((key) => <option key={key} value={key}>{titleCase(key)}</option>)}
            </select>
            <select className="input" aria-label="Ecosystem" value={ecosystem} onChange={(event) => setEcosystem(event.target.value)}>
              <option value="">All ecosystems</option>
              {ECOSYSTEM_ORDER.map((key) => <option key={key} value={key}>{ecosystemLabel(key)}</option>)}
            </select>
          </div>

          {listQuery.isError && <div className="notice error">Fixes could not be loaded.</div>}
          {listQuery.isLoading && <p className="muted">Loading fixes…</p>}
          {list && list.items.length === 0 && (
            <p className="muted fi-empty">
              {view === 'patches'
                ? 'No patches yet. Connect SCCM, Intune, BigFix or Tanium under Connectors → Patch Management.'
                : 'No fixes match these filters.'}
            </p>
          )}
          {list && list.items.length > 0 && (
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
                      if (event.key === 'Enter') navigate(`/fix-intelligence/details/${encodeURIComponent(fix.id)}`);
                    }}
                  >
                    <td className="mono">{fix.displayId}</td>
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
          <h3>Severity Distribution</h3>
          <div className="severity-meter">
            {SEVERITY_ORDER.filter((key) => key !== 'NONE').map((key) => {
              const bucket = summary?.severityDistribution.find((item) => item.key === key);
              const percent = safePercent(bucket?.percent);
              return (
                <div key={key} className="severity-row">
                  <span className="severity-label">{titleCase(key)}</span>
                  <div className="severity-bar-track" role="presentation">
                    <div className={`severity-bar severity-bar-${key.toLowerCase()}`} style={{ width: `${percent}%` }} />
                  </div>
                  <span className="severity-value">{bucket?.count ?? 0} · {percent}%</span>
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
    { label: 'Critical Severity', value: summary?.criticalSeverity },
    { label: 'High Priority', value: summary?.highPriority, hint: 'Critical or high, and in KEV or not yet remediated anywhere' },
    { label: 'Ecosystems Covered', value: summary?.ecosystemsCovered }
  ];
  return (
    <div className="fi-kpis">
      {cards.map((card) => (
        <div key={card.label} className="panel fi-kpi" title={card.hint}>
          <span className="fi-kpi-label">{card.label}</span>
          <span className="fi-kpi-value">{card.value ?? 0}</span>
        </div>
      ))}
    </div>
  );
}
