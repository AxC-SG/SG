import React from 'react';
import './platform-feed-catalog.css';
import { useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { AlertTriangle, ArrowLeft, ArrowUpRight, CalendarDays, BookOpen, FileText, Globe, Monitor, PackageSearch, Search, Shield, TrendingUp } from 'lucide-react';
import { api } from '../api/client';
import { EolSourcePanel } from '../components/EolSourcePanel';
import { FeedScheduleControl } from './FeedScheduleControl';
import { intelligenceApi } from '../features/intelligence/api';
import type { VulnIntelSourceStatus, VulnIntelSourcesSummary } from '../api/client';
import type { SyncTriggerResponse } from '../features/connect/types';
import { formatTimestamp, timeAgo } from '../lib/time';

type SourceSectionProps = {
  icon: React.ReactNode;
  syncType?: string;
  name: string;
  lastRun?: VulnIntelSourceStatus;
  configFields?: React.ReactNode;
  triggerSync?: () => Promise<SyncTriggerResponse>;
  note?: string;
};

function SourceSection({ lastRun, configFields, triggerSync, note, syncType }: SourceSectionProps) {
  const client = useQueryClient();
  const [running, setRunning] = React.useState(false);
  const [result, setResult] = React.useState<SyncTriggerResponse | null>(null);
  const [error, setError] = React.useState('');

  const trigger = async () => {
    if (!triggerSync) return;
    setRunning(true);
    setError('');
    setResult(null);
    try {
      const res = await triggerSync();
      setResult(res);
      void client.invalidateQueries({ queryKey: ['vuln-intel-sources-summary'] });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  const hasLastRun = lastRun?.status === 'completed';
  const isFailed = lastRun?.status === 'failed';
  const totalRecords = (lastRun?.recordsInserted ?? 0) + (lastRun?.recordsUpdated ?? 0);
  const lastRunAgo = timeAgo(lastRun?.completedAt);

  const dotClass = isFailed
    ? 'connect-source-dot--fail'
    : hasLastRun
    ? 'connect-source-dot--ok'
    : 'connect-source-dot--warn';

  return (
    <div className="vi-source-section">
      <div className="vi-source-header">
        <span className="vi-source-name">Sync status</span>
        <span className={`connect-source-dot ${dotClass}`} aria-hidden="true" />
        <span className="vi-source-meta">{lastRun?.status === 'running' ? 'Syncing' : isFailed ? 'Sync failed' : hasLastRun ? 'Synced' : lastRun ? 'No sync run recorded yet' : 'Status unavailable'}</span>
        {hasLastRun && !isFailed && lastRunAgo && (
          <span className="vi-source-meta">
            Last run · {lastRunAgo}
            {totalRecords > 0 && ` · ${totalRecords.toLocaleString()} records`}
          </span>
        )}
        {isFailed && lastRunAgo && (
          <span className="vi-source-meta vi-source-meta--fail">Failed · {lastRunAgo}</span>
        )}
      </div>

      {isFailed && (
        <div className="sn-status-row sn-status-row--error">
          <span className="sn-status-pill sn-status-fail">Failed</span>
          <span className="sn-status-meta">{formatTimestamp(lastRun?.completedAt)}</span>
          {lastRun?.errorMessage && (
            <span className="sn-status-error-msg" title={lastRun.errorMessage}>
              {lastRun.errorMessage.length > 100
                ? lastRun.errorMessage.slice(0, 100) + '…'
                : lastRun.errorMessage}
            </span>
          )}
        </div>
      )}

      {note && <p className="vi-source-note">{note}</p>}
      {configFields && <div className="vi-source-config">{configFields}</div>}

      {syncType && <FeedScheduleControl syncType={syncType} />}

      {error && <div className="notice error" role="alert">{error}</div>}
      {result && (
        <div className="notice" role="status">
          <strong>Integration queued.</strong>{result.message ? ` ${result.message}` : ''}
        </div>
      )}

      {triggerSync && (
        <div className="vi-source-actions">
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => void trigger()}
            disabled={running}
          >
            {running ? 'Queueing…' : 'Run integration now'}
          </button>
        </div>
      )}
    </div>
  );
}

type Props = {
  vulnSummary?: VulnIntelSourcesSummary | null;
  isLoading?: boolean;
  loadError?: string;
};

type CatalogSource = SourceSectionProps & {
  id: string;
  group: string;
  summary: string;
};

const SOURCE_GROUPS = [
  { id: 'vulnerabilities', title: 'Vulnerability intelligence', caption: 'Core vulnerability and package advisory feeds.' },
  { id: 'vendors', title: 'Vendor & regional advisories', caption: 'Vendor applicability and regional vulnerability coverage.' },
  { id: 'enrichment', title: 'Enrichment & imports', caption: 'Exploit likelihood, product lifecycles, and curated advisories.' },
];

function sourceHealth(source: CatalogSource, unavailable: boolean) {
  if (unavailable) return { label: 'Status unavailable', tone: 'neutral' };
  if (source.lastRun?.status === 'failed') return { label: 'Sync failed', tone: 'fail' };
  if (source.lastRun?.status === 'running') return { label: 'Syncing', tone: 'running' };
  if (source.lastRun?.status === 'completed') return { label: 'Synced', tone: 'ok' };
  if (source.id === 'advisory') return { label: 'On demand', tone: 'neutral' };
  if (!source.lastRun) return { label: 'Status unavailable', tone: 'neutral' };
  return { label: 'Never synced', tone: 'neutral' };
}

export function VulnIntelConfigPage({ vulnSummary, isLoading = false, loadError }: Props) {
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = React.useState('');
  const detailHeading = React.useRef<HTMLHeadingElement>(null);
  const cardRefs = React.useRef(new Map<string, HTMLButtonElement>());
  const previousSource = React.useRef<string | null>(null);
  const [nvdApiKey, setNvdApiKey] = React.useState('');
  const [showNvdKey, setShowNvdKey] = React.useState(false);

  const s = vulnSummary?.sources;

  const nvdConfigFields = (
    <>
      <div className="form-grid">
        <label>
          <span>
            NVD API Key{' '}
            <span
              className="sn-tooltip"
              title="Optional. Requests without a key are rate-limited to 5 req/30s. A free key raises the limit to 50 req/30s."
            >
              ⓘ
            </span>
          </span>
          <div className="secure-input-row">
            <input
              type={showNvdKey ? 'text' : 'password'}
              value={nvdApiKey}
              onChange={(e) => setNvdApiKey(e.target.value)}
              placeholder="Leave blank to use anonymous rate limits"
              autoComplete="off"
            />
            <button
              type="button"
              className="btn btn-secondary btn-inline"
              onClick={() => setShowNvdKey((v) => !v)}
            >
              {showNvdKey ? 'Hide' : 'Show'}
            </button>
          </div>
        </label>
      </div>

    </>
  );

  const sources: CatalogSource[] = [
    {
      id: 'nvd', group: 'vulnerabilities', summary: 'CVE records, severity scores, and affected products.',
      icon: <Shield />,
      name: 'NVD Vulnerability Feed',
      lastRun: s?.['NVD'],
      configFields: nvdConfigFields,
      triggerSync: () => api.syncNvd(),
      syncType: 'NVD',
    },
    {
      id: 'kev', group: 'vulnerabilities', summary: 'CISA’s catalog of vulnerabilities exploited in the wild.',
      icon: <AlertTriangle />,
      name: 'CISA KEV Feed',
      lastRun: s?.['KEV'],
      note: 'Known-exploited vulnerabilities catalog from CISA. No credentials required — publicly accessible.',

      triggerSync: () => api.syncKev(),
      syncType: 'KEV',
    },
    {
      id: 'ghsa', group: 'vulnerabilities', summary: 'GitHub security advisories and affected package versions.',
      icon: <BookOpen />,
      name: 'GitHub Advisory Database (GHSA)',
      lastRun: s?.['GHSA'],
      note: 'Advisories with package-version applicability for correlation. GitHub credentials are managed by your platform administrator.',

      triggerSync: () => api.syncGhsa(),
      syncType: 'GHSA',
    },
    {
      id: 'microsoft', group: 'vendors', summary: 'Microsoft security advisories and VEX applicability.',
      icon: <Monitor />,
      name: 'Microsoft CSAF + VEX',
      lastRun: s?.['CSAF_MICROSOFT'],
      note: 'Microsoft CSAF advisories and VEX applicability data from the MSRC public feed. No credentials required.',
      triggerSync: () => api.syncMicrosoftCsaf(),
      syncType: 'CSAF_MICROSOFT',
    },
    {
      id: 'redhat', group: 'vendors', summary: 'Red Hat security advisories and VEX applicability.',
      icon: <Shield />,
      name: 'Red Hat CSAF + VEX',
      lastRun: s?.['CSAF_REDHAT'],
      note: 'Red Hat CSAF advisories and VEX applicability data from the Red Hat Security Data API. No credentials required.',

      triggerSync: () => api.syncRedhatCsaf(),
      syncType: 'CSAF_REDHAT',
    },
    {
      id: 'advisory', group: 'enrichment', summary: 'Curated vendor advisories imported on demand.',
      icon: <FileText />,
      name: 'Advisory Imports',
      lastRun: s?.['ADVISORY'],
      note: 'Curated vendor advisories imported via API (POST /api/ingestion/advisories). No scheduled sync — imports are triggered on demand.',
    },
    {
      id: 'euvd', group: 'vendors', summary: 'European Union vulnerability intelligence from ENISA.',
      icon: <Globe />,
      name: 'EUVD Feed',
      lastRun: s?.['EUVD'],
      note: 'European Union Vulnerability Database ingestion for supplemental regional vulnerability intelligence.',
      triggerSync: () => api.syncEuvd(),
      syncType: 'EUVD',
    },
    {
      id: 'jvn', group: 'vendors', summary: 'Japanese vulnerability notes and JVNDB mappings.',
      icon: <Globe />,
      name: 'JVN Feed',
      lastRun: s?.['JVN'],
      note: 'Japan Vulnerability Notes Database ingestion for regional advisories and JVNDB mappings.',
      triggerSync: () => api.syncJvn(),
      syncType: 'JVN',
    },
    { id: 'epss', group: 'enrichment', summary: 'FIRST.org scores for the likelihood of exploitation.', icon: <TrendingUp />, lastRun: s?.['EPSS'], name: 'EPSS enrichment', syncType: 'EPSS', triggerSync: () => intelligenceApi.trigger('EPSS'),
      note: 'Stage FIRST.org exploitation probability scores for review. Enrichment never establishes applicability by itself.' },
    { id: 'osv', group: 'vulnerabilities', summary: 'Open-source package advisories and verified identifiers.', icon: <PackageSearch />, lastRun: s?.['OSV'], name: 'OSV advisories', syncType: 'OSV', triggerSync: () => intelligenceApi.trigger('OSV'),
      note: 'Stage package advisory records and verified identifier equivalences for review.' },
    { id: 'eol', group: 'enrichment', summary: 'Product release cycles and end-of-life dates.', icon: <CalendarDays />, name: 'endoflife.date EOL Feed', lastRun: s?.['EOL_FULL_REFRESH'] },
  ];

  const selected = sources.find((source) => source.id === params.get('feed'));
  const activeId = selected?.id;
  const query = search.trim().toLowerCase();
  const visibleSources = sources.filter((source) => `${source.name} ${source.summary}`.toLowerCase().includes(query));
  const selectSource = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set('feed', id);
    else next.delete('feed');
    setParams(next);
  };

  React.useEffect(() => {
    if (activeId) detailHeading.current?.focus();
    else if (previousSource.current) cardRefs.current.get(previousSource.current)?.focus();
    previousSource.current = activeId ?? null;
  }, [activeId]);

  if (selected) {
    return (
      <section className="panel platform-feed-detail">
        <button type="button" className="btn-link platform-feed-back" onClick={() => selectSource(null)}><ArrowLeft size={16} aria-hidden="true" /> Back to sources</button>
        <div className="platform-feed-detail-header">
          <span className={`platform-feed-icon platform-feed-icon--${selected.id}`} aria-hidden="true">{selected.icon}</span>
          <div><h3 ref={detailHeading} tabIndex={-1}>{selected.name}</h3><p className="panel-caption">{selected.summary}</p></div>
        </div>
        {selected.id === 'eol' ? (
          <>
            <div className="platform-feed-schedules">
              <section><h4>Full refresh schedule</h4><FeedScheduleControl syncType="EOL_FULL_REFRESH" /></section>
              <section><h4>Date sweep schedule</h4><FeedScheduleControl syncType="EOL_DATE_SWEEP" /></section>
            </div>
            <EolSourcePanel title="endoflife.date EOL Feed" caption="Refresh the shared catalog, release lifecycle data, inventory mappings, and EOL status." />
          </>
        ) : <SourceSection key={selected.id} {...selected} />}
      </section>
    );
  }

  return (
    <section className="panel platform-feed-catalog">
      <div className="platform-feed-toolbar">
        <div>
          <div className="platform-feed-title-row"><h3>Vulnerability Intelligence Sources</h3><span className="platform-feed-count">{sources.length} integrations</span></div>
          <p className="panel-caption">Select a source to manage its schedule and run an integration.</p>
        </div>
        <label className="platform-feed-search"><Search size={16} aria-hidden="true" /><input type="search" aria-label="Search integrations" placeholder="Search integrations…" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
      </div>
      {isLoading && <div className="notice" role="status">Loading source status…</div>}
      {loadError && <div className="notice error" role="alert">{loadError}</div>}
      <div className="platform-feed-groups">
        {SOURCE_GROUPS.map((group) => {
          const members = visibleSources.filter((source) => source.group === group.id);
          if (members.length === 0) return null;
          return (
            <section key={group.id} className="platform-feed-group" aria-labelledby={`feed-group-${group.id}`}>
              <div className="platform-feed-group-header"><h4 id={`feed-group-${group.id}`}>{group.title}</h4><span className="panel-caption">{group.caption}</span></div>
              <div className="platform-feed-grid">
                {members.map((source) => {
                  const health = sourceHealth(source, !vulnSummary);
                  const lastSync = source.lastRun?.status !== 'never' ? timeAgo(source.lastRun?.completedAt) : null;
                  return (
                    <button key={source.id} ref={(node) => { if (node) cardRefs.current.set(source.id, node); else cardRefs.current.delete(source.id); }} type="button" className="platform-feed-card" onClick={() => selectSource(source.id)}>
                      <span className="platform-feed-card-top"><span className={`platform-feed-icon platform-feed-icon--${source.id}`} aria-hidden="true">{source.icon}</span><ArrowUpRight className="platform-feed-card-arrow" size={16} aria-hidden="true" /></span>
                      <span className="platform-feed-card-name">{source.name}</span>
                      <span className="platform-feed-card-summary">{source.summary}</span>
                      <span className="platform-feed-card-footer"><span className={`platform-feed-health platform-feed-health--${health.tone}`}><span aria-hidden="true" />{isLoading ? 'Loading status…' : health.label}</span>{lastSync && <span title={formatTimestamp(source.lastRun?.completedAt)}>{lastSync}</span>}</span>
                    </button>
                  );
                })}
              </div>
            </section>
          );
        })}
        {visibleSources.length === 0 && <div className="empty-state" role="status"><p>No integrations match “{search}”.</p><button type="button" className="btn btn-secondary btn-sm" onClick={() => setSearch('')}>Clear search</button></div>}
      </div>
    </section>
  );
}
