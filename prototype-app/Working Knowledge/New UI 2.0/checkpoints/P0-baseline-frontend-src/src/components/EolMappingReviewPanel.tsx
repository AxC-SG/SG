import { useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { createPortal } from 'react-dom';
import { api } from '../api/client';
import { pathForTab } from '../app/routes';
import {
  useOperationalQualityIssuesQuery,
  type OperationalQualityIssuesQueryParams
} from '../features/operations/queries';
import {
  useEolUnresolvedMappingsQuery,
  useEolSlugSuggestionsQuery
} from '../features/eol/queries';
import { useSoftwareIdentityDetailQuery } from '../features/software-identities/queries';
import type {
  EolSlugSuggestion,
  UnresolvedEolMapping
} from '../features/eol/types';

const UNRESOLVED_PAGE_SIZE = 25;
const MATCHING_ISSUE_TYPE = 'SOFTWARE_IDENTITY_NEEDS_EOL_MAPPING';
const INVALIDATION_KEYS = [
  ['eol-unresolved-mappings'],
  ['eol-summary'],
  ['eol-component-statuses'],
  ['software-identities'],
  ['software-identity-detail'],
  ['operational-quality-summary'],
  ['operational-quality-issues'],
  ['operational-quality-issue-detail']
] as const;

type Props = {
  qualityFilters?: Pick<
    OperationalQualityIssuesQueryParams,
    'issueType' | 'severity' | 'affectsActiveFindings' | 'assetType' | 'sourceSystem' | 'ecosystem' | 'query'
  >;
};

function formatInstant(value?: string): string {
  if (!value) return '-';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function formatCount(value: number | string | undefined): string {
  if (typeof value === 'number') return value.toLocaleString();
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed.toLocaleString();
  }
  return '0';
}

// ---------------------------------------------------------------------------
// Slug suggestion combobox
// ---------------------------------------------------------------------------

function SlugSuggestInput({
  value,
  onChange,
  suggestions,
  disabled,
}: {
  value: string;
  onChange: (val: string) => void;
  suggestions: EolSlugSuggestion[];
  disabled: boolean;
}) {
  const [open, setOpen] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);
  const [dropdownPos, setDropdownPos] = React.useState<{ top: number; left: number; width: number } | null>(null);

  function updatePosition() {
    if (inputRef.current) {
      const rect = inputRef.current.getBoundingClientRect();
      setDropdownPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    }
  }

  function confidenceClass(confidence: string) {
    switch (confidence.toUpperCase()) {
      case 'HIGH': return 'slug-suggest-confidence--high';
      case 'MEDIUM': return 'slug-suggest-confidence--medium';
      default: return 'slug-suggest-confidence--low';
    }
  }

  const showDropdown = open && suggestions.length > 0;

  return (
    <div className="slug-suggest-wrap">
      <input
        ref={inputRef}
        type="text"
        className="filter-input"
        placeholder="Select a suggestion or type a slug"
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => { updatePosition(); setOpen(true); }}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
      />
      {showDropdown && dropdownPos && createPortal(
        <div
          className="slug-suggest-dropdown"
          style={{
            position: 'fixed',
            top: dropdownPos.top,
            left: dropdownPos.left,
            width: dropdownPos.width,
            zIndex: 9999,
          }}
        >
          {suggestions.map((s) => (
            <button
              key={s.slug}
              type="button"
              className="slug-suggest-option"
              onMouseDown={() => { onChange(s.slug); setOpen(false); }}
            >
              <div className="slug-suggest-top">
                <span className="mono">{s.slug}</span>
                <span className={`slug-suggest-confidence ${confidenceClass(s.confidence)}`}>
                  {s.confidence}
                </span>
              </div>
              <div className="slug-suggest-bottom">
                <span>{s.displayName}</span>
                <span className="panel-caption slug-suggest-method">{s.method}</span>
              </div>
            </button>
          ))}
        </div>,
        document.body
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-version EOL status badge
// ---------------------------------------------------------------------------

function EolVersionBadge({ isEol, eolDate, daysRemaining }: {
  isEol?: boolean;
  eolDate?: string;
  daysRemaining?: number;
}) {
  if (isEol === true) {
    return <span className="eol-badge eol-badge--eol">EOL</span>;
  }
  if (daysRemaining !== undefined && daysRemaining <= 365) {
    return <span className="eol-badge eol-badge--near">Near EOL · {daysRemaining}d</span>;
  }
  if (eolDate) {
    return <span className="panel-caption mono">{eolDate}</span>;
  }
  return <span className="panel-caption">Unknown</span>;
}

// ---------------------------------------------------------------------------
// Expanded version rows — lazy-loaded when identity is expanded
// ---------------------------------------------------------------------------

function EolVersionRows({ identityId }: { identityId: string }) {
  const detailQuery = useSoftwareIdentityDetailQuery(identityId);
  const versions = detailQuery.data?.versions ?? [];

  if (detailQuery.isPending && !detailQuery.data) {
    return (
      <tr>
        <td colSpan={5} className="si-version-state-row">Loading versions…</td>
      </tr>
    );
  }

  if (!versions.length) {
    return (
      <tr>
        <td colSpan={5} className="si-version-state-row panel-caption">No version data available.</td>
      </tr>
    );
  }

  return (
    <>
      {versions.map(v => (
        <tr key={v.version} className="si-version-row">
          <td>
            <div className="quality-version-child-cell">
              <span className="si-version-indent">↳</span>
              <span className="mono si-version-tag">{v.version || '—'}</span>
              {v.eolCycle && (
                <span className="panel-caption"> · cycle {v.eolCycle}</span>
              )}
            </div>
          </td>
          <td>
            <div className="software-identity-row-stack">
              <span>{v.assetCount.toLocaleString()} asset{v.assetCount !== 1 ? 's' : ''}</span>
              <span className="panel-caption">{v.componentCount.toLocaleString()} components</span>
            </div>
          </td>
          <td>
            <div className="software-identity-row-stack">
              <span>{v.openFindingCount.toLocaleString()} findings</span>
              <span className="panel-caption">{v.openVulnerabilityCount.toLocaleString()} vulns</span>
            </div>
          </td>
          <td className="panel-caption">{v.lastObservedAt ? formatInstant(v.lastObservedAt) : '—'}</td>
          <td>
            <EolVersionBadge isEol={v.isEol} eolDate={v.eolDate} daysRemaining={v.eolDaysRemaining} />
          </td>
        </tr>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------
// Identity parent row — owns its own draft slug + suggestion state
// Fetching suggestions here (not in the parent) avoids bulk upfront queries
// and ensures data is ready before the user interacts with the input.
// ---------------------------------------------------------------------------

type EolIdentityRowProps = {
  item: UnresolvedEolMapping;
  isExpanded: boolean;
  onToggle: () => void;
  onMapped: () => Promise<void>;
};

function EolIdentityRow({ item, isExpanded, onToggle, onMapped }: EolIdentityRowProps) {
  const [draft, setDraft] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [rowNotice, setRowNotice] = React.useState<{ kind: 'error' | 'success'; message: string } | null>(null);

  // Suggestions fetched per-row so they load in the background as the list
  // renders, rather than all at once via useQueries in the parent.
  const suggestionsQuery = useEolSlugSuggestionsQuery(item.normalizedKey);
  const suggestions = suggestionsQuery.data ?? [];

  async function handleConfirm() {
    const slug = draft.trim();
    if (!slug) return;
    setBusy(true);
    setRowNotice(null);
    try {
      await api.confirmEolMapping(item.normalizedKey, slug);
      setRowNotice({ kind: 'success', message: `Mapped to "${slug}"` });
      await onMapped();
    } catch (err) {
      setRowNotice({ kind: 'error', message: err instanceof Error ? err.message : String(err) });
      setBusy(false);
    }
  }

  return (
    <tr className={`si-identity-row${isExpanded ? ' si-identity-row-expanded' : ''}`}>
      <td onClick={onToggle} style={{ cursor: 'pointer' }}>
        <div className="si-identity-name-cell">
          <span className={`si-expand-toggle${isExpanded ? ' si-expand-toggle-open' : ''}`}>▶</span>
          <div>
            <div>{item.displayName}</div>
            <div className="panel-caption mono">{item.normalizedKey}</div>
            {item.versionCount > 0 && (
              <div className="panel-caption si-version-count">
                {item.versionCount} version{item.versionCount !== 1 ? 's' : ''}
              </div>
            )}
          </div>
        </div>
      </td>
      <td>
        <div className="software-identity-row-stack">
          <span>{formatCount(item.assetCount)} assets</span>
          <span className="panel-caption">
            {formatCount(item.componentCount)} components · {formatCount(item.versionCount)} versions
          </span>
        </div>
      </td>
      <td>
        <div className="software-identity-row-stack">
          <span>{formatCount(item.openFindingCount)} findings</span>
          <span className="panel-caption">{formatCount(item.openVulnerabilityCount)} vulns</span>
        </div>
      </td>
      <td>{formatInstant(item.lastObservedAt)}</td>
      <td onClick={e => e.stopPropagation()}>
        <div className="eol-slug-confirm-row">
          <SlugSuggestInput
            value={draft}
            onChange={setDraft}
            suggestions={suggestions}
            disabled={busy}
          />
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy || !draft.trim()}
            onClick={() => void handleConfirm()}
          >
            {busy ? 'Saving…' : 'Confirm'}
          </button>
        </div>
        {rowNotice && (
          <div
            className={`notice${rowNotice.kind === 'error' ? ' error' : ''}`}
            style={{ marginTop: 4, padding: '4px 8px', fontSize: '0.85em' }}
          >
            {rowNotice.message}
          </div>
        )}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

export function EolMappingReviewPanel({ qualityFilters }: Props) {
  const queryClient = useQueryClient();
  const [unresolvedPage, setUnresolvedPage] = React.useState(0);
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());

  const unresolvedMappingsQuery = useEolUnresolvedMappingsQuery(
    { page: unresolvedPage, size: UNRESOLVED_PAGE_SIZE }
  );
  const unresolvedPageData = unresolvedMappingsQuery.data;
  const unresolvedList = React.useMemo(() => unresolvedPageData?.content ?? [], [unresolvedPageData]);
  const unresolvedTotalPages = unresolvedPageData?.totalPages ?? 1;
  const unresolvedTotalElements = unresolvedPageData?.totalElements ?? 0;

  const normalizedIssueType = (qualityFilters?.issueType ?? '').trim().toUpperCase();
  const issueTypeExcludesMappingReview = normalizedIssueType.length > 0 && normalizedIssueType !== MATCHING_ISSUE_TYPE;

  const mappingIssueFilters = React.useMemo<OperationalQualityIssuesQueryParams>(() => ({
    domain: 'EOL',
    issueType: MATCHING_ISSUE_TYPE,
    severity: qualityFilters?.severity,
    affectsActiveFindings: qualityFilters?.affectsActiveFindings,
    assetType: qualityFilters?.assetType,
    sourceSystem: qualityFilters?.sourceSystem,
    ecosystem: qualityFilters?.ecosystem,
    query: qualityFilters?.query,
    page: 0,
    size: 200
  }), [qualityFilters]);

  const hasIntersectionFilters = Boolean(
    qualityFilters?.severity
    || qualityFilters?.affectsActiveFindings != null
    || (qualityFilters?.assetType?.length ?? 0) > 0
    || (qualityFilters?.sourceSystem?.length ?? 0) > 0
    || (qualityFilters?.ecosystem?.length ?? 0) > 0
    || (qualityFilters?.query?.trim().length ?? 0) > 0
  );

  const filteredMappingIssuesQuery = useOperationalQualityIssuesQuery(
    mappingIssueFilters,
    hasIntersectionFilters && !issueTypeExcludesMappingReview
  );

  const filteredIdentityIds = React.useMemo(
    () => new Set(
      (filteredMappingIssuesQuery.data?.items ?? [])
        .map(issue => issue.sourceObjectId)
        .filter((v): v is string => Boolean(v))
    ),
    [filteredMappingIssuesQuery.data?.items]
  );

  const filteredList = React.useMemo(() => {
    if (issueTypeExcludesMappingReview) return [];
    if (!hasIntersectionFilters || !filteredMappingIssuesQuery.data) return unresolvedList;
    return unresolvedList.filter(item => filteredIdentityIds.has(item.softwareIdentityId));
  }, [
    filteredIdentityIds,
    filteredMappingIssuesQuery.data,
    hasIntersectionFilters,
    issueTypeExcludesMappingReview,
    unresolvedList
  ]);

  const loadingReviewList = unresolvedMappingsQuery.isPending
    || (
      hasIntersectionFilters
      && !issueTypeExcludesMappingReview
      && filteredMappingIssuesQuery.isPending
      && !filteredMappingIssuesQuery.data
    );

  const eolCatalogHref = pathForTab('end-of-life');

  function toggleExpand(identityId: string) {
    setExpandedIds(prev => {
      const next = new Set(prev);
      if (next.has(identityId)) next.delete(identityId); else next.add(identityId);
      return next;
    });
  }

  const handleMapped = React.useCallback(async () => {
    await Promise.all(INVALIDATION_KEYS.map(queryKey => queryClient.invalidateQueries({ queryKey })));
  }, [queryClient]);

  return (
    <div className="eol-mapping-review">
      <div className="eol-mapping-review-header">
        <div>
          <span className="panel-caption">
            Software without an endoflife.date match — sorted by exposure then footprint.
            {' '}{unresolvedTotalElements > 0 && <strong>{unresolvedTotalElements.toLocaleString()} remaining</strong>}
          </span>
        </div>
        <a href={eolCatalogHref} className="btn btn-secondary">
          Browse EOL Catalog
        </a>
      </div>

      {loadingReviewList && (
        <div className="panel-caption" style={{ padding: '24px 0' }}>Loading…</div>
      )}

      {!loadingReviewList && unresolvedMappingsQuery.error instanceof Error && (
        <div className="notice error">
          Unable to load unmatched EOL software: {unresolvedMappingsQuery.error.message}
        </div>
      )}

      {!loadingReviewList && hasIntersectionFilters && !issueTypeExcludesMappingReview && filteredMappingIssuesQuery.error instanceof Error && (
        <div className="notice error">
          Unable to apply current Quality filters: {filteredMappingIssuesQuery.error.message}
        </div>
      )}

      {!loadingReviewList && !unresolvedMappingsQuery.error && filteredList.length === 0 && (
        <div className="empty-state">
          <p>
            {issueTypeExcludesMappingReview
              ? 'The current Issue Type filter excludes unmatched EOL software.'
              : hasIntersectionFilters
                ? 'No unmatched EOL software matches the current filters.'
                : 'No actionable EOL mapping gaps. Library-ecosystem packages (npm, maven, pypi, etc.) are excluded — endoflife.date tracks OS packages, runtimes, and infrastructure software, not individual libraries.'}
          </p>
        </div>
      )}

      {!loadingReviewList && filteredList.length > 0 && (
        <>
          <div className="table-scroll">
            <table className="resizable-table">
              <thead>
                <tr>
                  <th style={{ minWidth: 240 }}>Software</th>
                  <th style={{ minWidth: 180 }}>Footprint</th>
                  <th style={{ minWidth: 140 }}>Exposure</th>
                  <th style={{ minWidth: 160 }}>Last Observed</th>
                  <th style={{ minWidth: 360 }}>EOL Slug</th>
                </tr>
              </thead>
              <tbody>
                {filteredList.map(item => (
                  <React.Fragment key={item.softwareIdentityId}>
                    <EolIdentityRow
                      item={item}
                      isExpanded={expandedIds.has(item.softwareIdentityId)}
                      onToggle={() => toggleExpand(item.softwareIdentityId)}
                      onMapped={handleMapped}
                    />
                    {expandedIds.has(item.softwareIdentityId) && (
                      <EolVersionRows identityId={item.softwareIdentityId} />
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>

          {!hasIntersectionFilters && unresolvedTotalPages > 1 && (
            <div className="pagination quality-pagination">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={unresolvedPage === 0}
                onClick={() => setUnresolvedPage(p => p - 1)}
              >
                Previous
              </button>
              <span className="panel-caption">
                Page {unresolvedPage + 1} of {unresolvedTotalPages}
                {' · '}{unresolvedTotalElements.toLocaleString()} unmatched
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={unresolvedPage >= unresolvedTotalPages - 1}
                onClick={() => setUnresolvedPage(p => p + 1)}
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
