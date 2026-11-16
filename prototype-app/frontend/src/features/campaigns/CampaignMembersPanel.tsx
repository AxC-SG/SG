import React from 'react';
import { useInfiniteQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api } from '../../api/client';
import { pathForFindingDetail } from '../../app/routes';
import { AsyncSection } from '../../components/AsyncSection';
import { DataTable, type DataTableColumn, type DataTableRow } from '../../components/DataTable';
import type { BucketSelection } from './CampaignOwnerBucketsPanel';
import { CAMPAIGN_OUTCOMES, ownerBucketLabel, campaignOwnerLabel, outcomeLabel, ownerAtAddLabel } from './ownership';
import { OwnerChangeIndicator } from './OwnerChangeIndicator';
import type { CampaignOutcome, CampaignOwnerGrouping } from './types';

const COLUMNS: DataTableColumn[] = [
  { id: 'finding', label: 'Finding', header: 'Finding', priority: 'essential', initialSize: 280, minWidth: 180 },
  { id: 'outcome', label: 'Outcome', header: 'Outcome', initialSize: 150 },
  { id: 'atAdd', label: 'Owner at add', header: 'Owner at add', initialSize: 180 },
  { id: 'current', label: 'Current owner', header: 'Current owner', priority: 'essential', initialSize: 220 },
];

const PAGE_SIZE = 50;

/**
 * Cursor-paged campaign members (Phase 0B §4.5). Suppressed, false-positive and accepted-risk members are hidden
 * until the outcome filter names them or "Include hidden" is on.
 */
export function CampaignMembersPanel({ campaignId, groupBy = 'current', bucket = null, onClearBucket }: {
  campaignId: string; groupBy?: CampaignOwnerGrouping; bucket?: BucketSelection | null; onClearBucket?: () => void;
}) {
  const [outcome, setOutcome] = React.useState<CampaignOutcome | ''>('');
  const [includeHidden, setIncludeHidden] = React.useState(false);
  const members = useInfiniteQuery({
    queryKey: ['campaign-members-panel', campaignId, outcome, includeHidden, groupBy, bucket],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => api.listCampaignMembers(campaignId, {
      cursor: pageParam, limit: PAGE_SIZE, outcome: outcome || undefined, includeHidden,
      ...(bucket ? { groupBy, bucket: bucket.bucket, teamId: bucket.teamId ?? undefined } : {}),
    }),
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = members.data?.pages.flatMap((page) => page.items) ?? [];
  const filtered = outcome !== '' || includeHidden || bucket !== null;
  const state = members.isPending ? 'pending' : members.isError && !members.data ? 'error'
    : items.length > 0 ? 'ready' : filtered ? 'filtered-empty' : 'empty';

  const rows: DataTableRow[] = items.map((member) => ({
    id: member.findingId,
    cells: {
      finding: { content: <><Link to={pathForFindingDetail(member.displayId)}>{member.displayId}</Link> {member.title}</> },
      outcome: { content: outcomeLabel(member.outcome) },
      atAdd: { content: ownerAtAddLabel(member.ownerAtAdd) },
      current: { content: <>{campaignOwnerLabel(member.currentOwnership)} <OwnerChangeIndicator member={member} /></> },
    },
  }));

  return (
    <section className="panel" aria-labelledby="campaign-members-panel">
      <div className="panel-header">
        <h3 id="campaign-members-panel">Campaign members</h3>
        <div className="button-row">
          <label>
            <span>Outcome</span>
            <select value={outcome} onChange={(event) => setOutcome(event.target.value as CampaignOutcome | '')}>
              <option value="">All except hidden</option>
              {CAMPAIGN_OUTCOMES.map((value) => <option key={value} value={value}>{outcomeLabel(value)}</option>)}
            </select>
          </label>
          <label>
            <input type="checkbox" checked={includeHidden} onChange={(event) => setIncludeHidden(event.target.checked)} />
            <span>Include hidden (suppressed, false positive, accepted risk)</span>
          </label>
        </div>
      </div>
      {bucket && (
        <p className="panel-caption" role="status">
          Showing {ownerBucketLabel({ bucket: bucket.bucket, teamName: null })} ({groupBy === 'atAdd' ? 'owner at add' : 'current owner'}){' '}
          <button type="button" className="btn btn-ghost btn-sm" onClick={onClearBucket}>Clear owner filter</button>
        </p>
      )}
      <AsyncSection
        state={state}
        loadingLabel="Loading members…"
        errorMessage="Campaign members could not be loaded."
        onRetry={() => void members.refetch()}
        retrying={members.isFetching}
        emptyTitle="No members yet"
        emptyMessage="Findings appear here once they are added to the campaign."
        filteredEmptyMessage="No members match this outcome."
        onClearFilters={() => { setOutcome(''); setIncludeHidden(false); onClearBucket?.(); }}
        refreshError={members.isError && members.data ? 'The latest members could not be loaded; showing the previous result.' : undefined}
      >
        <DataTable storageKey="campaign-members" columns={COLUMNS} rows={rows} label="Campaign members" />
        {members.hasNextPage && (
          <button type="button" className="btn btn-secondary btn-sm" disabled={members.isFetchingNextPage} onClick={() => void members.fetchNextPage()}>
            {members.isFetchingNextPage ? 'Loading…' : 'Load more'}
          </button>
        )}
        {members.isFetchNextPageError && <div className="notice error" role="alert">More members could not be loaded.</div>}
      </AsyncSection>
    </section>
  );
}
