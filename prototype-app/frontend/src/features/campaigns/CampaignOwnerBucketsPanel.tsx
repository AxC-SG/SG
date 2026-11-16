import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import { AsyncSection } from '../../components/AsyncSection';
import { SegmentedControl } from '../../components/SegmentedControl';
import { ownerBucketLabel } from './ownership';
import type { CampaignOwnerGrouping } from './types';

/** Members by owner (Phase 0B §4.5): current owner by default, owner at add as an alternative. A rename changes only the label. */
export function CampaignOwnerBucketsPanel({ campaignId }: { campaignId: string }) {
  const [groupBy, setGroupBy] = React.useState<CampaignOwnerGrouping>('current');
  const buckets = useQuery({
    queryKey: ['campaign-owner-buckets', campaignId, groupBy],
    queryFn: () => api.listCampaignOwnerBuckets(campaignId, groupBy),
  });
  const rows = buckets.data ?? [];
  const state = buckets.isPending ? 'pending' : buckets.isError && !buckets.data ? 'error' : rows.length > 0 ? 'ready' : 'empty';

  return (
    <section className="panel" aria-labelledby="campaign-owner-buckets">
      <div className="panel-header">
        <h3 id="campaign-owner-buckets">Members by owner</h3>
        <SegmentedControl<CampaignOwnerGrouping>
          ariaLabel="Group owners by"
          value={groupBy}
          onChange={setGroupBy}
          options={[{ value: 'current', label: 'Current owner' }, { value: 'atAdd', label: 'Owner at add' }]}
        />
      </div>
      <AsyncSection
        state={state}
        loadingLabel="Loading owners…"
        errorMessage="Owner buckets could not be loaded."
        onRetry={() => void buckets.refetch()}
        retrying={buckets.isFetching}
        emptyTitle="No members yet"
        emptyMessage="Owners appear once the campaign has members."
        refreshError={buckets.isError && buckets.data ? 'The latest owner buckets could not be loaded; showing the previous result.' : undefined}
      >
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th>Owner</th><th>Members</th><th>Active remaining</th><th>Remediated</th></tr></thead>
            <tbody>
              {rows.map((bucket) => (
                <tr key={`${bucket.bucket}:${bucket.teamId ?? ''}`}>
                  <td>{ownerBucketLabel(bucket)}</td>
                  <td>{bucket.members}</td>
                  <td>{bucket.activeRemaining}</td>
                  <td>{bucket.outcomes.REMEDIATED ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </AsyncSection>
    </section>
  );
}
