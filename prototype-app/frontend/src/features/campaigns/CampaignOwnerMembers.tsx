import React from 'react';
import { CampaignMembersPanel } from './CampaignMembersPanel';
import { CampaignOwnerBucketsPanel, type BucketSelection } from './CampaignOwnerBucketsPanel';
import type { CampaignOwnerGrouping } from './types';

/** Owner buckets that drill into the members table; changing the grouping drops the bucket filter. */
export function CampaignOwnerMembers({ campaignId }: { campaignId: string }) {
  const [groupBy, setGroupBy] = React.useState<CampaignOwnerGrouping>('current');
  const [bucket, setBucket] = React.useState<BucketSelection | null>(null);
  return (
    <>
      <CampaignOwnerBucketsPanel
        campaignId={campaignId}
        groupBy={groupBy}
        onGroupByChange={(value) => { setGroupBy(value); setBucket(null); }}
        selected={bucket}
        onSelect={setBucket}
      />
      <CampaignMembersPanel campaignId={campaignId} groupBy={groupBy} bucket={bucket} onClearBucket={() => setBucket(null)} />
    </>
  );
}
