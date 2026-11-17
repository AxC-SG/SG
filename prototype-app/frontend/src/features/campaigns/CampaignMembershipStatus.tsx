import { useQuery } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { CampaignSummary } from './types';

function formatWhen(value: string | null): string {
  return value ? new Date(value).toLocaleString() : 'not yet';
}

/**
 * Membership state for a campaign (Phase 0B §4.2, §4.3): a banner while it is still MATERIALIZING, and the reconciler's
 * last run underneath. A reconciliation failure is shown here, never as an ownership problem.
 */
export function CampaignMembershipStatus({ campaignId, summary }: {
  campaignId: string; summary: Pick<CampaignSummary, 'membershipState' | 'totalFindings'>;
}) {
  const reconciliation = useQuery({
    queryKey: ['campaign-reconciliation', campaignId],
    queryFn: () => api.getCampaignReconciliation(campaignId),
  });
  const data = reconciliation.data;
  return (
    <div className="campaign-membership-status">
      {summary.membershipState === 'MATERIALIZING' && (
        <div className="notice warning" role="status">
          This campaign is still adding members: {summary.totalFindings} so far. Counts are partial, and launch
          notifications are sent once membership is complete.
        </div>
      )}
      {reconciliation.isError && <p className="panel-caption" role="status">Reconciliation status could not be loaded.</p>}
      {data && (
        <p className="panel-caption" role="status">
          Membership {data.membershipState === 'COMPLETE' ? 'complete' : 'in progress'} · {data.members} members
          {data.scopeKind === 'CVE'
            ? ` · last reconciled ${formatWhen(data.reconciledAt)} · ${data.lastAdded ?? 0} added in the last run`
            : ' · fixed scope, no automatic additions'}
          {data.consecutiveFailures > 0 ? ` · ${data.consecutiveFailures} consecutive failure${data.consecutiveFailures === 1 ? '' : 's'}` : ''}
          {data.lastError ? ` · last error: ${data.lastError}` : ''}
        </p>
      )}
    </div>
  );
}
