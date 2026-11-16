import { type UseQueryResult } from '@tanstack/react-query';
import { ownerBucketLabel, outcomeLabel } from './ownership';
import type { CampaignPreview } from './types';

/**
 * Read-only preview of what a campaign would contain (Phase 0B §4.2): member count, distribution by owner, findings
 * left out, and teams that cannot be notified. Nothing is written.
 */
export function CampaignLaunchPreview({ preview }: { preview: UseQueryResult<CampaignPreview> }) {
  return (
    <section className="full cw-launch-preview" aria-labelledby="cw-launch-preview-title">
      <h4 id="cw-launch-preview-title">Launch preview</h4>
      {preview.isPending && <p className="muted" role="status">Checking what this campaign would contain…</p>}
      {preview.isError && (
        <div className="notice error" role="alert">
          <span>The launch preview could not be loaded: {preview.error instanceof Error ? preview.error.message : 'unknown error'}</span>
          <button type="button" className="btn btn-sm" onClick={() => void preview.refetch()}>Retry preview</button>
        </div>
      )}
      {preview.data && <PreviewBody preview={preview.data} />}
    </section>
  );
}

function PreviewBody({ preview }: { preview: CampaignPreview }) {
  const excluded = Object.entries(preview.excluded).filter(([, count]) => count > 0);
  return (
    <>
      <p><strong>{preview.memberCount}</strong> finding{preview.memberCount === 1 ? '' : 's'} would be added.</p>
      {preview.exceedsCreateBound && (
        <div className="notice warning" role="status">
          This scope is larger than the launch limit. The campaign starts with the first members and keeps adding the rest;
          launch notifications are sent once membership is complete.
        </div>
      )}
      {preview.distribution.length > 0 && (
        <ul aria-label="Members by owner">
          {preview.distribution.map((bucket) => (
            <li key={`${bucket.bucket}:${bucket.teamId ?? ''}`}>{ownerBucketLabel(bucket)}: {bucket.members}</li>
          ))}
        </ul>
      )}
      {excluded.length > 0 && (
        <p className="panel-caption">
          Left out: {excluded.map(([state, count]) => `${count} ${outcomeLabel(state).toLowerCase()}`).join(', ')}.
        </p>
      )}
      {preview.teamsWithoutChannel.length > 0 && (
        <div className="notice warning" role="status">
          No notification channel: {preview.teamsWithoutChannel.map((team) => team.teamName).join(', ')}. Their notifications will be recorded as skipped.
        </div>
      )}
    </>
  );
}
