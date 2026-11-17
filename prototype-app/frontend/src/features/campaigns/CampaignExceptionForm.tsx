import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import type { CampaignException } from './types';

/**
 * Requests a campaign exception for one member finding (Phase 0B §4.7). The finding is chosen from the campaign's
 * members, never typed as a display ID. The exception stays inside the campaign and does not change the finding.
 */
export function CampaignExceptionForm({ campaignId, onCreated }: { campaignId: string; onCreated: (exception: CampaignException) => void }) {
  const client = useQueryClient();
  const [findingId, setFindingId] = React.useState('');
  const [title, setTitle] = React.useState('');
  const [reason, setReason] = React.useState('');
  const [decisionDueAt, setDecisionDueAt] = React.useState('');
  const members = useQuery({
    queryKey: ['campaign-exception-members', campaignId],
    queryFn: () => api.listCampaignMembers(campaignId, { limit: 200 }),
  });
  const create = useMutation({
    mutationFn: () => api.addCampaignException(campaignId, {
      findingId, title: title.trim(), reason: reason.trim(), decisionDueAt: decisionDueAt ? new Date(decisionDueAt).toISOString() : null,
    }),
    onSuccess: (exception) => {
      setFindingId(''); setTitle(''); setReason(''); setDecisionDueAt('');
      void client.invalidateQueries({ queryKey: ['campaign-members', campaignId] });
      onCreated(exception);
    },
  });
  const items = members.data?.items ?? [];

  return (
    <form
      className="panel"
      aria-label="Request campaign exception"
      onSubmit={(event) => { event.preventDefault(); create.mutate(); }}
    >
      <h3>Request an exception</h3>
      <p className="panel-caption">Campaign-only exception, does not change the finding. To suppress or accept the risk on the finding itself, use the finding's own exception action.</p>
      {members.isError && <div className="notice error" role="alert">Campaign members could not be loaded.</div>}
      <label>
        <span>Member finding</span>
        <select required value={findingId} onChange={(event) => setFindingId(event.target.value)} disabled={members.isPending}>
          <option value="">Choose a member finding</option>
          {items.map((member) => <option key={member.findingId} value={member.findingId}>{member.displayId}{member.title ? ` · ${member.title}` : ''}</option>)}
        </select>
      </label>
      {members.data?.nextCursor && <p className="panel-caption">Showing the first {items.length} members.</p>}
      <label><span>Title</span><input required value={title} onChange={(event) => setTitle(event.target.value)} /></label>
      <label><span>Reason</span><textarea required value={reason} onChange={(event) => setReason(event.target.value)} /></label>
      <label><span>Decision due (optional)</span><input type="date" value={decisionDueAt} onChange={(event) => setDecisionDueAt(event.target.value)} /></label>
      {create.isError && <div className="notice error" role="alert">{create.error instanceof Error ? create.error.message : 'The exception could not be requested.'}</div>}
      <button type="submit" className="btn btn-primary" disabled={create.isPending || findingId === '' || title.trim() === '' || reason.trim() === ''}>
        {create.isPending ? 'Requesting…' : 'Request exception'}
      </button>
    </form>
  );
}
