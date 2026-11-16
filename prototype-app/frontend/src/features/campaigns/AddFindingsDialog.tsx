import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';
import type { CampaignDetail } from './types';

export const MAX_ADD_FINDINGS = 500;

type SearchField = 'vulnerabilityId' | 'packageName' | 'assetName';
const FIELD_LABELS: Record<SearchField, string> = { vulnerabilityId: 'CVE ID', packageName: 'Package', assetName: 'Asset' };

/**
 * Adds existing findings to a campaign (Phase 0B §4.2, add_source MANUAL). The write is saved on the server; the
 * server answers 409 for a closed or cancelled campaign and 400 for a bad selection, and the draft stays put.
 */
export function AddFindingsDialog({ campaignId, isOpen, onClose, onAdded }: {
  campaignId: string; isOpen: boolean; onClose: () => void; onAdded: (detail: CampaignDetail) => void;
}) {
  const client = useQueryClient();
  const [field, setField] = React.useState<SearchField>('vulnerabilityId');
  const [term, setTerm] = React.useState('');
  const [submitted, setSubmitted] = React.useState<{ field: SearchField; term: string } | null>(null);
  const [selected, setSelected] = React.useState<Map<string, string>>(new Map());

  const results = useQuery({
    queryKey: ['campaign-add-findings-search', submitted],
    queryFn: () => api.listFindings({ size: 50, page: 0, [submitted!.field]: submitted!.term }),
    enabled: isOpen && submitted !== null,
  });
  const add = useMutation({
    mutationFn: () => api.addCampaignMembers(campaignId, Array.from(selected.keys())),
    onSuccess: (detail) => {
      void client.invalidateQueries({ queryKey: ['campaign-members', campaignId] });
      void client.invalidateQueries({ queryKey: ['campaign-members-panel', campaignId] });
      void client.invalidateQueries({ queryKey: ['campaign-owner-buckets', campaignId] });
      onAdded(detail);
      setSelected(new Map());
      onClose();
    },
  });

  const toggle = (id: string, label: string) => setSelected((prev) => {
    const next = new Map(prev);
    if (next.has(id)) next.delete(id); else next.set(id, label);
    return next;
  });
  const overLimit = selected.size > MAX_ADD_FINDINGS;
  const items = results.data?.items ?? [];

  return (
    <Dialog isOpen={isOpen} title="Add findings to campaign" onClose={onClose} busy={add.isPending} busyMessage="Adding findings…" className="fd3-modal cd-asset-picker-modal">
      <form
        className="cd-add-findings"
        onSubmit={(event) => { event.preventDefault(); if (term.trim()) setSubmitted({ field, term: term.trim() }); }}
      >
        <div className="button-row">
          <label>
            <span>Search by</span>
            <select value={field} onChange={(event) => setField(event.target.value as SearchField)}>
              {(Object.keys(FIELD_LABELS) as SearchField[]).map((key) => <option key={key} value={key}>{FIELD_LABELS[key]}</option>)}
            </select>
          </label>
          <label>
            <span>Search findings</span>
            <input type="search" value={term} onChange={(event) => setTerm(event.target.value)} />
          </label>
          <button type="submit" className="btn btn-secondary" disabled={term.trim() === ''}>Search</button>
        </div>
      </form>
      {submitted === null && <p className="panel-caption">Search for findings to add. Selections are kept across searches.</p>}
      {results.isPending && submitted !== null && <p className="muted" role="status">Searching…</p>}
      {results.isError && <div className="notice error" role="alert">Findings could not be searched.</div>}
      {submitted !== null && results.data && items.length === 0 && <p className="panel-caption" role="status">No findings match.</p>}
      {items.length > 0 && (
        <div className="table-scroll">
          <table className="data-table">
            <thead><tr><th><span className="ui2-sr-only">Select</span></th><th>Finding</th><th>CVE</th><th>Asset</th><th>Package</th><th>Status</th></tr></thead>
            <tbody>
              {items.map((finding) => (
                <tr key={finding.id}>
                  <td><input type="checkbox" aria-label={`Select ${finding.displayId}`} checked={selected.has(finding.id)} onChange={() => toggle(finding.id, finding.displayId)} /></td>
                  <td>{finding.displayId}</td>
                  <td>{finding.vulnerabilityId}</td>
                  <td>{finding.assetName}</td>
                  <td>{finding.packageName}</td>
                  <td>{finding.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {overLimit && <div className="notice warning" role="alert">At most {MAX_ADD_FINDINGS} findings can be added at once.</div>}
      {add.isError && <div className="notice error" role="alert">{add.error instanceof Error ? add.error.message : 'The findings could not be added.'}</div>}
      <div className="button-row">
        <span>{selected.size} selected</span>
        <button type="button" className="btn btn-secondary" disabled={add.isPending} onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={selected.size === 0 || overLimit || add.isPending} onClick={() => add.mutate()}>
          {add.isPending ? 'Adding…' : `Add ${selected.size} finding${selected.size === 1 ? '' : 's'}`}
        </button>
      </div>
    </Dialog>
  );
}
