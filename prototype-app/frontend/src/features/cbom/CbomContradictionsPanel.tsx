import { useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';
import { formatDate } from './labels';
import type { CbomContradiction } from './types';

type Decision = 'ACCEPTED_A' | 'ACCEPTED_B' | 'DISMISSED';

/** Open contradictions between current CBOMs for the same asset, with an analyst review decision. Hidden when none are open. */
export function CbomContradictionsPanel({ canReview }: { canReview: boolean }) {
  const client = useQueryClient();
  const query = useQuery({ queryKey: ['cbom-contradictions', 'OPEN'], queryFn: () => api.listCbomContradictions('OPEN') });
  const [reviewing, setReviewing] = React.useState<CbomContradiction | null>(null);
  const [decision, setDecision] = React.useState<Decision>('ACCEPTED_A');
  const [note, setNote] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');
  const rows = query.data ?? [];
  if (query.isError) return <div className="notice error" role="alert">Contradictions could not be loaded.</div>;
  if (rows.length === 0) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!reviewing || !note.trim()) return;
    setBusy(true);
    setError('');
    try {
      await api.reviewCbomContradiction(reviewing.id, { decision, note: note.trim(), version: reviewing.version });
      setReviewing(null);
      await client.invalidateQueries({ queryKey: ['cbom-contradictions'] });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The review could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel cbom-contradictions-panel" aria-labelledby="cbom-contradictions-heading">
      <h3 id="cbom-contradictions-heading">Contradictory evidence ({rows.length})</h3>
      <p className="panel-caption">Two current CBOMs for the same asset disagree. Both claims are marked conflicting until someone decides.</p>
      <div className="table-scroll">
        <table className="data-table">
          <thead><tr><th>Asset</th><th>Claim</th><th>Source A</th><th>Source B</th><th>Detected</th>{canReview && <th>Review</th>}</tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.assetName ?? '—'} <span className="panel-caption">{row.identity}</span></td>
                <td>{row.claim}</td>
                <td>{row.valueA ?? '—'} <span className="panel-caption">{row.documentA}</span></td>
                <td>{row.valueB ?? '—'} <span className="panel-caption">{row.documentB}</span></td>
                <td>{formatDate(row.detectedAt)}</td>
                {canReview && (
                  <td><button type="button" className="btn btn-secondary btn-sm" aria-label={`Review ${row.claim} contradiction for ${row.identity}`}
                    onClick={() => { setReviewing(row); setDecision('ACCEPTED_A'); setNote(''); setError(''); }}>Review</button></td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {reviewing && (
        <Dialog isOpen onClose={() => setReviewing(null)} title="Review contradictory evidence" busy={busy} busyMessage="Saving review…">
          <form className="crypto-campaign-form" onSubmit={(event) => void submit(event)}>
            <fieldset>
              <legend>Which source is right about {reviewing.claim}?</legend>
              <label><input type="radio" name="contradiction-decision" checked={decision === 'ACCEPTED_A'} onChange={() => setDecision('ACCEPTED_A')} />
                {' '}{reviewing.valueA} ({reviewing.documentA})</label>
              <label><input type="radio" name="contradiction-decision" checked={decision === 'ACCEPTED_B'} onChange={() => setDecision('ACCEPTED_B')} />
                {' '}{reviewing.valueB} ({reviewing.documentB})</label>
              <label><input type="radio" name="contradiction-decision" checked={decision === 'DISMISSED'} onChange={() => setDecision('DISMISSED')} />
                {' '}Not a real contradiction (dismiss)</label>
            </fieldset>
            <label>Evidence for the decision<textarea value={note} onChange={(event) => setNote(event.target.value)} rows={3} required /></label>
            {error && <div className="notice error" role="alert">{error}</div>}
            <div className="confirm-dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={() => setReviewing(null)} disabled={busy}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={busy || !note.trim()}>Save review</button>
            </div>
          </form>
        </Dialog>
      )}
    </section>
  );
}
