import React from 'react';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';

/**
 * Creates a remediation campaign from selected CRYPTO findings. Plan §6.13 / Phase 0B §4.12: launch never writes an owner
 * or a free-text assignee onto the findings; owner state is read per member.
 */
export function CryptoCampaignDialog({ isOpen, findingIds, onClose, onCreated }: {
  isOpen: boolean; findingIds: string[]; onClose: () => void; onCreated: (campaign: { id: string; name: string }) => void;
}) {
  const [name, setName] = React.useState('');
  const [dueDate, setDueDate] = React.useState('');
  const [note, setNote] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    if (isOpen) { setName(''); setDueDate(''); setNote(''); setError(''); }
  }, [isOpen]);

  const valid = name.trim().length > 0;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError('');
    try {
      const response = await api.createCampaignFromFindings({
        name: name.trim(), findingIds,
        dueAt: dueDate ? new Date(`${dueDate}T23:59:59Z`).toISOString() : undefined,
        launchNote: note.trim() || undefined,
      });
      onCreated({ id: response.summary.id, name: response.summary.name });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The campaign could not be created.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen={isOpen} onClose={onClose} title="Create remediation campaign" busy={busy} busyMessage="Creating campaign…">
      <form className="crypto-campaign-form" onSubmit={(event) => void submit(event)}>
        <p className="panel-caption">{findingIds.length} selected finding{findingIds.length === 1 ? '' : 's'} will be linked to the campaign.</p>
        <label>Campaign name<input value={name} onChange={(event) => setName(event.target.value)} required autoFocus /></label>
        <label>Due date (optional)<input type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} /></label>
        <label>Launch note (optional)<textarea value={note} onChange={(event) => setNote(event.target.value)} rows={2} /></label>
        {error && <div className="notice error" role="alert">{error}</div>}
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || !valid}>Create campaign</button>
        </div>
      </form>
    </Dialog>
  );
}
