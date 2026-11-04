import React from 'react';
import { api } from '../../api/client';
import { Dialog } from '../../components/Dialog';

export type CryptoVerificationMode = 'REQUEST' | 'ACCEPT' | 'REJECT';

const TITLES: Record<CryptoVerificationMode, string> = {
  REQUEST: 'Request remediation verification',
  ACCEPT: 'Accept verification evidence',
  REJECT: 'Reject verification evidence',
};

/** Labelled verification form replacing browser prompts; input stays in place when the request fails. */
export function CryptoVerificationDialog({ findingId, mode, targetState, onClose, onCompleted }: {
  findingId: string;
  mode: CryptoVerificationMode | null;
  targetState?: string | null;
  onClose: () => void;
  onCompleted: (message: string) => void;
}) {
  const [target, setTarget] = React.useState('');
  const [evidence, setEvidence] = React.useState('');
  const [runId, setRunId] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    if (mode) { setTarget(''); setEvidence(''); setRunId(''); setError(''); }
  }, [mode]);

  if (!mode) return null;
  const valid = mode === 'REQUEST' ? target.trim().length > 0 : evidence.trim().length > 0 && (mode === 'REJECT' || runId.trim().length > 0);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!mode || !valid) return;
    setBusy(true);
    setError('');
    try {
      await api.updateFindingVerification(findingId, mode === 'REQUEST'
        ? { action: 'REQUEST', targetState: target.trim() }
        : { action: mode, evidence: evidence.trim(), assessmentRunId: mode === 'ACCEPT' ? runId.trim() : undefined });
      onCompleted(mode === 'REQUEST'
        ? 'Verification requested. The finding remains open until evidence is accepted.'
        : mode === 'ACCEPT' ? 'Verification accepted and finding resolved.' : 'Verification rejected; remediation remains active.');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The verification could not be saved.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog isOpen onClose={onClose} title={TITLES[mode]} busy={busy} busyMessage="Saving verification…" className="crypto-verification-dialog">
      <form onSubmit={(event) => void submit(event)} className="crypto-verification-form">
        {mode === 'REQUEST' ? (
          <label>
            Target cryptographic state
            <textarea value={target} onChange={(event) => setTarget(event.target.value)} rows={3} required autoFocus
              placeholder="For example: RSA keys rotated to 3072 bits and TLS 1.0 disabled" />
          </label>
        ) : (
          <>
            {targetState && <p className="panel-caption">Target state: {targetState}</p>}
            <label>
              Verification evidence
              <textarea value={evidence} onChange={(event) => setEvidence(event.target.value)} rows={3} required autoFocus
                placeholder="What was checked and what it showed" />
            </label>
            {mode === 'ACCEPT' && (
              <>
                <label>
                  Assessment run ID that proves the target state
                  <input value={runId} onChange={(event) => setRunId(event.target.value)} required
                    aria-describedby="crypto-verification-run-help" />
                </label>
                <span id="crypto-verification-run-help" className="panel-caption">
                  Use the assessment of the CBOM published after the fix; accepting resolves the finding.
                </span>
              </>
            )}
          </>
        )}
        {error && <div className="notice error" role="alert">{error}</div>}
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn btn-primary" disabled={busy || !valid}>
            {mode === 'REQUEST' ? 'Request verification' : mode === 'ACCEPT' ? 'Accept and resolve' : 'Reject evidence'}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
