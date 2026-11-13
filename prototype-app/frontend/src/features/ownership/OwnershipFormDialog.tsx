import React from 'react';
import { Dialog } from '../../components/Dialog';

type Props = {
  isOpen: boolean;
  title: string;
  description?: React.ReactNode;
  submitLabel: string;
  busy: boolean;
  busyMessage: string;
  error?: string | null;
  submitDisabled?: boolean;
  onSubmit: () => void;
  onClose: () => void;
  initialFocusRef?: React.RefObject<HTMLElement>;
  children: React.ReactNode;
};

/**
 * Form dialog for Ownership & Directory writes, built on the shared Dialog with the confirm-dialog panel. The input
 * stays mounted on a recoverable failure and dismissal is blocked while the write is pending.
 */
export function OwnershipFormDialog({
  isOpen,
  title,
  description,
  submitLabel,
  busy,
  busyMessage,
  error,
  submitDisabled = false,
  onSubmit,
  onClose,
  initialFocusRef,
  children
}: Props) {
  return (
    <Dialog
      isOpen={isOpen}
      title={title}
      onClose={onClose}
      busy={busy}
      busyMessage={busyMessage}
      initialFocusRef={initialFocusRef}
      className="confirm-dialog confirm-dialog-content ownership-dialog"
    >
      <form
        className="ownership-dialog-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (!busy && !submitDisabled) onSubmit();
        }}
      >
        {description && <div className="confirm-dialog-message">{description}</div>}
        {error && (
          <div className="notice error" role="alert">
            {error}
          </div>
        )}
        <div className="form-grid">{children}</div>
        <div className="confirm-dialog-actions">
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || submitDisabled}>
            {busy ? 'Saving…' : submitLabel}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
