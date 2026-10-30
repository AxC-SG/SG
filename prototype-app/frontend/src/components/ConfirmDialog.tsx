import React from 'react';
import { Dialog } from './Dialog';

type Props = {
  isOpen: boolean;
  title: string;
  message: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  confirmDisabled?: boolean;
  busy?: boolean;
  busyMessage?: string;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  confirmDisabled = false,
  busy = false,
  busyMessage,
  onConfirm,
  onCancel
}: Props) {
  const messageId = React.useId();
  return (
    <Dialog
      isOpen={isOpen}
      title={title}
      describedBy={messageId}
      onClose={onCancel}
      busy={busy}
      busyMessage={busyMessage}
      className="confirm-dialog confirm-dialog-content"
    >
      <div id={messageId} className="confirm-dialog-message">{message}</div>
      <div className="confirm-dialog-actions">
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>
          {cancelLabel}
        </button>
        <button type="button" className="btn btn-primary" disabled={confirmDisabled || busy} onClick={onConfirm}>
          {confirmLabel}
        </button>
      </div>
    </Dialog>
  );
}
