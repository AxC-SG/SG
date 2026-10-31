import React from 'react';

// One native modal for every dialog. The <dialog> element is the full-viewport scrim; children are the panel.
// The feature decides whether closing is safe and owns validation and mutation outcomes.
type NameProps =
  | { title: string; labelledBy?: never }
  | { labelledBy: string; title?: never };

type Props = NameProps & {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  describedBy?: string;
  // A pending non-cancellable write blocks Escape and backdrop dismissal and says why.
  busy?: boolean;
  busyMessage?: string;
  initialFocusRef?: React.RefObject<HTMLElement>;
  closeOnBackdrop?: boolean;
  className?: string;
};

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableIn(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter((node) => !node.closest('[hidden]'));
}

export function Dialog(props: Props) {
  // The surface mounts once per opening, so it can record where focus was before any autofocus inside it runs.
  return props.isOpen ? <DialogSurface {...props} /> : null;
}

function DialogSurface({
  onClose,
  children,
  title,
  labelledBy,
  describedBy,
  busy = false,
  busyMessage = 'Saving… this dialog can be closed when the request finishes.',
  initialFocusRef,
  closeOnBackdrop = true,
  className,
}: Props) {
  const dialogRef = React.useRef<HTMLDialogElement>(null);
  const titleId = React.useId();
  const [returnTarget] = React.useState(() => (document.activeElement instanceof HTMLElement ? document.activeElement : null));

  React.useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return undefined;
    if (!dialog.open) {
      if (typeof dialog.showModal === 'function') {
        dialog.showModal();
      } else {
        dialog.setAttribute('open', '');
      }
    }
    // A field the feature autofocuses keeps focus; otherwise use the requested or first control.
    if (!dialog.contains(document.activeElement)) {
      (initialFocusRef?.current ?? focusableIn(dialog)[0] ?? dialog).focus();
    }
    return () => {
      if (dialog.open && typeof dialog.close === 'function') dialog.close();
      if (returnTarget?.isConnected) returnTarget.focus();
    };
    // Focus entry runs once per opening; a changing ref object must not move focus mid-edit.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function requestClose(): void {
    if (!busy) onClose();
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLDialogElement>): void {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (event.key === 'Escape') {
      // Cancelling the keydown also stops the native close request, so this is the only close path for Escape.
      event.preventDefault();
      event.stopPropagation();
      requestClose();
      return;
    }
    if (event.key !== 'Tab') return;
    const nodes = focusableIn(dialog);
    if (nodes.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || active === dialog)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="ui2-dialog"
      aria-labelledby={labelledBy ?? titleId}
      aria-describedby={describedBy}
      aria-busy={busy || undefined}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
      onCancel={(event) => {
        // Other close requests (e.g. a platform back gesture) still respect the busy state.
        event.preventDefault();
        requestClose();
      }}
      onClick={(event) => {
        if (closeOnBackdrop && event.target === dialogRef.current) requestClose();
      }}
    >
      <div className={className}>
        {title != null && <h2 id={titleId} className="ui2-dialog-title">{title}</h2>}
        {children}
        {busy && <p className="ui2-dialog-busy" role="status">{busyMessage}</p>}
      </div>
    </dialog>
  );
}
