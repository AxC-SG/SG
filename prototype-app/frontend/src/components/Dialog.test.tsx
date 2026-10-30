import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ConfirmDialog } from './ConfirmDialog';
import { Dialog } from './Dialog';

function Harness({ busy = false, onClose }: { busy?: boolean; onClose?: () => void }) {
  const [open, setOpen] = React.useState(false);
  const close = () => {
    onClose?.();
    setOpen(false);
  };
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>Open</button>
      <Dialog isOpen={open} title="Edit owner" onClose={close} busy={busy}>
        <input aria-label="Owner" />
        <button type="button" onClick={close}>Done</button>
      </Dialog>
    </>
  );
}

describe('Dialog', () => {
  it('is named by its title, focuses the first control and returns focus on close', () => {
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open' });
    trigger.focus();
    fireEvent.click(trigger);

    expect(screen.getByRole('dialog', { name: 'Edit owner' })).toBeInTheDocument();
    expect(screen.getByLabelText('Owner')).toHaveFocus();

    fireEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('keeps Tab and Shift+Tab inside the dialog', () => {
    render(<Harness />);
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));

    const done = screen.getByRole('button', { name: 'Done' });
    done.focus();
    fireEvent.keyDown(done, { key: 'Tab' });
    expect(screen.getByLabelText('Owner')).toHaveFocus();
    fireEvent.keyDown(screen.getByLabelText('Owner'), { key: 'Tab', shiftKey: true });
    expect(done).toHaveFocus();
  });

  it('closes on Escape and backdrop press, and reopens repeatedly', () => {
    const onClose = vi.fn();
    render(<Harness onClose={onClose} />);

    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    fireEvent.click(screen.getByRole('dialog'));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Open' }));
    expect(screen.getByRole('dialog', { name: 'Edit owner' })).toBeInTheDocument();
    expect(onClose).toHaveBeenCalledTimes(2);
  });

  it('blocks Escape, backdrop and cancel while busy and explains why', () => {
    const onClose = vi.fn();
    render(<Harness busy onClose={onClose} />);
    fireEvent.click(screen.getByRole('button', { name: 'Open' }));

    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    fireEvent.click(screen.getByRole('dialog'));
    fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));

    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByRole('status')).toHaveTextContent(/can be closed when the request finishes/);
  });

  it('can be named by a heading the feature renders itself', () => {
    render(
      <Dialog isOpen labelledBy="custom-title" onClose={() => undefined}>
        <h3 id="custom-title">Add assets</h3>
      </Dialog>
    );
    expect(screen.getByRole('dialog', { name: 'Add assets' })).toBeInTheDocument();
  });
});

describe('ConfirmDialog', () => {
  it('describes the dialog with its message and disables both actions while busy', () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const { rerender } = render(
      <ConfirmDialog isOpen title="Block tenant access?" message="Tenant data will be retained." confirmLabel="Block Access" onConfirm={onConfirm} onCancel={onCancel} />
    );
    const dialog = screen.getByRole('dialog', { name: 'Block tenant access?' });
    expect(dialog).toHaveAccessibleDescription('Tenant data will be retained.');
    expect(screen.getByRole('button', { name: 'Cancel' })).toHaveFocus();

    rerender(
      <ConfirmDialog isOpen busy title="Block tenant access?" message="Tenant data will be retained." confirmLabel="Updating..." onConfirm={onConfirm} onCancel={onCancel} />
    );
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Updating...' })).toBeDisabled();
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(onCancel).not.toHaveBeenCalled();
  });
});
