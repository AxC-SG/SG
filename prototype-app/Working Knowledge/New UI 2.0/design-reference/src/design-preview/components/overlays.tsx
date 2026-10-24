import React from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { useDialogBehavior } from './useDialogBehavior';

/**
 * Modal dialog. Replaces `.fd3-modal`, `.modal`, ConfirmDialog visuals.
 * role="dialog" + aria-modal + aria-labelledby so getByRole('dialog', { name }) works.
 * Escape and scrim click close only when the call site allows it today.
 */
export function Modal({ open, onClose, title, description, children, footer, size = 'md', dismissible = true }: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  size?: 'sm' | 'md' | 'lg';
  dismissible?: boolean;
}) {
  const titleId = React.useId();
  const { panel, layer } = useDialogBehavior(open, onClose, dismissible);

  if (!open) return null;
  return createPortal(
    <div className="dp-modal-root" ref={layer}>
      <div className="dp-scrim visible" onClick={dismissible ? onClose : undefined} />
      <div ref={el => { panel.current = el; }} tabIndex={-1} className={`dp-modal dp-modal--${size}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <header className="dp-modal-header">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description ? <p>{description}</p> : null}
          </div>
          {dismissible ? <button type="button" data-dp-close className="dp-icon-btn sm" onClick={onClose} aria-label="Close"><X size={14} /></button> : null}
        </header>
        {children ? <div className="dp-modal-body">{children}</div> : null}
        {footer ? <footer className="dp-modal-footer">{footer}</footer> : null}
      </div>
    </div>, document.body
  );
}

/** Destructive confirmation. Optional type-to-confirm; keeps confirm/cancel button labels caller-defined. */
export function ConfirmDialog({ open, onCancel, onConfirm, title, body, confirmLabel, requireText }: {
  open: boolean;
  onCancel: () => void;
  onConfirm: () => void;
  title: string;
  body: React.ReactNode;
  confirmLabel: string;
  requireText?: string;
}) {
  const [typed, setTyped] = React.useState('');
  React.useEffect(() => { if (open) setTyped(''); }, [open]);
  const blocked = requireText !== undefined && typed !== requireText;
  return (
    <Modal
      open={open}
      onClose={onCancel}
      title={title}
      size="sm"
      footer={(
        <>
          <button type="button" className="dp-btn" onClick={onCancel}>Cancel</button>
          <button type="button" className="dp-btn dp-btn--danger" disabled={blocked} onClick={onConfirm}>{confirmLabel}</button>
        </>
      )}
    >
      <div className="dp-confirm-body">{body}</div>
      {requireText !== undefined ? (
        <label className="dp-confirm-type">
          <span>Type <code>{requireText}</code> to confirm</span>
          <input className="dp-input" value={typed} onChange={(e) => setTyped(e.target.value)} aria-label={`Type ${requireText} to confirm`} />
        </label>
      ) : null}
    </Modal>
  );
}

/** Hover/focus tooltip. Replaces InfoTooltip/MetricInfoIcon visuals; content stays in the DOM via aria-describedby. */
export function Tooltip({ content, children }: { content: React.ReactNode; children: React.ReactElement }) {
  const id = React.useId();
  const [open, setOpen] = React.useState(false);
  return (
    <span className="dp-tooltip-anchor" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)} onFocus={() => setOpen(true)} onBlur={() => setOpen(false)}>
      {React.cloneElement(children, { 'aria-describedby': id } as React.HTMLAttributes<HTMLElement>)}
      <span id={id} role="tooltip" className={`dp-tooltip-bubble${open ? ' open' : ''}`}>{content}</span>
    </span>
  );
}

/** Action menu (role="menu"). Use only to style menus that already exist (e.g. Findings "More actions"). */
export function Menu({ items }: {
  items: Array<{ label: string; onSelect: () => void; disabled?: boolean; danger?: boolean; icon?: React.ReactNode } | 'separator'>;
}) {
  return (
    <div role="menu" className="dp-menu" onKeyDown={event => {
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
      const items = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
      const current = items.indexOf(document.activeElement as HTMLButtonElement);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
      event.preventDefault(); items[next]?.focus();
    }}>
      {items.map((item, index) => item === 'separator' ? <div key={`sep-${index}`} className="dp-menu-sep" /> : (
        <button
          key={item.label}
          type="button"
          role="menuitem"
          disabled={item.disabled}
          className={`dp-menu-item${item.danger ? ' danger' : ''}`}
          onClick={item.onSelect}
        >
          {item.icon}
          {item.label}
        </button>
      ))}
    </div>
  );
}
