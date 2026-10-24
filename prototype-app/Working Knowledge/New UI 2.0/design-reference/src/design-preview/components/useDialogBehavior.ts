import React from 'react';

const dialogs: symbol[] = [];
const focusable = 'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]';

/** Shared by mock dialogs/drawers. Restores the exact previous background state. */
export function useDialogBehavior(open: boolean, onClose: () => void, dismissible = true) {
  const panel = React.useRef<HTMLElement | null>(null);
  const layer = React.useRef<HTMLDivElement>(null);
  const close = React.useRef(onClose);
  close.current = onClose;

  React.useLayoutEffect(() => {
    if (!open || !panel.current || !layer.current) return;
    const token = Symbol('dialog');
    dialogs.push(token);
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    const background = [...document.body.children].filter((el): el is HTMLElement => el instanceof HTMLElement && el !== layer.current);
    const original = background.map(el => ({ el, inert: el.inert, hidden: el.getAttribute('aria-hidden') }));
    background.forEach(el => { el.inert = true; el.setAttribute('aria-hidden', 'true'); });
    document.body.style.overflow = 'hidden';
    const items = () => [...(panel.current?.querySelectorAll<HTMLElement>('*') ?? [])].filter(el => el.matches(focusable) && el.tabIndex >= 0 && !el.closest('[hidden], [aria-hidden="true"]'));
    const first = () => panel.current?.querySelector<HTMLElement>('input:not(:disabled), select:not(:disabled), textarea:not(:disabled)') ?? items()[0] ?? panel.current;
    first()?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (dialogs[dialogs.length - 1] !== token) return;
      if (event.key === 'Escape' && dismissible) { event.preventDefault(); event.stopPropagation(); close.current(); }
      if (event.key === 'Tab') {
        const controls = items();
        const start = controls[0];
        const end = controls[controls.length - 1];
        if (!start) { event.preventDefault(); panel.current?.focus(); }
        else if (event.shiftKey && (document.activeElement === start || document.activeElement === panel.current)) { event.preventDefault(); end?.focus(); }
        else if (!event.shiftKey && document.activeElement === end) { event.preventDefault(); start.focus(); }
      }
    };
    const onFocus = (event: FocusEvent) => {
      if (dialogs[dialogs.length - 1] === token && !panel.current?.contains(event.target as Node)) first()?.focus();
    };
    document.addEventListener('keydown', onKey, true);
    document.addEventListener('focusin', onFocus);
    return () => {
      dialogs.splice(dialogs.indexOf(token), 1);
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('focusin', onFocus);
      original.forEach(({ el, inert, hidden }) => { el.inert = inert; if (hidden === null) el.removeAttribute('aria-hidden'); else el.setAttribute('aria-hidden', hidden); });
      document.body.style.overflow = overflow;
      if (previous?.isConnected) previous.focus();
    };
  }, [open, dismissible]);
  return { panel, layer };
}
