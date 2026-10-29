import React from 'react';

type AccountMenuProps = {
  id: string;
  open: boolean;
  onClose: () => void;
  // Elements that toggle the menu themselves; a press on them is not an outside click.
  triggers: Array<React.RefObject<HTMLElement | null>>;
  header: React.ReactNode;
  children: React.ReactNode;
};

const ITEM_SELECTOR = '[role="menuitem"]:not([disabled])';

// Menu-button popover: focus moves to the first item on open; arrows/Home/End move between
// items; Escape returns focus to the trigger that opened it; Tab or an outside press closes it.
export function AccountMenu({ id, open, onClose, triggers, header, children }: AccountMenuProps) {
  const menuRef = React.useRef<HTMLDivElement>(null);
  const returnFocusRef = React.useRef<HTMLElement | null>(null);
  const triggersRef = React.useRef(triggers);
  React.useLayoutEffect(() => {
    triggersRef.current = triggers;
  });

  React.useLayoutEffect(() => {
    if (!open) return undefined;
    returnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    menuRef.current?.querySelector<HTMLElement>(ITEM_SELECTOR)?.focus();
    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (menuRef.current?.contains(target)) return;
      if (triggersRef.current.some((trigger) => trigger.current?.contains(target))) return;
      onClose();
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open, onClose]);

  if (!open) return null;

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    const items = [...(menuRef.current?.querySelectorAll<HTMLElement>(ITEM_SELECTOR) ?? [])];
    const index = items.indexOf(document.activeElement as HTMLElement);
    const focusAt = (next: number) => {
      event.preventDefault();
      items[(next + items.length) % items.length]?.focus();
    };
    if (event.key === 'ArrowDown') focusAt(index + 1);
    else if (event.key === 'ArrowUp') focusAt(index < 0 ? items.length - 1 : index - 1);
    else if (event.key === 'Home') focusAt(0);
    else if (event.key === 'End') focusAt(items.length - 1);
    else if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      returnFocusRef.current?.focus();
    } else if (event.key === 'Tab') {
      onClose();
    }
  };

  return (
    <div className="settings-menu" ref={menuRef} onKeyDown={onKeyDown}>
      <div className="settings-menu-header">{header}</div>
      <div className="settings-menu-items" id={id} role="menu" aria-label="Account">{children}</div>
    </div>
  );
}
