import React from 'react';

type InventoryShellProps = {
  title: string;
  eyebrow?: string;
  description?: string;
  actions?: React.ReactNode;
  legacyClassName?: string;
  children: React.ReactNode;
};

export function InventoryShell({
  title,
  eyebrow,
  description,
  actions,
  legacyClassName,
  children
}: InventoryShellProps) {
  const className = ['inventory-shell', legacyClassName].filter(Boolean).join(' ');
  return (
    <section className={className}>
      <header className="inventory-shell-header">
        <div className="inventory-shell-heading">
          {eyebrow ? <span className="inventory-shell-eyebrow">{eyebrow}</span> : null}
          <h1 className="inventory-shell-title">{title}</h1>
          {description ? <p className="inventory-shell-description">{description}</p> : null}
        </div>
        {actions ? <div className="inventory-shell-actions">{actions}</div> : null}
      </header>
      <div className="inventory-shell-body">
        {children}
      </div>
    </section>
  );
}
