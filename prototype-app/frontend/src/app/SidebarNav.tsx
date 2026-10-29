import React from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, ChevronUp, type LucideIcon } from 'lucide-react';

export type NavChild = { key: string; label: string; to: string; active: boolean };
export type NavItem = { key: string; label: string; to: string; icon: LucideIcon; active: boolean; children?: NavChild[] };
// A heading only labels its group; it is never a control.
export type NavGroup = { key: string; heading?: string; items: NavItem[] };
export type NavSection = { key: string; className: string; groups: NavGroup[] };

export function SidebarNav({ sections }: { sections: NavSection[] }) {
  const [expanded, setExpanded] = React.useState<Record<string, boolean>>({});
  const idPrefix = React.useId();
  const toggle = (key: string) => setExpanded((current) => ({ ...current, [key]: !current[key] }));

  const renderItem = (item: NavItem) => {
    const Icon = item.icon;
    const open = expanded[item.key] ?? false;
    const listId = `${idPrefix}-${item.key}-sections`;
    const visibleChildActive = open && (item.children?.some((child) => child.active) ?? false);
    return (
      <React.Fragment key={item.key}>
        <div className={item.active ? 'nav-btn active' : 'nav-btn'}>
          <Link
            to={item.to}
            className="nav-destination"
            aria-current={item.active ? (visibleChildActive ? 'true' : 'page') : undefined}
          >
            <Icon className="nav-icon" aria-hidden="true" />
            <span className="nav-label">{item.label}</span>
          </Link>
          {item.children && (
            <button
              type="button"
              className="nav-expand-toggle"
              aria-expanded={open}
              aria-controls={listId}
              aria-label={open ? `Collapse ${item.label} sections` : `Expand ${item.label} sections`}
              onClick={() => toggle(item.key)}
            >
              {open ? <ChevronUp aria-hidden="true" /> : <ChevronDown aria-hidden="true" />}
            </button>
          )}
        </div>
        {item.children && (
          <div className="nav-sub-list" id={listId} hidden={!open}>
            {item.children.map((child) => (
              <Link
                key={child.key}
                to={child.to}
                className={child.active ? 'nav-sub-btn active' : 'nav-sub-btn'}
                aria-current={child.active ? 'page' : undefined}
              >
                {child.label}
              </Link>
            ))}
          </div>
        )}
      </React.Fragment>
    );
  };

  return (
    <nav className="sidebar-nav" aria-label="Primary">
      {sections.map((section) => {
        const groups = section.groups.filter((group) => group.items.length > 0);
        if (groups.length === 0) return null;
        return (
          <div key={section.key} className={section.className}>
            {groups.map((group) => {
              const headingId = `${idPrefix}-${group.key}-heading`;
              return (
                <div
                  key={group.key}
                  className="nav-group"
                  role={group.heading ? 'group' : undefined}
                  aria-labelledby={group.heading ? headingId : undefined}
                >
                  {group.heading && <div className="nav-group-heading" id={headingId}>{group.heading}</div>}
                  {group.items.map(renderItem)}
                </div>
              );
            })}
          </div>
        );
      })}
    </nav>
  );
}
