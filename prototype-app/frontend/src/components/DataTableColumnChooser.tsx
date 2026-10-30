import React from 'react';
import type { ColumnPriority, VisibilityOverride } from './dataTablePreferences';

export type ChooserColumn = { id: string; label: string; priority?: ColumnPriority };

type Props = {
  columns: ChooserColumn[];
  visibility: Record<string, boolean>;
  overrides: Record<string, VisibilityOverride>;
  onToggle: (id: string) => void;
  onUseDefault: (id: string) => void;
  onMove: (id: string, offset: -1 | 1) => void;
  onReset: () => void;
};

// A labelled popover with real checkboxes (not a menu role around non-menu children).
export function DataTableColumnChooser({ columns, visibility, overrides, onToggle, onUseDefault, onMove, onReset }: Props) {
  const [open, setOpen] = React.useState(false);
  const rootRef = React.useRef<HTMLDivElement>(null);
  const buttonRef = React.useRef<HTMLButtonElement>(null);
  const popoverId = React.useId();
  const titleId = React.useId();
  const essentialNoteId = React.useId();

  React.useEffect(() => {
    if (!open) return undefined;
    const onPointerDown = (event: MouseEvent): void => {
      if (event.target instanceof Node && rootRef.current?.contains(event.target)) return;
      setOpen(false);
    };
    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [open]);

  React.useEffect(() => {
    if (open) rootRef.current?.querySelector<HTMLInputElement>('input:not([disabled])')?.focus();
  }, [open]);

  const visibleIds = columns.filter((column) => visibility[column.id]).map((column) => column.id);

  return (
    <div
      className="table-column-controls"
      ref={rootRef}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.stopPropagation();
          setOpen(false);
          buttonRef.current?.focus();
        }
      }}
    >
      <button
        ref={buttonRef}
        type="button"
        className="table-settings-btn"
        onClick={() => setOpen((current) => !current)}
        aria-label="Show or hide columns"
        aria-expanded={open}
        aria-controls={open ? popoverId : undefined}
        title="Show or hide columns"
        disabled={columns.length === 0}
      >
        ⚙
      </button>
      {open && columns.length > 0 && (
        <div id={popoverId} className="table-settings-menu" role="group" aria-labelledby={titleId}>
          <div id={titleId} className="table-settings-title">Columns</div>
          <p id={essentialNoteId} className="table-settings-note">Identity and action columns are always shown.</p>
          <ul className="table-settings-list">
            {columns.map((column) => {
              const essential = column.priority === 'essential';
              const isVisible = visibility[column.id];
              const visibleIndex = visibleIds.indexOf(column.id);
              const override = overrides[column.id];
              return (
                <li key={column.id} className="table-settings-item">
                  <label className="table-settings-toggle">
                    <input
                      type="checkbox"
                      checked={isVisible}
                      onChange={() => onToggle(column.id)}
                      disabled={essential || (isVisible && visibleIds.length <= 1)}
                      aria-describedby={essential ? essentialNoteId : undefined}
                    />
                    <span>{column.label}</span>
                  </label>
                  <span className="table-settings-actions">
                    {override && !essential && (
                      <button type="button" className="table-settings-action" onClick={() => onUseDefault(column.id)} aria-label={`Use default visibility for ${column.label}`}>
                        Use default
                      </button>
                    )}
                    <button
                      type="button"
                      className="table-settings-action"
                      onClick={() => onMove(column.id, -1)}
                      disabled={!isVisible || visibleIndex <= 0}
                      aria-label={`Move ${column.label} left`}
                    >
                      ←
                    </button>
                    <button
                      type="button"
                      className="table-settings-action"
                      onClick={() => onMove(column.id, 1)}
                      disabled={!isVisible || visibleIndex < 0 || visibleIndex >= visibleIds.length - 1}
                      aria-label={`Move ${column.label} right`}
                    >
                      →
                    </button>
                  </span>
                </li>
              );
            })}
          </ul>
          <button type="button" className="btn btn-secondary btn-sm table-settings-reset" onClick={onReset}>
            Reset columns
          </button>
        </div>
      )}
    </div>
  );
}
