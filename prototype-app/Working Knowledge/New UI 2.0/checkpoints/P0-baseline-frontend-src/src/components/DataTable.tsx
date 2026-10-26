import React from 'react';
import {
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnSizingState,
  type VisibilityState,
} from '@tanstack/react-table';
import './DataTable.css';

export type DataTableColumn = {
  id: string;
  label: string;
  header: React.ReactNode;
  headerProps?: Omit<React.ThHTMLAttributes<HTMLTableCellElement>, 'children'>;
  initialSize?: number;
  defaultHidden?: boolean;
};

export type DataTableCell = {
  content: React.ReactNode;
  props?: Omit<React.TdHTMLAttributes<HTMLTableCellElement>, 'children'>;
};

export type DataTableRow = {
  id: string;
  rowProps?: Omit<React.HTMLAttributes<HTMLTableRowElement>, 'children'>;
  cells: Record<string, DataTableCell>;
};

type DataTableProps = {
  storageKey: string;
  columns: DataTableColumn[];
  rows: DataTableRow[];
  minColumnWidth?: number;
  showColumnControls?: boolean;
};

const ORDER_KEY_SUFFIX = ':order';
const HIDDEN_KEY_SUFFIX = ':hidden';

function classNames(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

function serializeStoredIds(ids: Iterable<string>): Array<number | string> {
  return Array.from(ids).map((id) => {
    const numeric = Number(id);
    return Number.isInteger(numeric) && String(numeric) === id ? numeric : id;
  });
}

function readStoredWidths(storageKey: string): ColumnSizingState {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return {};
    }

    const next: ColumnSizingState = {};
    Object.entries(parsed).forEach(([key, value]) => {
      const numeric = Number(value);
      if (Number.isFinite(numeric) && numeric > 0) {
        next[String(key)] = Math.round(numeric);
      }
    });
    return next;
  } catch {
    return {};
  }
}

function writeStoredWidths(storageKey: string, widths: ColumnSizingState): void {
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(widths));
  } catch {
    // no-op for storage failures
  }
}

function readStoredOrder(storageKey: string): string[] | null {
  try {
    const raw = window.localStorage.getItem(`${storageKey}${ORDER_KEY_SUFFIX}`);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return null;
    const order = parsed
      .map((value) => String(value))
      .filter((value) => value.length > 0);
    return order.length > 0 ? order : null;
  } catch {
    return null;
  }
}

function writeStoredOrder(storageKey: string, order: string[]): void {
  try {
    window.localStorage.setItem(`${storageKey}${ORDER_KEY_SUFFIX}`, JSON.stringify(serializeStoredIds(order)));
  } catch {
    // no-op for storage failures
  }
}

function readStoredHidden(storageKey: string): Set<string> {
  try {
    const raw = window.localStorage.getItem(`${storageKey}${HIDDEN_KEY_SUFFIX}`);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.map((value) => String(value)).filter((value) => value.length > 0));
  } catch {
    return new Set();
  }
}

function hasStoredHiddenPreference(storageKey: string): boolean {
  try {
    return window.localStorage.getItem(`${storageKey}${HIDDEN_KEY_SUFFIX}`) != null;
  } catch {
    return false;
  }
}

function writeStoredHidden(storageKey: string, hiddenColumns: Set<string>): void {
  try {
    window.localStorage.setItem(
      `${storageKey}${HIDDEN_KEY_SUFFIX}`,
      JSON.stringify(serializeStoredIds(Array.from(hiddenColumns).sort()))
    );
  } catch {
    // no-op for storage failures
  }
}

function arraysEqual(left: string[], right: string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  return left.every((value, index) => value === right[index]);
}

function visibilityEqual(left: VisibilityState, right: VisibilityState): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (!arraysEqual(leftKeys, rightKeys)) {
    return false;
  }
  return leftKeys.every((key) => left[key] === right[key]);
}

function sizingEqual(left: ColumnSizingState, right: ColumnSizingState): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (!arraysEqual(leftKeys, rightKeys)) {
    return false;
  }
  return leftKeys.every((key) => Math.round(left[key] ?? 0) === Math.round(right[key] ?? 0));
}

function initialColumnOrder(storageKey: string, columns: DataTableColumn[]): string[] {
  const currentIds = columns.map((column) => column.id);
  const stored = readStoredOrder(storageKey);
  if (!stored) {
    return currentIds;
  }

  const validIds = new Set(currentIds);
  const next = stored.filter((id) => validIds.has(id));
  currentIds.forEach((id) => {
    if (!next.includes(id)) {
      next.push(id);
    }
  });
  return next;
}

function reconcileColumnOrder(order: string[], columns: DataTableColumn[]): string[] {
  const currentIds = columns.map((column) => column.id);
  const validIds = new Set(currentIds);
  const next = order.filter((id) => validIds.has(id));
  currentIds.forEach((id) => {
    if (!next.includes(id)) {
      next.push(id);
    }
  });
  return next;
}

function buildVisibilityState(storageKey: string, columns: DataTableColumn[]): VisibilityState {
  const storedHidden = readStoredHidden(storageKey);
  const hasStoredPreference = hasStoredHiddenPreference(storageKey);
  const next: VisibilityState = {};
  columns.forEach((column) => {
    next[column.id] = hasStoredPreference ? !storedHidden.has(column.id) : !column.defaultHidden;
  });

  if (columns.length > 0 && columns.every((column) => next[column.id] === false)) {
    next[columns[0].id] = true;
  }
  return next;
}

function reconcileVisibilityState(
  current: VisibilityState,
  storageKey: string,
  columns: DataTableColumn[]
): VisibilityState {
  const fallback = buildVisibilityState(storageKey, columns);
  const next: VisibilityState = {};
  columns.forEach((column) => {
    next[column.id] = column.id in current ? current[column.id] !== false : fallback[column.id] !== false;
  });

  if (columns.length > 0 && columns.every((column) => next[column.id] === false)) {
    next[columns[0].id] = true;
  }
  return next;
}

function buildBaseColumnSizing(
  columns: DataTableColumn[],
  minColumnWidth: number,
  basis: ColumnSizingState
): ColumnSizingState {
  const next: ColumnSizingState = {};
  columns.forEach((column) => {
    const raw = basis[column.id] ?? column.initialSize;
    if (raw != null && Number.isFinite(raw) && raw > 0) {
      next[column.id] = Math.max(minColumnWidth, Math.round(raw));
    }
  });
  return next;
}

function rebalanceColumnSizing(
  columns: DataTableColumn[],
  columnVisibility: VisibilityState,
  basis: ColumnSizingState,
  containerWidth: number,
  minColumnWidth: number
): ColumnSizingState {
  const visibleColumns = columns.filter((column) => columnVisibility[column.id] !== false);
  if (visibleColumns.length === 0) {
    return basis;
  }

  const next = { ...basis };
  const visibleBasisTotal = visibleColumns.reduce((sum, column) => {
    const width = basis[column.id] ?? column.initialSize ?? minColumnWidth;
    return sum + width;
  }, 0);
  const targetTotal = Math.max(1, Math.floor(containerWidth > 0 ? containerWidth : visibleBasisTotal));
  const perColumnBudget = Math.max(1, Math.floor(targetTotal / visibleColumns.length));
  const effectiveMinWidth = Math.max(1, Math.min(minColumnWidth, perColumnBudget));
  const fallbackWidth = perColumnBudget;

  const basisWidths = visibleColumns.map((column) => {
    const width = basis[column.id] ?? column.initialSize ?? fallbackWidth;
    return Math.max(1, Math.round(width));
  });

  const basisTotal = basisWidths.reduce((sum, width) => sum + width, 0);
  const safeBasisTotal = basisTotal > 0 ? basisTotal : fallbackWidth * visibleColumns.length;
  const scale = targetTotal / safeBasisTotal;

  const scaled = basisWidths.map((width) => Math.max(effectiveMinWidth, Math.floor(width * scale)));
  let scaledTotal = scaled.reduce((sum, width) => sum + width, 0);

  if (scaledTotal > targetTotal) {
    let overflow = scaledTotal - targetTotal;
    while (overflow > 0) {
      let reduced = false;
      for (let index = scaled.length - 1; index >= 0 && overflow > 0; index -= 1) {
        if (scaled[index] > effectiveMinWidth) {
          scaled[index] -= 1;
          overflow -= 1;
          reduced = true;
        }
      }
      if (!reduced) {
        break;
      }
    }
    scaledTotal = scaled.reduce((sum, width) => sum + width, 0);
  }

  if (scaledTotal < targetTotal) {
    let remaining = targetTotal - scaledTotal;
    let index = 0;
    while (remaining > 0) {
      scaled[index % scaled.length] += 1;
      remaining -= 1;
      index += 1;
    }
  }

  const finalTotal = scaled.reduce((sum, width) => sum + width, 0);
  if (finalTotal > targetTotal) {
    const lastIndex = scaled.length - 1;
    scaled[lastIndex] = Math.max(1, scaled[lastIndex] - (finalTotal - targetTotal));
  }

  visibleColumns.forEach((column, index) => {
    next[column.id] = scaled[index];
  });
  return next;
}

function mergeWidthStyle(size: number, style?: React.CSSProperties): React.CSSProperties {
  return {
    ...style,
    width: `${size}px`,
    minWidth: `${size}px`,
    maxWidth: `${size}px`,
  };
}

function moveColumn(order: string[], sourceId: string, targetId: string): string[] {
  const fromIndex = order.indexOf(sourceId);
  const toIndex = order.indexOf(targetId);
  if (fromIndex < 0 || toIndex < 0 || fromIndex === toIndex) {
    return order;
  }

  const next = [...order];
  const [moved] = next.splice(fromIndex, 1);
  next.splice(toIndex, 0, moved);
  return next;
}

function useContainerWidth(ref: React.RefObject<HTMLDivElement>): number {
  const [width, setWidth] = React.useState(0);

  React.useEffect(() => {
    const node = ref.current;
    if (!node) {
      return;
    }

    const measure = () => {
      const next = Math.round(node.getBoundingClientRect().width);
      setWidth((current) => (current === next ? current : next));
    };

    measure();

    if (typeof ResizeObserver !== 'undefined') {
      const observer = new ResizeObserver(() => measure());
      observer.observe(node);
      return () => observer.disconnect();
    }

    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [ref]);

  return width;
}

export function DataTable({
  storageKey,
  columns,
  rows,
  minColumnWidth = 96,
  showColumnControls = true,
}: DataTableProps) {
  const wrapperRef = React.useRef<HTMLDivElement | null>(null);
  const containerWidth = useContainerWidth(wrapperRef);
  const [menuOpen, setMenuOpen] = React.useState(false);
  const [draggedColumnId, setDraggedColumnId] = React.useState<string | null>(null);
  const [dropTargetId, setDropTargetId] = React.useState<string | null>(null);
  const [columnOrder, setColumnOrder] = React.useState<string[]>(() => initialColumnOrder(storageKey, columns));
  const [columnVisibility, setColumnVisibility] = React.useState<VisibilityState>(() => buildVisibilityState(storageKey, columns));
  const [columnSizing, setColumnSizing] = React.useState<ColumnSizingState>(() => (
    buildBaseColumnSizing(columns, minColumnWidth, readStoredWidths(storageKey))
  ));

  React.useEffect(() => {
    const onPointerDown = (event: MouseEvent): void => {
      if (!menuOpen) {
        return;
      }
      const target = event.target as Node | null;
      if (!target || wrapperRef.current?.contains(target)) {
        return;
      }
      setMenuOpen(false);
    };

    document.addEventListener('mousedown', onPointerDown);
    return () => document.removeEventListener('mousedown', onPointerDown);
  }, [menuOpen]);

  React.useEffect(() => {
    setColumnOrder((current) => {
      const next = reconcileColumnOrder(current, columns);
      return arraysEqual(current, next) ? current : next;
    });
  }, [columns]);

  React.useEffect(() => {
    setColumnVisibility((current) => {
      const next = reconcileVisibilityState(current, storageKey, columns);
      return visibilityEqual(current, next) ? current : next;
    });
  }, [columns, storageKey]);

  React.useEffect(() => {
    setColumnSizing((current) => {
      const stored = readStoredWidths(storageKey);
      const next = buildBaseColumnSizing(columns, minColumnWidth, { ...stored, ...current });
      return sizingEqual(current, next) ? current : next;
    });
  }, [columns, minColumnWidth, storageKey]);

  React.useEffect(() => {
    if (containerWidth <= 0) {
      return;
    }
    setColumnSizing((current) => {
      const next = rebalanceColumnSizing(columns, columnVisibility, current, containerWidth, minColumnWidth);
      return sizingEqual(current, next) ? current : next;
    });
  }, [columnVisibility, columns, containerWidth, minColumnWidth]);

  React.useEffect(() => {
    writeStoredOrder(storageKey, columnOrder);
  }, [columnOrder, storageKey]);

  React.useEffect(() => {
    const hidden = new Set(
      columns
        .filter((column) => columnVisibility[column.id] === false)
        .map((column) => column.id)
    );
    writeStoredHidden(storageKey, hidden);
  }, [columnVisibility, columns, storageKey]);

  React.useEffect(() => {
    writeStoredWidths(storageKey, columnSizing);
  }, [columnSizing, storageKey]);

  const columnDefs = React.useMemo<ColumnDef<DataTableRow>[]>(() => (
    columns.map((column) => ({
      id: column.id,
      accessorFn: (row) => row.cells[column.id]?.content ?? null,
      header: () => column.header,
      minSize: minColumnWidth,
      size: columnSizing[column.id] ?? column.initialSize ?? minColumnWidth,
      meta: column,
    }))
  ), [columnSizing, columns, minColumnWidth]);

  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns: columnDefs,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => row.id,
    state: {
      columnOrder,
      columnVisibility,
      columnSizing,
    },
    onColumnOrderChange: setColumnOrder,
    onColumnVisibilityChange: setColumnVisibility,
    onColumnSizingChange: setColumnSizing,
    columnResizeMode: 'onChange',
  });

  const orderedColumns = React.useMemo(() => {
    const lookup = new Map(columns.map((column) => [column.id, column]));
    return table.getAllLeafColumns()
      .map((column) => lookup.get(column.id))
      .filter((column): column is DataTableColumn => column != null);
  }, [columns, table]);

  const toggleColumn = React.useCallback((columnId: string): void => {
    setColumnVisibility((current) => {
      const visibleIds = columns.filter((column) => current[column.id] !== false).map((column) => column.id);
      const isVisible = current[columnId] !== false;
      if (isVisible && visibleIds.length <= 1) {
        return current;
      }

      const next = { ...current, [columnId]: !isVisible };
      return next;
    });
  }, [columns]);

  return (
    <div className="resizable-table-wrapper" ref={wrapperRef}>
      {showColumnControls && (
        <div className="table-column-controls">
          <button
            type="button"
            className="table-settings-btn"
            onClick={() => setMenuOpen((current) => !current)}
            aria-label="Show or hide columns"
            title="Show or hide columns"
            disabled={orderedColumns.length === 0}
          >
            ⚙
          </button>
          {menuOpen && orderedColumns.length > 0 && (
            <div className="table-settings-menu" role="menu" aria-label="Column visibility">
              <div className="table-settings-title">Columns</div>
              {orderedColumns.map((column) => {
                const visibleCount = orderedColumns.filter((item) => columnVisibility[item.id] !== false).length;
                const isVisible = columnVisibility[column.id] !== false;
                return (
                  <label key={column.id} className="table-settings-item">
                    <input
                      type="checkbox"
                      checked={isVisible}
                      onChange={() => toggleColumn(column.id)}
                      disabled={isVisible && visibleCount <= 1}
                    />
                    <span>{column.label}</span>
                  </label>
                );
              })}
            </div>
          )}
        </div>
      )}

      <table className="resizable-table">
        <thead>
          {table.getHeaderGroups().map((headerGroup) => (
            <tr key={headerGroup.id}>
              {headerGroup.headers.map((header) => {
                const column = header.column.columnDef.meta as DataTableColumn;
                const headerProps = column.headerProps ?? {};
                const isDragging = draggedColumnId === header.column.id;
                const isDropTarget = dropTargetId === header.column.id && draggedColumnId !== header.column.id;

                return (
                  <th
                    key={header.id}
                    {...headerProps}
                    className={classNames(headerProps.className, 'resizable-header', isDragging && 'is-dragging', isDropTarget && 'drop-target')}
                    style={mergeWidthStyle(header.getSize(), headerProps.style)}
                    onDragOver={(event) => {
                      if (!draggedColumnId || draggedColumnId === header.column.id) {
                        return;
                      }
                      event.preventDefault();
                      setDropTargetId(header.column.id);
                    }}
                    onDragLeave={() => {
                      if (dropTargetId === header.column.id) {
                        setDropTargetId(null);
                      }
                    }}
                    onDrop={(event) => {
                      if (!draggedColumnId) {
                        return;
                      }
                      event.preventDefault();
                      setColumnOrder((current) => moveColumn(current, draggedColumnId, header.column.id));
                      setDraggedColumnId(null);
                      setDropTargetId(null);
                    }}
                  >
                    {column.header}
                    <button
                      type="button"
                      className="col-dragger"
                      title={`Drag to reorder ${column.label}`}
                      aria-label={`Drag to reorder ${column.label}`}
                      draggable
                      onDragStart={(event) => {
                        setDraggedColumnId(header.column.id);
                        if (event.dataTransfer) {
                          event.dataTransfer.effectAllowed = 'move';
                          event.dataTransfer.setData('text/plain', header.column.id);
                        }
                      }}
                      onDragEnd={() => {
                        setDraggedColumnId(null);
                        setDropTargetId(null);
                      }}
                    >
                      ⋮⋮
                    </button>
                    <div
                      className="col-resizer"
                      role="separator"
                      aria-label={`Resize ${column.label}`}
                      onMouseDown={header.getResizeHandler()}
                      onTouchStart={header.getResizeHandler()}
                    />
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => {
            const rowProps = row.original.rowProps ?? {};
            return (
              <tr key={row.id} {...rowProps}>
                {row.getVisibleCells().map((cell) => {
                  const cellDescriptor = row.original.cells[cell.column.id] ?? { content: null };
                  const cellProps = cellDescriptor.props ?? {};
                  return (
                    <td
                      key={cell.id}
                      {...cellProps}
                      style={mergeWidthStyle(cell.column.getSize(), cellProps.style)}
                    >
                      {cellDescriptor.content}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
