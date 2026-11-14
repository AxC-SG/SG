import React from 'react';
import {
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from '@tanstack/react-table';
import { DataTableColumnChooser } from './DataTableColumnChooser';
import {
  clearColumnPreferences,
  layoutWidths,
  moveBefore,
  moveId,
  readStoredOrder,
  readStoredWidths,
  readVisibilityOverrides,
  reconcileOrder,
  resolveVisibility,
  writeStoredOrder,
  writeStoredWidths,
  writeVisibilityOverrides,
  type ColumnPriority,
  type VisibilityOverride,
} from './dataTablePreferences';

export type DataTableColumn = {
  id: string;
  label: string;
  header: React.ReactNode;
  headerProps?: Omit<React.ThHTMLAttributes<HTMLTableCellElement>, 'children'>;
  initialSize?: number;
  // Readable floor for this column; the table scrolls internally instead of shrinking below it.
  minWidth?: number;
  // essential: identity/action, always shown; optional: hidden below 768px unless the user chose otherwise.
  priority?: ColumnPriority;
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
  // Names the scroll region when the columns are wider than the available space.
  label?: string;
};

const RESIZE_STEP = 8;
const TABLE_DEFAULTS_QUERY = '(min-width: 768px)';

function classNames(...values: Array<string | false | null | undefined>): string {
  return values.filter(Boolean).join(' ');
}

function mergeWidthStyle(size: number, style?: React.CSSProperties): React.CSSProperties {
  return {
    ...style,
    width: `${size}px`,
    minWidth: `${size}px`,
    maxWidth: `${size}px`,
  };
}

function useContainerWidth(ref: React.RefObject<HTMLDivElement | null>): number {
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

function useNarrowViewport(): boolean {
  const query = React.useMemo(
    () => (typeof window !== 'undefined' && typeof window.matchMedia === 'function' ? window.matchMedia(TABLE_DEFAULTS_QUERY) : null),
    [],
  );
  const [narrow, setNarrow] = React.useState(() => (query ? !query.matches : false));
  React.useEffect(() => {
    if (!query) return undefined;
    const update = () => setNarrow(!query.matches);
    update();
    query.addEventListener?.('change', update);
    return () => query.removeEventListener?.('change', update);
  }, [query]);
  return narrow;
}

export function DataTable(props: DataTableProps) {
  // Preferences are read once per storage key; a different key is a different table.
  return <DataTableView key={props.storageKey} {...props} />;
}

function DataTableView({
  storageKey,
  columns,
  rows,
  minColumnWidth = 96,
  showColumnControls = true,
  label,
}: DataTableProps) {
  const wrapperRef = React.useRef<HTMLDivElement | null>(null);
  const containerWidth = useContainerWidth(wrapperRef);
  const narrow = useNarrowViewport();
  const [draggedColumnId, setDraggedColumnId] = React.useState<string | null>(null);
  const [dropTargetId, setDropTargetId] = React.useState<string | null>(null);
  const [storedOrder, setStoredOrder] = React.useState<string[] | null>(() => readStoredOrder(storageKey));
  const [overrides, setOverrides] = React.useState<Record<string, VisibilityOverride>>(() => readVisibilityOverrides(storageKey, columns));
  const [userWidths, setUserWidths] = React.useState<Record<string, number>>(() => readStoredWidths(storageKey));

  const columnOrder = React.useMemo(() => reconcileOrder(storedOrder, columns), [columns, storedOrder]);
  const visibility = React.useMemo(() => resolveVisibility(columns, overrides, narrow), [columns, narrow, overrides]);
  const minWidths = React.useMemo(() => Object.fromEntries(columns.map((column) => [column.id, column.minWidth ?? minColumnWidth])), [columns, minColumnWidth]);
  const visibleIds = React.useMemo(() => columnOrder.filter((id) => visibility[id]), [columnOrder, visibility]);
  const columnSizing = React.useMemo(() => layoutWidths(
    visibleIds,
    minWidths,
    Object.fromEntries(columns.map((column) => [column.id, column.initialSize])),
    userWidths,
    containerWidth,
  ), [columns, containerWidth, minWidths, userWidths, visibleIds]);
  const tableWidth = visibleIds.reduce((sum, id) => sum + (columnSizing[id] ?? 0), 0);
  const overflowing = containerWidth > 0 && tableWidth > containerWidth;

  const persistOrder = React.useCallback((next: string[]): void => {
    setStoredOrder(next);
    writeStoredOrder(storageKey, next);
  }, [storageKey]);

  const persistOverrides = React.useCallback((next: Record<string, VisibilityOverride>): void => {
    setOverrides(next);
    writeVisibilityOverrides(storageKey, next);
  }, [storageKey]);

  const setUserWidth = React.useCallback((columnId: string, width: number, persist: boolean): void => {
    setUserWidths((current) => {
      const next = { ...current, [columnId]: Math.max(minWidths[columnId] ?? minColumnWidth, Math.round(width)) };
      if (persist) writeStoredWidths(storageKey, next);
      return next;
    });
  }, [minColumnWidth, minWidths, storageKey]);

  const columnDefs = React.useMemo<ColumnDef<DataTableRow>[]>(() => (
    columns.map((column) => ({
      id: column.id,
      accessorFn: (row) => row.cells[column.id]?.content ?? null,
      header: () => column.header,
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
      columnVisibility: visibility,
      columnSizing,
    },
  });

  const orderedColumns = React.useMemo(() => {
    const lookup = new Map(columns.map((column) => [column.id, column]));
    return columnOrder
      .map((id) => lookup.get(id))
      .filter((column): column is DataTableColumn => column != null);
  }, [columnOrder, columns]);

  const toggleColumn = (columnId: string): void => {
    const column = columns.find((item) => item.id === columnId);
    if (!column || column.priority === 'essential') return;
    const isVisible = visibility[columnId];
    if (isVisible && visibleIds.length <= 1) return;
    persistOverrides({ ...overrides, [columnId]: { visible: !isVisible, provenance: 'user' } });
  };

  const useDefault = (columnId: string): void => {
    const next = { ...overrides };
    delete next[columnId];
    persistOverrides(next);
  };

  const resetColumns = (): void => {
    clearColumnPreferences(storageKey);
    setStoredOrder(null);
    setOverrides({});
    setUserWidths({});
  };

  const startPointerResize = (columnId: string, event: React.PointerEvent<HTMLDivElement>): void => {
    event.preventDefault();
    event.stopPropagation();
    const startX = event.clientX;
    const startWidth = columnSizing[columnId] ?? minWidths[columnId];
    let latest = startWidth;
    const onMove = (moveEvent: PointerEvent): void => {
      latest = startWidth + moveEvent.clientX - startX;
      setUserWidth(columnId, latest, false);
    };
    const onUp = (): void => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      setUserWidth(columnId, latest, true);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  };

  const keyboardResize = (columnId: string, event: React.KeyboardEvent<HTMLDivElement>): void => {
    const current = columnSizing[columnId] ?? minWidths[columnId];
    const delta = event.key === 'ArrowLeft' ? -RESIZE_STEP : event.key === 'ArrowRight' ? RESIZE_STEP : 0;
    if (delta === 0) return;
    event.preventDefault();
    setUserWidth(columnId, current + delta, true);
  };

  return (
    <div className="resizable-table-wrapper" ref={wrapperRef}>
      {showColumnControls && (
        <DataTableColumnChooser
          columns={orderedColumns}
          visibility={visibility}
          overrides={overrides}
          onToggle={toggleColumn}
          onUseDefault={useDefault}
          onMove={(id, offset) => persistOrder(moveId(columnOrder, id, offset, (value) => visibility[value]))}
          onReset={resetColumns}
        />
      )}

      <div
        className="resizable-table-scroll"
        role={overflowing ? 'region' : undefined}
        aria-label={overflowing ? label ?? 'Table, scroll horizontally for more columns' : undefined}
        tabIndex={overflowing ? 0 : undefined}
      >
        <table className="resizable-table" style={{ width: `${Math.max(tableWidth, 1)}px` }}>
          <thead>
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  const column = header.column.columnDef.meta as DataTableColumn;
                  const headerProps = column.headerProps ?? {};
                  const size = header.getSize();
                  const isDragging = draggedColumnId === header.column.id;
                  const isDropTarget = dropTargetId === header.column.id && draggedColumnId !== header.column.id;

                  return (
                    <th
                      key={header.id}
                      {...headerProps}
                      className={classNames(headerProps.className, 'resizable-header', isDragging && 'is-dragging', isDropTarget && 'drop-target')}
                      style={mergeWidthStyle(size, headerProps.style)}
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
                        persistOrder(moveBefore(columnOrder, draggedColumnId, header.column.id));
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
                        tabIndex={-1}
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
                        aria-orientation="vertical"
                        aria-label={`Resize ${column.label}`}
                        aria-valuenow={size}
                        aria-valuemin={minWidths[column.id]}
                        tabIndex={0}
                        onPointerDown={(event) => startPointerResize(column.id, event)}
                        onKeyDown={(event) => keyboardResize(column.id, event)}
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
    </div>
  );
}
