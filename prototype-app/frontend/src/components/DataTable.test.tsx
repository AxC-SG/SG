import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DataTable, type DataTableColumn } from './DataTable';
import { layoutWidths, readVisibilityOverrides } from './dataTablePreferences';

const COLUMNS: DataTableColumn[] = [
  { id: 'id', label: 'Identifier', header: 'Identifier', priority: 'essential', minWidth: 140 },
  { id: 'owner', label: 'Owner', header: 'Owner' },
  { id: 'notes', label: 'Notes', header: 'Notes', priority: 'optional' },
  { id: 'audit', label: 'Audit', header: 'Audit', defaultHidden: true },
];

const ROWS = [{
  id: 'row-1',
  cells: {
    id: { content: 'F-10420' },
    owner: { content: 'Platform Ops' },
    notes: { content: 'Patch window Friday' },
    audit: { content: 'Reviewed' },
  },
}];

function renderTable(columns: DataTableColumn[] = COLUMNS) {
  return render(<DataTable storageKey="test-table" columns={columns} rows={ROWS} label="Findings table" />);
}

function headers(): string[] {
  return screen.getAllByRole('columnheader').map((header) => header.textContent?.replace(/⋮⋮/g, '').trim() ?? '');
}

function openChooser() {
  fireEvent.click(screen.getByRole('button', { name: /show or hide columns/i }));
  return screen.getByRole('group', { name: 'Columns' });
}

function setViewport(wide: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: wide,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  }));
}

describe('DataTable', () => {
  beforeEach(() => {
    window.localStorage.clear();
    setViewport(true);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('starts from defaults and writes nothing until the user acts', () => {
    renderTable();
    expect(headers()).toEqual(['Identifier', 'Owner', 'Notes']);
    expect(window.localStorage.length).toBe(0);
  });

  it('hides optional columns below 768px unless the user chose otherwise', () => {
    setViewport(false);
    renderTable();
    expect(headers()).toEqual(['Identifier', 'Owner']);

    const chooser = openChooser();
    fireEvent.click(within(chooser).getByRole('checkbox', { name: 'Notes' }));
    expect(headers()).toEqual(['Identifier', 'Owner', 'Notes']);
    expect(JSON.parse(window.localStorage.getItem('test-table:preferences:v2') ?? '{}')).toEqual({
      version: 2,
      visibilityOverrides: { notes: { visible: true, provenance: 'user' } },
    });
  });

  it('keeps essential columns visible with a disabled, explained checkbox', () => {
    renderTable();
    const chooser = openChooser();
    const essential = within(chooser).getByRole('checkbox', { name: 'Identifier' });
    expect(essential).toBeChecked();
    expect(essential).toBeDisabled();
    expect(essential).toHaveAccessibleDescription('Identity and action columns are always shown.');
  });

  it('removes an override through Use default and resets every column preference', () => {
    window.localStorage.setItem('unrelated-filter', 'kept');
    renderTable();
    const chooser = openChooser();
    fireEvent.click(within(chooser).getByRole('checkbox', { name: 'Owner' }));
    expect(headers()).toEqual(['Identifier', 'Notes']);

    fireEvent.click(within(chooser).getByRole('button', { name: 'Use default visibility for Owner' }));
    expect(headers()).toEqual(['Identifier', 'Owner', 'Notes']);

    fireEvent.click(within(chooser).getByRole('button', { name: 'Move Owner right' }));
    fireEvent.click(within(chooser).getByRole('button', { name: 'Reset columns' }));
    expect(headers()).toEqual(['Identifier', 'Owner', 'Notes']);
    expect(window.localStorage.getItem('test-table:order')).toBeNull();
    expect(window.localStorage.getItem('test-table:preferences:v2')).toBeNull();
    expect(window.localStorage.getItem('unrelated-filter')).toBe('kept');
  });

  it('reorders by keyboard-operable move actions and persists the order', () => {
    renderTable();
    const chooser = openChooser();
    expect(within(chooser).getByRole('button', { name: 'Move Identifier left' })).toBeDisabled();
    fireEvent.click(within(chooser).getByRole('button', { name: 'Move Notes left' }));
    expect(headers()).toEqual(['Identifier', 'Notes', 'Owner']);
    expect(JSON.parse(window.localStorage.getItem('test-table:order') ?? '[]')).toEqual(['id', 'notes', 'owner', 'audit']);
  });

  it('closes the chooser on Escape and returns focus to its button', () => {
    renderTable();
    const chooser = openChooser();
    const button = screen.getByRole('button', { name: /show or hide columns/i });
    expect(button).toHaveAttribute('aria-expanded', 'true');
    expect(within(chooser).getByRole('checkbox', { name: 'Owner' })).toHaveFocus();
    fireEvent.keyDown(within(chooser).getByRole('checkbox', { name: 'Owner' }), { key: 'Escape' });
    expect(screen.queryByRole('group', { name: 'Columns' })).not.toBeInTheDocument();
    expect(button).toHaveFocus();
  });

  it('resizes by keyboard in 8px steps without going below the declared minimum', () => {
    renderTable();
    const handle = screen.getByRole('separator', { name: 'Resize Identifier' });
    expect(handle).toHaveAttribute('aria-valuenow', '140');
    fireEvent.keyDown(handle, { key: 'ArrowRight' });
    expect(handle).toHaveAttribute('aria-valuenow', '148');
    expect(JSON.parse(window.localStorage.getItem('test-table') ?? '{}')).toEqual({ id: 148 });
    fireEvent.keyDown(handle, { key: 'ArrowLeft' });
    fireEvent.keyDown(handle, { key: 'ArrowLeft' });
    expect(handle).toHaveAttribute('aria-valuenow', '140');
  });

  it('clamps undersized stored widths when rendering', () => {
    window.localStorage.setItem('test-table', JSON.stringify({ id: 40 }));
    renderTable();
    expect(screen.getByRole('separator', { name: 'Resize Identifier' })).toHaveAttribute('aria-valuenow', '140');
  });

  it('imports a legacy snapshot for the columns it knew and defaults newer columns', () => {
    window.localStorage.setItem('test-table:hidden', JSON.stringify(['owner']));
    window.localStorage.setItem('test-table:order', JSON.stringify(['id', 'owner', 'notes']));
    expect(readVisibilityOverrides('test-table', COLUMNS)).toEqual({
      id: { visible: true, provenance: 'legacy-snapshot' },
      owner: { visible: false, provenance: 'legacy-snapshot' },
      notes: { visible: true, provenance: 'legacy-snapshot' },
    });

    setViewport(false);
    renderTable();
    // The legacy visible choice for Notes wins over the narrow default; Audit was unknown, so it stays hidden by default.
    expect(headers()).toEqual(['Identifier', 'Notes']);
  });

  it('cannot hide an essential column through a legacy snapshot', () => {
    window.localStorage.setItem('test-table:hidden', JSON.stringify(['id']));
    renderTable();
    expect(headers()[0]).toBe('Identifier');
  });

  it('keeps the last visible column when nothing is essential', () => {
    renderTable([
      { id: 'first', label: 'First', header: 'First' },
      { id: 'second', label: 'Second', header: 'Second' },
    ]);
    const chooser = openChooser();
    fireEvent.click(within(chooser).getByRole('checkbox', { name: 'Second' }));
    expect(within(chooser).getByRole('checkbox', { name: 'First' })).toBeDisabled();
    expect(screen.queryByText('Platform Ops')).not.toBeInTheDocument();
  });
});

describe('layoutWidths', () => {
  const mins = { a: 100, b: 100, c: 120 };

  it('never shrinks below minimums, so a narrow container scrolls', () => {
    expect(layoutWidths(['a', 'b', 'c'], mins, {}, {}, 200)).toEqual({ a: 100, b: 100, c: 120 });
  });

  it('gives spare width to columns without a user width', () => {
    expect(layoutWidths(['a', 'b', 'c'], mins, {}, { a: 150 }, 590)).toEqual({ a: 150, b: 200, c: 240 });
  });

  it('gives spare width to the last column when every column was resized', () => {
    expect(layoutWidths(['a', 'b'], mins, {}, { a: 100, b: 100 }, 300)).toEqual({ a: 100, b: 200 });
  });
});
