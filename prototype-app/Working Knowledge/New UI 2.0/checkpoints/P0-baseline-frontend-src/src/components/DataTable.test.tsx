import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { DataTable } from './DataTable';

describe('DataTable', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('renders rows and persists column visibility changes', () => {
    render(
      <div style={{ width: 720 }}>
        <DataTable
          storageKey="test-table"
          columns={[
            { id: 'first', label: 'First', header: 'First' },
            { id: 'second', label: 'Second', header: 'Second' }
          ]}
          rows={[
            {
              id: 'row-1',
              cells: {
                first: { content: 'alpha' },
                second: { content: 'beta' }
              }
            }
          ]}
        />
      </div>
    );

    expect(screen.getByText('alpha')).toBeInTheDocument();
    expect(screen.getByText('beta')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /show or hide columns/i }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Second' }));

    expect(screen.queryByText('beta')).not.toBeInTheDocument();
    expect(window.localStorage.getItem('test-table:hidden')).toBe('["second"]');
  });
});
