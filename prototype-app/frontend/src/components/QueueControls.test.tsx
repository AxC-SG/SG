import type React from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { ActiveFilterChips, Pager, ResultScope } from './QueueControls';

function resultScopeText(props: React.ComponentProps<typeof ResultScope>): string {
  const { unmount } = render(<ResultScope {...props} />);
  const text = screen.getByRole('status').textContent ?? '';
  unmount();
  return text;
}

describe('ActiveFilterChips', () => {
  it('renders nothing without active filters', () => {
    const { container } = render(<ActiveFilterChips filters={[]} onClearAll={() => undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('names each removal and clears all filters', () => {
    const removeSeverity = vi.fn();
    const clearAll = vi.fn();
    render(
      <ActiveFilterChips
        filters={[
          { key: 'severity', label: 'Severity', value: 'Critical', onRemove: removeSeverity },
          { key: 'owner', label: 'Owner', value: 'Platform Ops', onRemove: () => undefined },
        ]}
        onClearAll={clearAll}
      />
    );
    const group = screen.getByRole('group', { name: 'Active filters' });
    fireEvent.click(within(group).getByRole('button', { name: 'Remove filter Severity: Critical' }));
    expect(removeSeverity).toHaveBeenCalledOnce();
    fireEvent.click(within(group).getByRole('button', { name: 'Clear filters' }));
    expect(clearAll).toHaveBeenCalledOnce();
  });
});

describe('ResultScope', () => {
  it('states the shown range, total and filter scope', () => {
    expect(resultScopeText({ offset: 25, count: 25, total: 132, noun: 'finding', filtered: true }))
      .toBe('Showing 26–50 of 132 findings matching the filters');
    expect(resultScopeText({ offset: 0, count: 1, total: 1, noun: 'finding' })).toBe('Showing 1–1 of 1 finding');
  });

  it('does not invent a total the source did not report', () => {
    expect(resultScopeText({ offset: 0, count: 50, total: null, noun: 'asset' })).toBe('Showing 1–50 assets');
  });

  it('distinguishes no results from a filtered miss', () => {
    expect(resultScopeText({ offset: 0, count: 0, total: 0, noun: 'campaign' })).toBe('No campaigns');
    expect(resultScopeText({ offset: 0, count: 0, total: 0, noun: 'campaign', filtered: true })).toBe('No campaigns matching the filters');
  });

  it('announces selection with its page or all-pages scope', () => {
    const { rerender } = render(<ResultScope offset={0} count={25} total={60} noun="finding" selectedCount={3} />);
    expect(screen.getByRole('status')).toHaveTextContent('Showing 1–25 of 60 findings · 3 selected on this page');
    rerender(<ResultScope offset={0} count={25} total={60} noun="finding" selectedCount={60} selectionScope="all" />);
    expect(screen.getByRole('status')).toHaveTextContent('60 selected across all pages');
  });
});

describe('Pager', () => {
  it('is a labelled navigation with bounded Previous/Next', () => {
    const onPrevious = vi.fn();
    const onNext = vi.fn();
    const { rerender } = render(<Pager page={0} totalPages={3} onPrevious={onPrevious} onNext={onNext} label="Findings pages" />);
    const nav = screen.getByRole('navigation', { name: 'Findings pages' });
    expect(within(nav).getByText('Page 1 of 3')).toBeInTheDocument();
    expect(within(nav).getByRole('button', { name: 'Previous' })).toBeDisabled();
    fireEvent.click(within(nav).getByRole('button', { name: 'Next' }));
    expect(onNext).toHaveBeenCalledOnce();

    rerender(<Pager page={2} totalPages={3} onPrevious={onPrevious} onNext={onNext} />);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }));
    expect(onPrevious).toHaveBeenCalledOnce();
  });

  it('uses hasNext when the source reports no page count, and disables both while loading', () => {
    const { rerender } = render(<Pager page={1} totalPages={null} hasNext onPrevious={() => undefined} onNext={() => undefined} />);
    expect(screen.getByText('Page 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
    rerender(<Pager page={1} totalPages={null} hasNext disabled onPrevious={() => undefined} onNext={() => undefined} />);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();
  });
});
