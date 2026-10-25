import { render, screen, fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DonutChart, HBarChart, WidgetCard } from './FplWidgets';
import type { DonutSeg, HBarItem } from './FplWidgets';

function seg(key: string, value: number, onClick?: () => void): DonutSeg {
  return { key, label: key, value, color: '#ff0000', onClick };
}

function bar(key: string, value: number, onClick?: () => void): HBarItem {
  return { key, label: key, value, color: '#ff0000', onClick };
}

// ── DonutChart ────────────────────────────────────────────────────────────────

describe('DonutChart', () => {
  it('renders empty SVG with dash when all segment values are zero', () => {
    const { container } = render(
      <DonutChart segs={[seg('a', 0), seg('b', 0)]} />
    );
    const textEls = container.querySelectorAll('text');
    expect(Array.from(textEls).some((t) => t.textContent === '—')).toBe(true);
  });

  it('renders the total count in centre', () => {
    render(<DonutChart segs={[seg('critical', 5), seg('high', 3)]} />);
    expect(screen.getByText('8')).toBeInTheDocument();
  });

  it('renders custom centreLabel', () => {
    render(<DonutChart segs={[seg('a', 1)]} centerLabel="open" />);
    expect(screen.getByText('open')).toBeInTheDocument();
  });

  it('renders tooltip title for each non-zero segment', () => {
    const { container } = render(
      <DonutChart segs={[seg('critical', 5), seg('high', 3)]} />
    );
    const titles = container.querySelectorAll('title');
    const texts = Array.from(titles).map((t) => t.textContent);
    expect(texts).toContain('critical: 5');
    expect(texts).toContain('high: 3');
  });

  it('filters out zero-value segments from the arc', () => {
    const { container } = render(
      <DonutChart segs={[seg('critical', 5), seg('empty', 0)]} />
    );
    // One background circle + one segment arc for critical (empty is filtered)
    const circles = container.querySelectorAll('circle');
    expect(circles).toHaveLength(2);
  });

  it('calls onClick when a segment arc is clicked', () => {
    const onClick = vi.fn();
    const { container } = render(
      <DonutChart segs={[seg('critical', 5, onClick)]} />
    );
    // circles[0] = background track, circles[1] = first segment arc
    const circles = container.querySelectorAll('circle');
    fireEvent.click(circles[1]);
    expect(onClick).toHaveBeenCalledOnce();
  });

  it('does not crash when segs array is empty', () => {
    const { container } = render(<DonutChart segs={[]} />);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });
});

// ── HBarChart ─────────────────────────────────────────────────────────────────

describe('HBarChart', () => {
  it('renders a row for each item with label and value', () => {
    render(
      <HBarChart items={[bar('Critical', 12), bar('High', 8), bar('Medium', 3)]} />
    );
    expect(screen.getByText('Critical')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
  });

  it('marks the activeKey row with active CSS class', () => {
    const { container } = render(
      <HBarChart items={[bar('Critical', 12), bar('High', 8)]} activeKey="High" />
    );
    const rows = container.querySelectorAll('.fpl-hbar-row');
    const highRow = Array.from(rows).find((r) => r.textContent?.includes('High'));
    expect(highRow?.className).toContain('fpl-hbar-row--active');
    const critRow = Array.from(rows).find((r) => r.textContent?.includes('Critical'));
    expect(critRow?.className).not.toContain('fpl-hbar-row--active');
  });

  it('hides zero-value items when list has more than 4 items', () => {
    const items = [
      bar('a', 10),
      bar('b', 5),
      bar('c', 3),
      bar('d', 1),
      bar('e', 0),
    ];
    render(<HBarChart items={items} />);
    expect(screen.queryByText('e')).not.toBeInTheDocument();
    expect(screen.getByText('a')).toBeInTheDocument();
  });

  it('shows zero-value items when list has 4 or fewer items', () => {
    const items = [bar('a', 10), bar('b', 5), bar('c', 0)];
    render(<HBarChart items={items} />);
    expect(screen.getByText('c')).toBeInTheDocument();
  });

  it('calls onClick when a row is clicked', () => {
    const onClick = vi.fn();
    render(<HBarChart items={[bar('Critical', 12, onClick)]} />);
    const row = screen.getByText('Critical').closest('.fpl-hbar-row');
    if (row) fireEvent.click(row);
    expect(onClick).toHaveBeenCalledOnce();
  });
});

// ── WidgetCard ────────────────────────────────────────────────────────────────

describe('WidgetCard', () => {
  it('renders the title and children', () => {
    render(
      <WidgetCard title="Severity Breakdown">
        <span>child content</span>
      </WidgetCard>
    );
    expect(screen.getByText('Severity Breakdown')).toBeInTheDocument();
    expect(screen.getByText('child content')).toBeInTheDocument();
  });

  it('applies active CSS class when active is true', () => {
    const { container } = render(
      <WidgetCard title="Test" active>
        <span />
      </WidgetCard>
    );
    expect(container.firstChild).toHaveClass('fpl-widget--active');
  });

  it('does not apply active class when active is false', () => {
    const { container } = render(
      <WidgetCard title="Test" active={false}>
        <span />
      </WidgetCard>
    );
    expect(container.firstChild).not.toHaveClass('fpl-widget--active');
  });

  it('does not apply active class when active is omitted', () => {
    const { container } = render(
      <WidgetCard title="Test"><span /></WidgetCard>
    );
    expect(container.firstChild).not.toHaveClass('fpl-widget--active');
  });
});
