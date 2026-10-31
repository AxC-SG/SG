import React from 'react';

export type DonutSeg = {
  key: string;
  label: string;
  value: number;
  color: string;
  onClick?: () => void;
};

// The SVG is a picture of the values: it carries a text summary, and keyboard/screen-reader users act through
// a ChartLegend (real buttons) beside it. Segment clicks stay as a pointer convenience only.
function chartSummary(segs: Array<{ label: string; value: number }>, centerLabel: string): string {
  const total = segs.reduce((sum, seg) => sum + seg.value, 0);
  return `${total.toLocaleString()} ${centerLabel}: ${segs.map((seg) => `${seg.label} ${seg.value.toLocaleString()}`).join(', ')}`;
}

export function DonutChart({
  segs,
  size = 88,
  sw = 16,
  centerLabel = 'total'
}: {
  segs: DonutSeg[];
  size?: number;
  sw?: number;
  centerLabel?: string;
}) {
  const r = (size - sw) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const C = 2 * Math.PI * r;
  const total = segs.reduce((s, g) => s + g.value, 0);
  const [hovered, setHovered] = React.useState<string | null>(null);

  if (total === 0) {
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={`No ${centerLabel} to chart`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--dp-border)" strokeWidth={sw} />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fill="var(--dp-text-2)">—</text>
      </svg>
    );
  }

  const visible = segs.filter((s) => s.value > 0);
  const offsets = visible.reduce<Record<string, number>>((acc, seg, index) => {
    const prev = visible[index - 1];
    acc[seg.key] = prev ? acc[prev.key] + (prev.value / total) * C : 0;
    return acc;
  }, {});

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0, overflow: 'visible' }} role="img" aria-label={chartSummary(segs, centerLabel)}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--dp-border)" strokeWidth={sw} />
      {visible.map((seg) => {
        const arcLen = (seg.value / total) * C;
        const offset = -offsets[seg.key];
        const isHov = hovered === seg.key;
        return (
          <circle
            key={seg.key}
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={seg.color}
            strokeWidth={isHov ? sw + 4 : sw}
            strokeDasharray={`${arcLen} ${C}`}
            strokeDashoffset={offset}
            transform={`rotate(-90 ${cx} ${cy})`}
            style={{ cursor: seg.onClick ? 'pointer' : 'default', transition: 'stroke-width 0.15s' }}
            onClick={seg.onClick}
            onMouseEnter={() => setHovered(seg.key)}
            onMouseLeave={() => setHovered(null)}
          >
            <title>{seg.label}: {seg.value}</title>
          </circle>
        );
      })}
      <text x={cx} y={cy + 2} textAnchor="middle" fontSize={13} fontWeight="700" fill="var(--dp-text)">
        {total.toLocaleString()}
      </text>
      <text x={cx} y={cy + 13} textAnchor="middle" fontSize={8} fill="var(--dp-text-2)">
        {centerLabel}
      </text>
    </svg>
  );
}

export type HBarItem = {
  key: string;
  label: string;
  value: number;
  color: string;
  onClick?: () => void;
};

// Each bar keeps its label and value as text. An interactive bar is a real button whose pressed state
// says which filter is active.
export function HBarChart({ items, activeKey }: { items: HBarItem[]; activeKey?: string }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="fpl-hbar">
      {items.filter((i) => i.value > 0 || items.length <= 4).map((item) => {
        const active = activeKey === item.key;
        const content = (
          <>
            <span className="fpl-hbar-label" title={item.label}>{item.label}</span>
            <span className="fpl-hbar-track" aria-hidden="true">
              <span className="fpl-hbar-fill" style={{ width: `${(item.value / max) * 100}%`, background: item.color }} />
            </span>
            <span className="fpl-hbar-val">{item.value.toLocaleString()}</span>
          </>
        );
        const className = `fpl-hbar-row${active ? ' fpl-hbar-row--active' : ''}`;
        return item.onClick ? (
          <button key={item.key} type="button" className={className} aria-pressed={active} onClick={item.onClick}>
            {content}
          </button>
        ) : (
          <div key={item.key} className={`${className} fpl-hbar-row--static`}>{content}</div>
        );
      })}
    </div>
  );
}

export type LegendItem = {
  key: string;
  label: string;
  value: number;
  color: string;
  active?: boolean;
  onClick?: () => void;
};

export function ChartLegend({ items }: { items: LegendItem[] }) {
  return (
    <div className="fpl-widget-legend">
      {items.map((item) => {
        const content = (
          <>
            <span className="fpl-legend-dot" style={{ background: item.color }} aria-hidden="true" />
            <span className="fpl-legend-label">{item.label}</span>
            <strong className="fpl-legend-val">{item.value.toLocaleString()}</strong>
          </>
        );
        const className = `fpl-legend-row${item.active ? ' fpl-legend-row--active' : ''}`;
        return item.onClick ? (
          <button key={item.key} type="button" className={className} aria-pressed={item.active ?? false} onClick={item.onClick}>
            {content}
          </button>
        ) : (
          <div key={item.key} className={`${className} fpl-legend-row--static`}>{content}</div>
        );
      })}
    </div>
  );
}

// An active card names its filter state in text and, when the feature supports it, offers a labelled reset.
export function WidgetCard({
  title,
  children,
  active,
  onReset
}: {
  title: string;
  children: React.ReactNode;
  active?: boolean;
  onReset?: () => void;
}) {
  return (
    <div className={`fpl-widget${active ? ' fpl-widget--active' : ''}`}>
      <div className="fpl-widget-title">
        <span>{title}</span>
        {active && <span className="ui2-sr-only"> (filter applied)</span>}
        {active && onReset && (
          <button type="button" className="fpl-widget-reset" onClick={onReset} aria-label={`Clear ${title} filter`}>
            Clear
          </button>
        )}
      </div>
      <div className="fpl-widget-body">{children}</div>
    </div>
  );
}
