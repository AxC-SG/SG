import React from 'react';

export type DonutSeg = {
  key: string;
  label: string;
  value: number;
  color: string;
  onClick?: () => void;
};

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
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border,#e5e7eb)" strokeWidth={sw} />
        <text x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fill="var(--muted,#9ca3af)">—</text>
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
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0, overflow: 'visible' }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border,#e5e7eb)" strokeWidth={sw} />
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
      <text x={cx} y={cy + 2} textAnchor="middle" fontSize={13} fontWeight="700" fill="var(--title,#111827)">
        {total.toLocaleString()}
      </text>
      <text x={cx} y={cy + 13} textAnchor="middle" fontSize={8} fill="var(--muted,#9ca3af)">
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

export function HBarChart({ items, activeKey }: { items: HBarItem[]; activeKey?: string }) {
  const max = Math.max(...items.map((i) => i.value), 1);
  return (
    <div className="fpl-hbar">
      {items.filter((i) => i.value > 0 || items.length <= 4).map((item) => (
        <div
          key={item.key}
          className={`fpl-hbar-row${activeKey === item.key ? ' fpl-hbar-row--active' : ''}`}
          onClick={item.onClick}
        >
          <div className="fpl-hbar-label" title={item.label}>{item.label}</div>
          <div className="fpl-hbar-track">
            <div className="fpl-hbar-fill" style={{ width: `${(item.value / max) * 100}%`, background: item.color }} />
          </div>
          <div className="fpl-hbar-val">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

export function WidgetCard({
  title,
  children,
  active
}: {
  title: string;
  children: React.ReactNode;
  active?: boolean;
}) {
  return (
    <div className={`fpl-widget${active ? ' fpl-widget--active' : ''}`}>
      <div className="fpl-widget-title">{title}</div>
      <div className="fpl-widget-body">{children}</div>
    </div>
  );
}
