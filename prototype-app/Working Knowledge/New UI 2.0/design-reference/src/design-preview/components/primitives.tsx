import React from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { useDialogBehavior } from './useDialogBehavior';
import { STATUS_LABEL, type FindingStatus, type Severity } from '../data';

export function Badge({ tone = 'neutral', children, dot }: {
  tone?: Severity | 'neutral' | 'accent' | 'success' | 'warning';
  children: React.ReactNode;
  dot?: boolean;
}) {
  return (
    <span className={`dp-badge dp-badge--${tone}`}>
      {dot ? <span className="dp-badge-dot" /> : null}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={severity} dot>{severity[0].toUpperCase() + severity.slice(1)}</Badge>;
}

export function StatusBadge({ status }: { status: FindingStatus }) {
  const tone = status === 'OPEN' ? 'accent' : status === 'RESOLVED' ? 'success' : 'neutral';
  return <Badge tone={tone} dot>{STATUS_LABEL[status]}</Badge>;
}

export function Card({ title, subtitle, actions, children, className = '' }: {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`dp-card ${className}`}>
      {title ? (
        <header className="dp-card-header">
          <div>
            <h3>{title}</h3>
            {subtitle ? <p>{subtitle}</p> : null}
          </div>
          {actions ? <div className="dp-card-actions">{actions}</div> : null}
        </header>
      ) : null}
      {children}
    </section>
  );
}

export function Segmented<T extends string>({ value, options, onChange, size = 'md' }: {
  value: T;
  options: Array<{ value: T; label: React.ReactNode; title?: string }>;
  onChange: (value: T) => void;
  size?: 'sm' | 'md';
}) {
  return (
    <div className={`dp-segmented dp-segmented--${size}`} role="tablist">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          title={option.title}
          aria-selected={option.value === value}
          className={option.value === value ? 'active' : ''}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Sparkline({ values, tone = 'accent' }: { values: number[]; tone?: string }) {
  const w = 96;
  const h = 32;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const pts = values.map((v, i) => [
    (i / (values.length - 1)) * w,
    h - 3 - ((v - min) / (max - min || 1)) * (h - 6),
  ]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  return (
    <svg className={`dp-spark dp-spark--${tone}`} viewBox={`0 0 ${w} ${h}`} aria-hidden="true">
      <path className="dp-spark-area" d={`${line} L${w},${h} L0,${h} Z`} />
      <path className="dp-spark-line" d={line} />
    </svg>
  );
}

/**
 * KPI tile. Replaces `.exec-kpi` / `.fpl-kpi-card` / StatCard. Renders as a <button> when the
 * current tile is clickable (drill-down), otherwise a <div> — match the element the call site uses today.
 */
export function StatTile({ label, value, sub, tone = 'neutral', icon, onClick, active, spark }: {
  label: string;
  value: string;
  sub?: React.ReactNode;
  tone?: Severity | 'neutral' | 'accent' | 'warning';
  icon?: React.ReactNode;
  onClick?: () => void;
  active?: boolean;
  /** Only when the page already has a series to plot — never invent trend data. */
  spark?: number[];
}) {
  const body = (
    <>
      <div className="dp-kpi-top">
        {icon ? <span className={`dp-kpi-icon dp-kpi-icon--${tone}`}>{icon}</span> : <span className={`dp-kpi-bar dp-kpi-bar--${tone}`} />}
        <span className="dp-kpi-label">{label}</span>
      </div>
      <div className="dp-kpi-row">
        <span className="dp-kpi-value">{value}</span>
        {spark ? <Sparkline values={spark} tone={tone} /> : null}
      </div>
      {sub ? <div className="dp-kpi-foot dp-muted">{sub}</div> : null}
    </>
  );
  return onClick
    ? <button type="button" className={`dp-kpi${active ? ' active' : ''}`} onClick={onClick}>{body}</button>
    : <div className="dp-kpi static">{body}</div>;
}

/** Page header. `title` must keep the exact text the page/App renders today (tests read it). */
export function PageHeader({ eyebrow, title, description, actions, meta }: {
  eyebrow?: string;
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  meta?: React.ReactNode;
}) {
  return (
    <div className="dp-page-header">
      <div>
        {eyebrow ? <div className="dp-eyebrow">{eyebrow}</div> : null}
        <h1>{title}</h1>
        {description ? <p>{description}</p> : null}
        {meta ? <div className="dp-page-meta">{meta}</div> : null}
      </div>
      {actions ? <div className="dp-page-actions">{actions}</div> : null}
    </div>
  );
}

export function Drawer({ open, onClose, title, eyebrow, children, footer }: {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  eyebrow?: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const titleId = React.useId();
  const { panel, layer } = useDialogBehavior(open, onClose);
  if (!open) return null;
  return createPortal(
    <div className="dp-drawer-root open" ref={layer}>
      <div className="dp-scrim" onClick={onClose} />
      <aside className="dp-drawer" ref={el => { panel.current = el; }} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <header className="dp-drawer-header">
          <div>
            {eyebrow ? <div className="dp-drawer-eyebrow">{eyebrow}</div> : null}
            <h2 id={titleId}>{title}</h2>
          </div>
          <button type="button" className="dp-icon-btn" onClick={onClose} aria-label="Close"><X size={16} /></button>
        </header>
        <div className="dp-drawer-body">{children}</div>
        {footer ? <footer className="dp-drawer-footer">{footer}</footer> : null}
      </aside>
    </div>, document.body
  );
}

/** Click-outside aware popover anchored under its trigger. */
export function Popover({ trigger, children, align = 'left', width = 240 }: {
  trigger: (props: { open: boolean; toggle: () => void }) => React.ReactNode;
  children: (close: () => void) => React.ReactNode;
  align?: 'left' | 'right';
  width?: number;
}) {
  const [open, setOpen] = React.useState(false);
  const ref = React.useRef<HTMLDivElement>(null);
  const popup = React.useRef<HTMLDivElement>(null);
  const [position, setPosition] = React.useState({ left: 8, top: 8, width, maxHeight: 400 });
  React.useLayoutEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = ref.current?.getBoundingClientRect();
      if (!rect) return;
      const w = Math.min(width, window.innerWidth - 16);
      const h = Math.min(popup.current?.scrollHeight ?? 200, window.innerHeight - 24);
      const below = window.innerHeight - rect.bottom - 14;
      const above = rect.top - 14;
      const top = below >= h || below >= above ? rect.bottom + 6 : Math.max(8, rect.top - h - 6);
      setPosition({ left: Math.max(8, Math.min(align === 'right' ? rect.right - w : rect.left, window.innerWidth - w - 8)), top, width: w, maxHeight: Math.max(80, window.innerHeight - top - 8) });
    };
    place();
    window.addEventListener('resize', place);
    document.addEventListener('scroll', place, true);
    return () => { window.removeEventListener('resize', place); document.removeEventListener('scroll', place, true); };
  }, [open, align, width]);
  React.useEffect(() => {
    if (!open) return undefined;
    const onDown = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node) && !popup.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') { event.stopPropagation(); setOpen(false); ref.current?.querySelector<HTMLElement>('button')?.focus(); } };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open]);
  return (
    <div className="dp-popover-wrap" ref={ref}>
      {trigger({ open, toggle: () => setOpen((current) => !current) })}
      {open ? createPortal(
        <div className="dp-popover dp-floating-popover" ref={popup} style={position}>
          {children(() => setOpen(false))}
        </div>, document.body
      ) : null}
    </div>
  );
}

export function Meter({ value, max = 10 }: { value: number; max?: number }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  const tone = value >= 8.5 ? 'critical' : value >= 7 ? 'high' : value >= 4 ? 'medium' : 'low';
  return (
    <span className="dp-meter">
      <span className="dp-meter-value">{value.toFixed(1)}</span>
      <span className="dp-meter-track"><span className={`dp-meter-fill dp-meter-fill--${tone}`} style={{ width: `${pct}%` }} /></span>
    </span>
  );
}

export function Avatar({ name, size = 22 }: { name: string; size?: number }) {
  const initials = name.split(' ').map((part) => part[0]).join('').slice(0, 2).toUpperCase();
  const hue = [...name].reduce((acc, ch) => acc + ch.charCodeAt(0), 0) % 360;
  return (
    <span className="dp-avatar" style={{ width: size, height: size, background: `hsl(${hue} 60% 92%)`, color: `hsl(${hue} 45% 32%)` }}>
      {initials}
    </span>
  );
}
