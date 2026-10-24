import React from 'react';
import { Check, ChevronDown, ChevronRight, Copy } from 'lucide-react';

/** Underline tabs. Replaces `.fd3-tab-bar`, `.connect-filter-bar`, pill sub-navs. Keeps role="tab"/aria-selected. */
export function Tabs<T extends string>({ value, onChange, tabs, label }: {
  value: T;
  onChange: (value: T) => void;
  tabs: Array<{ value: T; label: string; count?: number }>;
  label: string;
}) {
  return (
    <div className="dp-tabs" role="tablist" aria-label={label} onKeyDown={event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      const buttons = [...event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')];
      const current = buttons.indexOf(document.activeElement as HTMLButtonElement);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (current + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
      event.preventDefault(); buttons[next]?.click(); buttons[next]?.focus();
    }}>
      {tabs.map((tab) => (
        <button
          key={tab.value}
          type="button"
          role="tab"
          aria-selected={tab.value === value}
          tabIndex={tab.value === value ? 0 : -1}
          className={tab.value === value ? 'active' : ''}
          onClick={() => onChange(tab.value)}
        >
          {tab.label}
          {tab.count !== undefined ? <span className="dp-tab-count">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

/** Native <details>: the app already uses <details> in 8 places, so open/close semantics stay identical. */
export function Accordion({ title, meta, children, defaultOpen }: {
  title: string;
  meta?: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details className="dp-accordion" open={defaultOpen}>
      <summary>
        <ChevronRight size={14} className="dp-accordion-caret" />
        <span className="dp-accordion-title">{title}</span>
        {meta ? <span className="dp-accordion-meta">{meta}</span> : null}
      </summary>
      <div className="dp-accordion-body">{children}</div>
    </details>
  );
}

export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="dp-stepper">
      {steps.map((step, index) => {
        const state = index < current ? 'done' : index === current ? 'current' : 'todo';
        return (
          <li key={step} className={`dp-step dp-step--${state}`} aria-current={state === 'current' ? 'step' : undefined}>
            <span className="dp-step-dot">{state === 'done' ? <Check size={12} /> : index + 1}</span>
            <span className="dp-step-label">{step}</span>
          </li>
        );
      })}
    </ol>
  );
}

export function Timeline({ items }: { items: Array<{ title: React.ReactNode; meta: string; tone?: 'accent' | 'critical' | 'success' | 'muted'; body?: React.ReactNode }> }) {
  return (
    <ol className="dp-timeline">
      {items.map((item, index) => (
        <li key={index} className={`dp-timeline-item dp-timeline-item--${item.tone ?? 'accent'}`}>
          <div className="dp-timeline-head"><strong>{item.title}</strong><span className="dp-muted">{item.meta}</span></div>
          {item.body ? <div className="dp-timeline-body">{item.body}</div> : null}
        </li>
      ))}
    </ol>
  );
}

export function CodeBlock({ code, language }: { code: string; language?: string }) {
  const [copied, setCopied] = React.useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <div className="dp-code">
      <div className="dp-code-head">
        <span>{language ?? 'text'}</span>
        <button type="button" className="dp-icon-btn sm" onClick={copy} aria-label="Copy to clipboard">{copied ? <Check size={12} /> : <Copy size={12} />}</button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

export function PropertyList({ items }: { items: Array<[string, React.ReactNode]> }) {
  return (
    <dl className="dp-props">
      {items.map(([term, value]) => (
        <React.Fragment key={term}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}

export function Collapsible({ label, children }: { label: string; children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  return (
    <div className="dp-collapsible">
      <button type="button" className="dp-link" aria-expanded={open} onClick={() => setOpen(!open)}>
        <ChevronDown size={13} style={{ transform: open ? 'none' : 'rotate(-90deg)', transition: 'transform 0.15s' }} /> {label}
      </button>
      {open ? <div className="dp-collapsible-body">{children}</div> : null}
    </div>
  );
}
