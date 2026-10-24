import React from 'react';
import { ChevronDown, Eye, EyeOff, UploadCloud } from 'lucide-react';

/**
 * Form controls. Every control is a styled native element (input/select/textarea),
 * so label association, keyboard behaviour and testing-library queries
 * (getByLabelText, getByRole('combobox'), …) work exactly as they do today.
 */

export function Field({ label, hint, error, required, htmlFor, children, inline }: {
  label: string;
  hint?: React.ReactNode;
  error?: string;
  required?: boolean;
  htmlFor?: string;
  children: React.ReactNode;
  inline?: boolean;
}) {
  const generated = React.useId();
  const element = React.isValidElement<React.InputHTMLAttributes<HTMLInputElement>>(children) ? children : null;
  const id = htmlFor ?? element?.props.id ?? generated;
  const detailId = `${id}-description`;
  const control = element ? React.cloneElement(element, {
    id,
    required: required || element.props.required,
    'aria-invalid': error ? true : element.props['aria-invalid'],
    'aria-describedby': [element.props['aria-describedby'], error || hint ? detailId : ''].filter(Boolean).join(' ') || undefined,
  }) : children;
  return (
    <div className={`dp-field${inline ? ' dp-field--inline' : ''}${error ? ' dp-field--error' : ''}`}>
      <label className="dp-label" htmlFor={id}>
        {label}
        {required ? <span className="dp-required" aria-hidden="true">*</span> : null}
      </label>
      <div className="dp-field-control">
        {control}
        {error ? <div id={detailId} className="dp-field-error" role="alert">{error}</div> : hint ? <div id={detailId} className="dp-hint">{hint}</div> : null}
      </div>
    </div>
  );
}

export function TextInput({ prefix, suffix, className = '', ...props }: React.InputHTMLAttributes<HTMLInputElement> & {
  prefix?: React.ReactNode;
  suffix?: React.ReactNode;
}) {
  if (!prefix && !suffix) return <input className={`dp-input ${className}`} {...props} />;
  return (
    <div className={`dp-input-group${props.disabled ? ' disabled' : ''}`}>
      {prefix ? <span className="dp-input-affix">{prefix}</span> : null}
      <input className={`dp-input dp-input--bare ${className}`} {...props} />
      {suffix ? <span className="dp-input-affix">{suffix}</span> : null}
    </div>
  );
}

export function PasswordInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  const [visible, setVisible] = React.useState(false);
  return (
    <div className="dp-input-group">
      <input className="dp-input dp-input--bare" {...props} type={visible ? 'text' : 'password'} />
      <button type="button" className="dp-icon-btn sm" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide value' : 'Show value'}>
        {visible ? <EyeOff size={14} /> : <Eye size={14} />}
      </button>
    </div>
  );
}

export function Select({ children, className = '', ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <div className={`dp-select ${className}`} data-label={props['aria-label']?.replace(/\s+\d+$/, '')}>
      <select {...props}>{children}</select>
      <ChevronDown size={14} className="dp-select-caret" aria-hidden="true" />
    </div>
  );
}

export function Textarea({ className = '', ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`dp-input dp-textarea ${className}`} {...props} />;
}

export function Checkbox({ label, description, ...props }: React.InputHTMLAttributes<HTMLInputElement> & { label: string; description?: string }) {
  return (
    <label className="dp-choice">
      <input type="checkbox" {...props} />
      <span><span className="dp-choice-label">{label}</span>{description ? <span className="dp-choice-desc">{description}</span> : null}</span>
    </label>
  );
}

export function RadioCards<T extends string>({ name, value, onChange, options }: {
  name: string;
  value: T;
  onChange: (value: T) => void;
  options: Array<{ value: T; label: string; description: string }>;
}) {
  return (
    <div className="dp-radio-cards" role="radiogroup">
      {options.map((option) => (
        <label key={option.value} className={`dp-radio-card${value === option.value ? ' checked' : ''}`}>
          <input type="radio" name={name} value={option.value} checked={value === option.value} onChange={() => onChange(option.value)} />
          <span className="dp-choice-label">{option.label}</span>
          <span className="dp-choice-desc">{option.description}</span>
        </label>
      ))}
    </div>
  );
}

export function Switch({ checked, onChange, label, description, role = 'switch' }: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  description?: string;
  role?: 'switch' | 'checkbox';
}) {
  return (
    <label className="dp-switch-field">
      <span>
        <span className="dp-choice-label">{label}</span>
        {description ? <span className="dp-choice-desc">{description}</span> : null}
      </span>
      <input type="checkbox" role={role} className="dp-switch-input" checked={checked} onChange={(e) => onChange(e.target.checked)} />
    </label>
  );
}

export function Slider({ label, value, min, max, step, onChange, format = (v) => v.toFixed(1) }: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (value: number) => void;
  format?: (value: number) => string;
}) {
  const pct = ((value - min) / (max - min)) * 100;
  return (
    <div className="dp-slider">
      <div className="dp-slider-head">
        <span className="dp-choice-label">{label}</span>
        <output className="dp-slider-value">{format(value)}</output>
      </div>
      <input
        type="range"
        aria-label={label}
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{ '--dp-pct': `${pct}%` } as React.CSSProperties}
      />
    </div>
  );
}

export function FileDropzone({ accept, onFiles }: { accept?: string; onFiles?: (names: string[]) => void }) {
  const [over, setOver] = React.useState(false);
  const [names, setNames] = React.useState<string[]>([]);
  const take = (files: FileList | null) => {
    const next = files ? Array.from(files).map((file) => file.name) : [];
    setNames(next);
    onFiles?.(next);
  };
  return (
    <label
      className={`dp-dropzone${over ? ' over' : ''}`}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); take(e.dataTransfer.files); }}
    >
      <input type="file" accept={accept} onChange={(e) => take(e.target.files)} />
      <UploadCloud size={20} />
      <span><strong>Drop a file</strong> or click to browse</span>
      <span className="dp-muted">{names.length ? names.join(', ') : accept ? `Accepts ${accept}` : 'Any file type'}</span>
    </label>
  );
}
