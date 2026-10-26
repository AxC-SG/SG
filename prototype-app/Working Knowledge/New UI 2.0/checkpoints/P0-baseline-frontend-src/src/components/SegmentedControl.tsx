import React from 'react';

type Option<T extends string> = {
  value: T;
  label: string;
  activeClass?: string;
};

type Props<T extends string> = {
  options: Option<T>[];
  value: T;
  onChange: (value: T) => void;
  ariaLabel?: string;
};

export function SegmentedControl<T extends string>({ options, value, onChange, ariaLabel }: Props<T>) {
  return (
    <div className="segmented-control" role="group" aria-label={ariaLabel}>
      {options.map((option, index) => (
        <button
          key={option.value}
          type="button"
          className={[
            'segmented-control-btn',
            value === option.value ? `segmented-control-btn--active ${option.activeClass ?? ''}` : '',
            index === 0 ? 'segmented-control-btn--first' : '',
            index === options.length - 1 ? 'segmented-control-btn--last' : '',
          ].filter(Boolean).join(' ')}
          onClick={() => onChange(option.value)}
          aria-pressed={value === option.value}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
