import React from 'react';

type Props = {
  className?: string;
};

// The ink quadrants use currentColor so the mark stays visible in dark theme.
export function BrandMark({ className }: Props) {
  return (
    <span className={className ? `brand-mark brand-mark-logo ${className}` : 'brand-mark brand-mark-logo'} aria-hidden="true">
      <svg viewBox="64 64 384 384" focusable="false">
        <path fill="currentColor" d="M64 120A56 56 0 0 1 120 64H232V150L150 232H64Z" />
        <path fill="#d50b2b" d="M280 64H392A56 56 0 0 1 448 120V232H362L280 150Z" />
        <path fill="currentColor" d="M64 280H150L232 362V448H120A56 56 0 0 1 64 392Z" />
        <path fill="currentColor" d="M362 280H448V392A56 56 0 0 1 392 448H280V362Z" />
      </svg>
    </span>
  );
}
