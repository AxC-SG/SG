import { useId } from 'react';

type MetricInfoIconProps = {
  label: string;
  description: string;
  className?: string;
};

export function MetricInfoIcon({ label, description, className = '' }: MetricInfoIconProps) {
  const tooltipId = useId();
  const classes = ['metric-info-icon', className].filter(Boolean).join(' ');
  return (
    <span className="metric-info-wrap">
      <button
        type="button"
        className={classes}
        aria-label={`${label}: ${description}`}
        aria-describedby={tooltipId}
      >
        i
      </button>
      <span id={tooltipId} role="tooltip" className="metric-info-tooltip">
        {description}
      </span>
    </span>
  );
}
