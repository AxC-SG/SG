import React from 'react';
import { MetricInfoIcon } from './MetricInfoIcon';

type Props = {
  title: string;
  value: number;
  tone?: 'neutral' | 'warn' | 'critical';
  caption?: string;
  description?: string;
};

export function StatCard({ title, value, tone = 'neutral', caption = 'Current tenant', description }: Props) {
  return (
    <div className={`stat-card stat-${tone}`}>
      <div className="stat-title-row">
        <div className="stat-title">{title}</div>
        {description ? <MetricInfoIcon label={title} description={description} /> : null}
      </div>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-caption">{caption}</div>
    </div>
  );
}
