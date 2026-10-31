import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '../test/test-utils';
import { MetricValue } from './MetricValue';

describe('MetricValue', () => {
  it('renders a valid zero as 0', () => {
    renderWithProviders(<MetricValue availability="available" value={0} />);
    expect(screen.getByText('0')).toBeInTheDocument();
  });

  it('formats available values', () => {
    renderWithProviders(<MetricValue availability="available" value={12345} />);
    expect(screen.getByText('12,345')).toBeInTheDocument();
  });

  it('accepts a custom formatter', () => {
    renderWithProviders(<MetricValue availability="available" value={0.42} format={(n) => `${Math.round(n * 100)}%`} />);
    expect(screen.getByText('42%')).toBeInTheDocument();
  });

  it('renders unavailable as a dash with an accessible explanation, never as 0', () => {
    renderWithProviders(<MetricValue availability="unavailable" value={0} unavailableReason="Patch source not connected" />);
    expect(screen.queryByText('0')).not.toBeInTheDocument();
    expect(screen.getByText('—')).toHaveAttribute('aria-hidden', 'true');
    expect(screen.getByText('Patch source not connected')).toBeInTheDocument();
  });

  it('treats a missing value as unavailable rather than zero', () => {
    renderWithProviders(<MetricValue availability="available" value={null} />);
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    expect(screen.queryByText('0')).not.toBeInTheDocument();
  });

  it('renders a consistent pending placeholder', () => {
    renderWithProviders(<MetricValue availability="pending" value={5} />);
    expect(screen.getByText('Loading')).toBeInTheDocument();
    expect(screen.queryByText('5')).not.toBeInTheDocument();
  });
});
