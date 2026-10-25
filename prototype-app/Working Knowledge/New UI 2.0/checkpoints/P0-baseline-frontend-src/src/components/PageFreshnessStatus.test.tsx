import { act, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../test/test-utils';
import { PageFreshnessStatus } from './PageFreshnessStatus';

describe('PageFreshnessStatus', () => {
  const visibilityDescriptor = Object.getOwnPropertyDescriptor(document, 'visibilityState')
    ?? Object.getOwnPropertyDescriptor(Document.prototype, 'visibilityState');

  beforeEach(() => {
    vi.useFakeTimers();
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    if (visibilityDescriptor) {
      Object.defineProperty(document, 'visibilityState', visibilityDescriptor);
    }
  });

  it('keeps the last-updated timestamp without a return-to-tab pulse', () => {
    const view = renderWithProviders(
      <PageFreshnessStatus updatedAt="2026-07-09T10:00:00Z" />
    );

    expect(screen.queryByText(/Updated just now while you were away/i)).not.toBeInTheDocument();

    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'hidden',
    });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    view.rerender(<PageFreshnessStatus updatedAt="2026-07-09T10:05:00Z" />);

    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    expect(screen.queryByText(/Updated just now while you were away/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
  });
});
