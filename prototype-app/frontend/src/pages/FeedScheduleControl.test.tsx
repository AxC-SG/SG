import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { describe, expect, it, vi } from 'vitest';
import { intelligenceApi } from '../features/intelligence/api';
import { FeedScheduleControl } from './FeedScheduleControl';

describe('FeedScheduleControl', () => {
  it('renders an enabled schedule with a next-run time', async () => {
    vi.spyOn(intelligenceApi, 'schedules').mockResolvedValue([
      {
        sync_type: 'NVD',
        enabled: true,
        interval_hours: 24,
        next_due_at: '2026-11-14T12:30:00Z'
      }
    ]);
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(
      <QueryClientProvider client={queryClient}>
        <FeedScheduleControl syncType="NVD" />
      </QueryClientProvider>
    );

    expect(await screen.findByText(/Next run:/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Scheduled ingestion' })).toBeChecked();
  });
});
