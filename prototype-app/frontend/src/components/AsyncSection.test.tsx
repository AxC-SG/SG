import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../test/test-utils';
import { AsyncSection } from './AsyncSection';

describe('AsyncSection', () => {
  it('announces the pending state without rendering children', () => {
    renderWithProviders(<AsyncSection state="pending" loadingLabel="Loading fixes…"><p>rows</p></AsyncSection>);
    expect(screen.getByRole('status')).toHaveTextContent('Loading fixes…');
    expect(screen.queryByText('rows')).not.toBeInTheDocument();
  });

  it('renders children when ready', () => {
    renderWithProviders(<AsyncSection state="ready"><p>rows</p></AsyncSection>);
    expect(screen.getByText('rows')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows a first-load error with a working retry', () => {
    const onRetry = vi.fn();
    renderWithProviders(
      <AsyncSection state="error" errorMessage="Fixes could not be loaded." onRetry={onRetry} retryLabel="Retry fixes"><p>rows</p></AsyncSection>
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Fixes could not be loaded.');
    expect(screen.queryByText('rows')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry fixes' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('disables retry while a retry is in flight', () => {
    renderWithProviders(<AsyncSection state="error" onRetry={() => undefined} retrying />);
    expect(screen.getByRole('button', { name: 'Retrying…' })).toBeDisabled();
  });

  it('distinguishes a successful empty result from a filtered-empty result', () => {
    const onClear = vi.fn();
    const view = renderWithProviders(<AsyncSection state="empty" emptyTitle="No fixes yet" emptyMessage="Connect a patch source." />);
    expect(screen.getByText('No fixes yet')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Clear filters' })).not.toBeInTheDocument();

    view.rerender(<AsyncSection state="filtered-empty" filteredEmptyMessage="No fixes match these filters." onClearFilters={onClear} />);
    expect(screen.getByText('No fixes match these filters.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });

  it('presents an unavailable capability without claiming an empty result', () => {
    renderWithProviders(<AsyncSection state="unavailable" unavailableMessage="Patch data is not connected for this tenant." />);
    expect(screen.getByRole('status')).toHaveTextContent('Patch data is not connected for this tenant.');
    expect(screen.queryByText('Nothing to show yet.')).not.toBeInTheDocument();
  });

  it('keeps cached data visible when a refresh fails', () => {
    const onRetry = vi.fn();
    renderWithProviders(
      <AsyncSection state="ready" refreshError="Showing the last loaded fixes; refresh failed." onRetry={onRetry}><p>rows</p></AsyncSection>
    );
    expect(screen.getByText('rows')).toBeInTheDocument();
    expect(screen.getByText('Showing the last loaded fixes; refresh failed.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('shows a stale warning and a refreshing announcement alongside data', () => {
    renderWithProviders(<AsyncSection state="ready" staleMessage="Data is older than 24 hours." isRefreshing><p>rows</p></AsyncSection>);
    expect(screen.getByText('Data is older than 24 hours.')).toBeInTheDocument();
    expect(screen.getByText('Refreshing…')).toBeInTheDocument();
    expect(screen.getByText('rows')).toBeInTheDocument();
  });

  it('keeps an independent secondary failure from hiding a populated sibling', () => {
    renderWithProviders(
      <>
        <AsyncSection state="ready"><p>finding facts</p></AsyncSection>
        <AsyncSection state="error" errorMessage="Remediation options could not be loaded." />
      </>
    );
    expect(screen.getByText('finding facts')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Remediation options could not be loaded.');
  });
});
