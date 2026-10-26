import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Link, Route, Routes, useLocation } from 'react-router-dom';
import { renderWithProviders } from '../test/test-utils';
import { RouteErrorBoundary } from './RouteErrorBoundary';

afterEach(() => vi.restoreAllMocks());

function Shell({ children }: React.PropsWithChildren) {
  const location = useLocation();
  return <><Link to="/healthy">Other page</Link><RouteErrorBoundary resetKey={location.pathname}>{children}</RouteErrorBoundary></>;
}

describe('RouteErrorBoundary', () => {
  it('keeps navigation usable after a rejected lazy page and recovers on navigation', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const BrokenPage = React.lazy(() => Promise.reject(new TypeError('Failed to fetch dynamically imported module')));
    renderWithProviders(
      <Shell><React.Suspense fallback="Loading"><Routes>
        <Route path="/broken" element={<BrokenPage />} />
        <Route path="/healthy" element={<p>Healthy page</p>} />
      </Routes></React.Suspense></Shell>,
      { route: '/broken' },
    );
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('This page could not be loaded'));
    expect(screen.getByRole('button', { name: 'Reload page' })).toBeVisible();
    fireEvent.click(screen.getByRole('link', { name: 'Other page' }));
    expect(await screen.findByText('Healthy page')).toBeVisible();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
