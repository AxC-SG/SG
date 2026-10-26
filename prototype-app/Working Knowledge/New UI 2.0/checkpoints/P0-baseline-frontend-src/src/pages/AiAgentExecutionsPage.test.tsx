import { screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiAgentExecutionsPage } from './AiAgentExecutionsPage';

it('redirects legacy execution bookmarks without fetching runtime data', async () => {
  const list = vi.spyOn(api, 'listAiAgentExecutions');
  renderWithProviders(<Routes>
    <Route path="/inventory/ai/executions" element={<AiAgentExecutionsPage />} />
    <Route path="/inventory/ai" element={<p>Static AI inventory</p>} />
  </Routes>, { route: '/inventory/ai/executions?source=old-pilot' });
  expect(await screen.findByText('Static AI inventory')).toBeInTheDocument();
  expect(list).not.toHaveBeenCalled();
  vi.restoreAllMocks();
});
