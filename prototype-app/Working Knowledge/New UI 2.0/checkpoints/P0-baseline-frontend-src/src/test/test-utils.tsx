import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false
      }
    }
  });
}

type InitialEntry = string | { pathname: string; state?: unknown; search?: string; hash?: string };

type ProviderProps = {
  children: React.ReactNode;
  route?: string;
  initialEntries?: InitialEntry[];
  queryClient?: QueryClient;
};

type ExtendedRenderOptions = Omit<RenderOptions, 'wrapper'> & {
  route?: string;
  initialEntries?: InitialEntry[];
  queryClient?: QueryClient;
};

export function renderWithProviders(
  ui: React.ReactElement,
  { route, initialEntries, queryClient, ...options }: ExtendedRenderOptions = {}
) {
  const entries = initialEntries ?? [route ?? '/'];

  const Wrapper = ({ children }: ProviderProps) => (
    <QueryClientProvider client={queryClient ?? createTestQueryClient()}>
      <MemoryRouter initialEntries={entries}>
        {children}
      </MemoryRouter>
    </QueryClientProvider>
  );

  return render(ui, {
    wrapper: Wrapper,
    ...options
  });
}

export { createTestQueryClient };
