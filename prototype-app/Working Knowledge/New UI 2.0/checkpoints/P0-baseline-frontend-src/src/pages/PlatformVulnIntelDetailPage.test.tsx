import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { api } from '../api/client';
import { PlatformVulnIntelDetailPage } from './PlatformVulnIntelDetailPage';

function renderDetailPage(route = '/platform/vuln-repo/intel/CVE-2026-1234') {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  return (
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[route]}>
        <Routes>
          <Route path="/platform/vuln-repo/intel/:externalId" element={<PlatformVulnIntelDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('PlatformVulnIntelDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders detail content with freshness status', async () => {
    vi.spyOn(api, 'getPlatformVulnIntelDetail').mockResolvedValue({
      externalId: 'CVE-2026-1234',
      title: 'Example vulnerability',
      description: 'Detail page description',
      severity: 'HIGH',
      cvssScore: 8.4,
      epssScore: 0.31,
      cweIds: 'CWE-79',
      inKev: true,
      sources: ['nvd', 'ghsa'],
      cpes: [],
      references: ['https://example.com/advisory'],
      observations: [],
    });

    render(renderDetailPage());

    expect(await screen.findByText('CVE-2026-1234')).toBeInTheDocument();
    expect(screen.getByText(/Last updated/i)).toBeInTheDocument();
    expect(screen.getByText('Example vulnerability')).toBeInTheDocument();
  });
});
