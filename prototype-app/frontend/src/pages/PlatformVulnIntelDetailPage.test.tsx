import { fireEvent, render, screen } from '@testing-library/react';
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
    const observationsSpy = vi.spyOn(api, 'getPlatformVulnIntelObservations').mockImplementation(async (_externalId, afterId) => afterId ? {
      items: [{ id: 'observation-2', observation: { sourceSystem: 'ghsa', sourceRecordId: 'second-page-record' } }],
      size: 25,
      hasMore: false,
      nextAfterId: null,
    } : {
      items: [{ id: 'observation-1', observation: { sourceSystem: 'nvd', sourceRecordId: 'nvd-source-record-1',
        cvssScore: 8.1, cvssVersion: '3.1',
        observedAt: '2026-01-01T00:00:00Z', lastSeenAt: '2026-01-02T00:00:00Z',
        payloadHash: 'fixture-fingerprint' } }],
      size: 25,
      hasMore: true,
      nextAfterId: 'cursor-1',
    });
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
    expect(await screen.findByText(/Stored payload fingerprint: fixture-fingerprint/)).toBeInTheDocument();
    expect(screen.getByText('CVSS v3.1 8.1')).toBeInTheDocument();
    expect(screen.getByText(/First observed:/)).toBeInTheDocument();
    expect(screen.getByText(/Last seen:/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next evidence page' }));
    expect(await screen.findByText('second-page-record')).toBeInTheDocument();
    expect(observationsSpy).toHaveBeenCalledWith('CVE-2026-1234', 'cursor-1');
  });
});
