import { afterEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { OperationalDashboardPage } from './OperationalDashboardPage';

describe('OperationalDashboardPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the enterprise performance scorecard in platform health view', async () => {
    vi.spyOn(api, 'getOperationalApiReadPath').mockResolvedValue({
      generatedAt: '2026-07-08T00:00:00Z',
      data: {
        summaryReadModelReady: true,
        canonicalCveCount: 1200,
        summaryCveCount: 1180,
        summaryCoveragePercent: 98.3,
        filterCacheActive: true,
        filterCacheExpiresAt: undefined,
        filterCacheHits: 240,
        filterCacheMisses: 12,
        filterCacheHitRatioPercent: 95.2,
        endpointMetrics: []
      }
    });
    vi.spyOn(api, 'getSloStatus').mockResolvedValue({
      evaluatedAt: '2026-07-08T00:00:00Z',
      overallCompliant: false,
      slos: [{
        name: 'delta_queue_processing_oldest_age',
        description: 'Delta queue processing age',
        unit: 'seconds',
        target: 600,
        current: 920,
        compliant: false,
        window: '15m freshness window'
      }]
    });
    vi.spyOn(api, 'getOperationalMetricCatalog').mockResolvedValue({
      generatedAt: '2026-07-08T00:00:00Z',
      data: []
    });
    vi.spyOn(api, 'getOperationalPerformanceScorecard').mockResolvedValue({
      generatedAt: '2026-07-08T00:00:00Z',
      scaleProfile: '1M inventory components / 250k findings / 100 concurrent users',
      overallCompliant: false,
      routeFailureCount: 1,
      routeNoDataCount: 0,
      freshnessFailureCount: 1,
      resourceFailureCount: 1,
      resourceNoDataCount: 0,
      routeItems: [{
        key: 'findings-list',
        label: 'Findings List',
        path: '/api/findings',
        category: 'paginated-list',
        status: 'FAIL',
        unit: 'ms',
        targetP95Ms: 800,
        targetP99Ms: 1500,
        requestCount: 25,
        currentP95Ms: 920,
        currentP99Ms: 1520,
        compliant: false,
        note: 'Observed latency exceeds at least one current target.'
      }],
      freshnessItems: [{
        key: 'delta_queue_processing_oldest_age',
        label: 'Delta Queue Processing Oldest Age',
        unit: 'seconds',
        targetValue: 600,
        currentValue: 920,
        compliant: false,
        window: '15m freshness window'
      }],
      resourceItems: [{
        key: 'db-pool-active-utilization',
        label: 'DB Pool Active Utilization',
        category: 'database',
        status: 'FAIL',
        unit: '%',
        targetValue: 80,
        currentValue: 92,
        compliant: false,
        note: 'Active connections 23 of 25.'
      }]
    });

    renderWithProviders(<OperationalDashboardPage selectedView="platform-health" />, {
      route: '/operations/platform-health'
    });

    expect(await screen.findByText('Enterprise Performance Scorecard')).toBeInTheDocument();
    expect(screen.getAllByText(/Last updated/i).length).toBeGreaterThan(0);
    expect(screen.getByText('Interactive Route Budgets')).toBeInTheDocument();
    expect(screen.getByText('Runtime Resource Ceilings')).toBeInTheDocument();
    expect(screen.getByText('Findings List')).toBeInTheDocument();
    expect(screen.getByText('DB Pool Active Utilization')).toBeInTheDocument();
  });
});
