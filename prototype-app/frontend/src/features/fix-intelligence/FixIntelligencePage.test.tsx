import React from 'react';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { PageHeaderProvider } from '../../app/PageHeader';
import { useRouteHeader } from '../../app/pageHeaderState';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { renderWithProviders } from '../../test/test-utils';
import { fixIntelligenceApi } from './api';
import { ANALYST, AUDITOR, TENANT_ADMIN, listItem, page, summary } from './fixtures';
import { FixIntelligencePage } from './FixIntelligencePage';
import type { FixView } from './types';

// Stands in for the shell, which renders the only route H1 from the page's registration.
function ShellTitle() {
  const { pathname } = useLocation();
  return <h1>{useRouteHeader(pathname, 'Fix Intelligence').title}</h1>;
}

function renderPage(view: FixView, actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <PageHeaderProvider>
        <ShellTitle />
        <FixIntelligencePage view={view} />
      </PageHeaderProvider>
    </ActorContextState.Provider>
  );
}

describe('FixIntelligencePage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders KPI cards, severity bars and fix rows', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary({
      totalFixes: 12,
      criticalSeverity: 3,
      highPriority: 5,
      ecosystemsCovered: 2,
      severityDistribution: [{ key: 'CRITICAL', count: 3, percent: 25 }]
    }));
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('all');

    expect(await screen.findByText('KB5034441')).toBeInTheDocument();
    expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('12');
    expect(screen.getByText('3 / 4 (75%)')).toBeInTheDocument();
    expect(screen.getByText('3 · 25%')).toBeInTheDocument();
  });

  it('shows zeros rather than NaN when there are no fixes', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([]));
    renderPage('patches');

    expect(await screen.findByText(/No patches yet/)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/NaN/);
    expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('0');
  });

  it('shows "No assets" instead of an impossible coverage percentage', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary({ totalFixes: 1 }));
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([
      listItem({ applicableAssets: 0, remediatedAssets: 0, coveragePercent: null })
    ]));
    renderPage('all');
    expect(await screen.findByText('No assets')).toBeInTheDocument();
  });

  it('filters patches by ecosystem from the strip', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary({
      totalFixes: 2,
      ecosystems: [{ key: 'WINDOWS', count: 2, percent: 100 }]
    }));
    const list = vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('patches');

    const strip = await screen.findByLabelText('Patches by ecosystem');
    fireEvent.click(within(strip).getByRole('button', { name: /Windows/ }));
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ view: 'patches', ecosystem: 'WINDOWS' })));
  });

  it('lets analysts create workarounds but not read-only users', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([]));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    const { unmount } = renderPage('workarounds', ANALYST);
    fireEvent.click(await screen.findByRole('button', { name: 'New workaround' }));
    expect(screen.getByRole('region', { name: 'New fix' })).toBeInTheDocument();
    unmount();

    renderPage('workarounds', AUDITOR);
    await screen.findByRole('heading', { level: 1, name: 'Workarounds' });
    expect(screen.queryByRole('button', { name: 'New workaround' })).not.toBeInTheDocument();
  });

  it('does not offer creation on the patches view', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([]));
    renderPage('patches');
    await screen.findByText(/No patches yet/);
    expect(screen.queryByRole('button', { name: /New / })).not.toBeInTheDocument();
  });

  it('keeps metrics unavailable on a summary failure and allows recovery without losing rows', async () => {
    const loadSummary = vi.spyOn(fixIntelligenceApi, 'summary')
      .mockRejectedValueOnce(new Error('Unavailable'))
      .mockResolvedValue(summary({ totalFixes: 12 }));
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('all');

    expect(await screen.findByRole('alert')).toHaveTextContent('Fix summary could not be loaded');
    expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('—');
    expect(screen.getByRole('link', { name: 'KB5034441' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry summary' }));
    await waitFor(() => expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('12'));
    expect(loadSummary).toHaveBeenCalledTimes(2);
  });

  it('clears active filters and distinguishes filtered results from an empty patch catalog', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    const list = vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([]));
    renderPage('patches');
    await screen.findByText(/No patches yet/);
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'HIGH' } });
    expect(await screen.findByText('No fixes match these filters.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ severity: undefined })));
    expect(screen.getByLabelText('Severity')).toHaveValue('');
  });

  it('registers the view as the route title and renders no feature H1', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('patches');
    expect(await screen.findByRole('heading', { level: 1, name: 'Patches' })).toBeInTheDocument();
    await screen.findByText('KB5034441');
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 2, name: 'Fix catalog' })).toBeInTheDocument();
  });

  it('shows loading metrics as pending, not zero, and states the result scope', async () => {
    let resolveSummary: (value: ReturnType<typeof summary>) => void = () => undefined;
    vi.spyOn(fixIntelligenceApi, 'summary').mockReturnValue(new Promise((resolve) => { resolveSummary = resolve; }));
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue({ ...page([listItem()]), totalItems: 120, totalPages: 3 });
    renderPage('all');

    expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('Loading');
    expect(screen.getByText('Total Fixes').nextSibling).not.toHaveTextContent('0');
    expect(await screen.findByText('Showing 1–1 of 120 fixes')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Fix pages' })).toHaveTextContent('Page 1 of 3');
    resolveSummary(summary({ totalFixes: 0 }));
    await waitFor(() => expect(screen.getByText('Total Fixes').nextSibling).toHaveTextContent('0'));
  });

  it('links each fix through a real link rather than a clickable row', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('all');
    const link = await screen.findByRole('link', { name: 'KB5034441' });
    expect(link).toHaveAttribute('href', '/fix-intelligence/details/fix-1');
    expect(link.closest('tr')).not.toHaveAttribute('tabindex');
  });

  it('offers a retry when the fix list fails and keeps the filters', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    const list = vi.spyOn(fixIntelligenceApi, 'list')
      .mockRejectedValueOnce(new Error('Unavailable'))
      .mockResolvedValue(page([listItem()]));
    renderPage('all');
    expect(await screen.findByRole('alert')).toHaveTextContent('Fixes could not be loaded.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry fixes' }));
    expect(await screen.findByRole('link', { name: 'KB5034441' })).toBeInTheDocument();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('shows active filters as removable chips', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    const list = vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([listItem()]));
    renderPage('all');
    await screen.findByText('KB5034441');
    fireEvent.change(screen.getByLabelText('Severity'), { target: { value: 'CRITICAL' } });
    const chips = screen.getByRole('group', { name: 'Active fix filters' });
    fireEvent.click(within(chips).getByRole('button', { name: 'Remove filter Severity: Critical' }));
    expect(screen.getByLabelText('Severity')).toHaveValue('');
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ severity: undefined })));
  });
});
