import React from 'react';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { renderWithProviders } from '../../test/test-utils';
import { fixIntelligenceApi } from './api';
import { ANALYST, AUDITOR, TENANT_ADMIN, listItem, page, summary } from './fixtures';
import { FixIntelligencePage } from './FixIntelligencePage';
import type { FixView } from './types';

function renderPage(view: FixView, actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <FixIntelligencePage view={view} />
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
    await screen.findByText('Workarounds');
    expect(screen.queryByRole('button', { name: 'New workaround' })).not.toBeInTheDocument();
  });

  it('does not offer creation on the patches view', async () => {
    vi.spyOn(fixIntelligenceApi, 'summary').mockResolvedValue(summary());
    vi.spyOn(fixIntelligenceApi, 'list').mockResolvedValue(page([]));
    renderPage('patches');
    await screen.findByText(/No patches yet/);
    expect(screen.queryByRole('button', { name: /New / })).not.toBeInTheDocument();
  });
});
