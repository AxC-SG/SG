import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { intelligenceApi } from '../features/intelligence/api';
import type { VulnIntelSourceStatus } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { VulnIntelConfigPage } from './VulnIntelConfigPage';

const status = (value: VulnIntelSourceStatus['status']): VulnIntelSourceStatus => ({ status: value, recordsInserted: 12, recordsUpdated: 3, recordsFetched: 15 });
const summary = { sources: { NVD: status('completed'), KEV: status('failed'), GHSA: status('running'), OSV: status('never') } };

beforeEach(() => {
  vi.spyOn(intelligenceApi, 'schedules').mockResolvedValue([
    { sync_type: 'KEV', enabled: true, interval_hours: 24, next_due_at: null },
    { sync_type: 'EOL_FULL_REFRESH', enabled: true, interval_hours: 48, next_due_at: null },
    { sync_type: 'EOL_DATE_SWEEP', enabled: false, interval_hours: 12, next_due_at: null },
  ]);
});
afterEach(() => vi.restoreAllMocks());

const card = (name: string) => screen.getByRole('button', { name: new RegExp(name) });

describe('Platform feed catalog', () => {
  it('groups all integrations and distinguishes completed, failed, running, and unconfigured sources', () => {
    renderWithProviders(<VulnIntelConfigPage vulnSummary={summary} />);
    expect(screen.getByText('11 integrations')).toBeInTheDocument();
    expect(screen.getAllByRole('button')).toHaveLength(11);
    expect(within(card('NVD Vulnerability Feed')).getByText('Synced')).toBeInTheDocument();
    expect(within(card('CISA KEV Feed')).getByText('Sync failed')).toBeInTheDocument();
    expect(within(card('GitHub Advisory')).getByText('Syncing')).toBeInTheDocument();
    expect(within(card('OSV advisories')).getByText('Never synced')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Run integration now' })).not.toBeInTheDocument();
    expect(intelligenceApi.schedules).not.toHaveBeenCalled();
  });

  it('searches across groups and recovers from an empty result', () => {
    renderWithProviders(<VulnIntelConfigPage vulnSummary={summary} />);
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'Japanese' } });
    expect(card('JVN Feed')).toBeInTheDocument();
    expect(screen.queryByText('NVD Vulnerability Feed')).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'missing feed' } });
    expect(screen.getByRole('status')).toHaveTextContent('No integrations match');
    fireEvent.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(screen.getByText('NVD Vulnerability Feed')).toBeInTheDocument();
  });

  it('opens only the selected controls, saves its schedule, queues its integration, and restores card focus', async () => {
    vi.spyOn(intelligenceApi, 'saveSchedule').mockResolvedValue({ sync_type: 'KEV', enabled: true, interval_hours: 36, next_due_at: null });
    vi.spyOn(api, 'syncKev').mockResolvedValue({ runId: 'run-kev', status: 'QUEUED', message: 'Ready for ingestion' });
    vi.spyOn(api, 'syncNvd');
    renderWithProviders(<VulnIntelConfigPage vulnSummary={summary} />);
    fireEvent.click(card('CISA KEV Feed'));
    expect(screen.getByRole('heading', { name: 'CISA KEV Feed' })).toHaveFocus();
    expect(await screen.findByLabelText('Interval in hours')).toHaveValue(24);
    fireEvent.change(screen.getByLabelText('Interval in hours'), { target: { value: '36' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save interval' }));
    await waitFor(() => expect(intelligenceApi.saveSchedule).toHaveBeenCalledWith('KEV', true, 36));
    fireEvent.click(screen.getByRole('button', { name: 'Run integration now' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Integration queued. Ready for ingestion');
    expect(api.syncKev).toHaveBeenCalledOnce();
    expect(api.syncNvd).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Back to sources' }));
    expect(card('CISA KEV Feed')).toHaveFocus();
  });

  it('supports direct feed links and reports integration errors', async () => {
    vi.spyOn(intelligenceApi, 'trigger').mockRejectedValue(new Error('Feed temporarily unavailable'));
    renderWithProviders(<VulnIntelConfigPage vulnSummary={summary} />, { route: '/platform/vuln-intel?feed=osv' });
    expect(screen.getByRole('heading', { name: 'OSV advisories' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Run integration now' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Feed temporarily unavailable');
    expect(intelligenceApi.trigger).toHaveBeenCalledWith('OSV');
  });

  it('keeps both EOL schedules and every refresh job available', async () => {
    renderWithProviders(<VulnIntelConfigPage vulnSummary={summary} />, { route: '/platform/vuln-intel?feed=eol' });
    expect(await screen.findAllByLabelText('Interval in hours')).toHaveLength(2);
    expect(screen.getAllByLabelText('Interval in hours').map((field) => (field as HTMLInputElement).value)).toEqual(['48', '12']);
    for (const name of ['Run Full EOL Refresh', 'Refresh Product Catalog', 'Refresh Release Cycles', 'Resolve Inventory Mappings', 'Denormalize EOL Status']) {
      expect(screen.getByRole('button', { name })).toBeInTheDocument();
    }
  });

  it('shows unavailable status when the summary could not load', () => {
    renderWithProviders(<VulnIntelConfigPage loadError="Unable to load source status." />);
    expect(screen.getByRole('alert')).toHaveTextContent('Unable to load source status');
    expect(within(card('NVD Vulnerability Feed')).getByText('Status unavailable')).toBeInTheDocument();
  });
});
