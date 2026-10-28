import React from 'react';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '../../api/client';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { renderWithProviders } from '../../test/test-utils';
import { fixIntelligenceApi } from './api';
import { ANALYST, TENANT_ADMIN, detail } from './fixtures';
import { FixDetailPage } from './FixDetailPage';

function renderPage(actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <Routes>
        <Route path="/fix-intelligence/details/:fixId" element={<FixDetailPage />} />
      </Routes>
    </ActorContextState.Provider>,
    { route: '/fix-intelligence/details/fix-9' }
  );
}

describe('FixDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders imported text as plain text, never HTML', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    const { container } = renderPage();
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByText('KEV')).toBeInTheDocument();
  });

  it('lets a different admin approve a proposal', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    const approve = vi.spyOn(fixIntelligenceApi, 'approve').mockResolvedValue(detail({ status: 'ACTIVE' }));
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(approve).toHaveBeenCalledWith('fix-9'));
  });

  it('disables approval of your own proposal and hides it from analysts', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ proposedBy: 'admin-1' }));
    const { unmount } = renderPage();
    expect(await screen.findByRole('button', { name: 'Approve' })).toBeDisabled();
    unmount();

    renderPage(ANALYST);
    await screen.findByText('Disable SMBv1');
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it('shows the server reason when approval is refused', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    vi.spyOn(fixIntelligenceApi, 'approve').mockRejectedValue(new Error('A fix must be approved by someone other than its proposer'));
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('someone other than its proposer');
  });

  it('treats patch-tool fixes as read-only and only links https advisories', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({
      fixType: 'PATCH',
      origin: 'PATCH_TOOL',
      editable: false,
      status: 'ACTIVE',
      control: null,
      patchSources: [
        { provider: 'SCCM', externalId: '16801234', kbArticle: '5034441', bulletinId: null, vendor: 'Microsoft', product: null,
          classification: null, vendorSeverity: 'Critical', releaseDate: null, superseded: false,
          infoUrl: 'javascript:alert(1)', lastSeenAt: null }
      ]
    }));
    renderPage();
    expect(await screen.findByText(/Imported from your patch tools/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Advisory' })).not.toBeInTheDocument();
    expect(screen.getByText('KB5034441')).toBeInTheDocument();
  });

  it('edits a control and validates CVE ids before saving', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ status: 'ACTIVE' }));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    const update = vi.spyOn(fixIntelligenceApi, 'update').mockResolvedValue(detail());
    renderPage(ANALYST);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(screen.getByText(/sends it back for approval/)).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText(/CVE-2024-21412/), { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('NOPE is not a CVE ID');
    expect(update).not.toHaveBeenCalled();

    fireEvent.change(screen.getByPlaceholderText(/CVE-2024-21412/), { target: { value: 'cve-2017-0144' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
    await waitFor(() => expect(update).toHaveBeenCalledWith('fix-9', expect.objectContaining({
      cveIds: ['CVE-2017-0144'], submit: true, version: 0
    })));
  });

  it('shows not found for a missing fix', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockRejectedValue(new ApiError('Fix not found', 404));
    renderPage();
    expect(await screen.findByText('This fix was not found.')).toBeInTheDocument();
  });

  it('distinguishes a service failure from a missing fix and offers a retry', async () => {
    const load = vi.spyOn(fixIntelligenceApi, 'detail').mockRejectedValueOnce(new ApiError('Unavailable', 503))
      .mockResolvedValue(detail());
    renderPage();
    expect(await screen.findByRole('alert')).toHaveTextContent('This fix could not be loaded.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry fix' }));
    expect(await screen.findByText('Disable SMBv1')).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(2);
  });
});
