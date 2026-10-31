import React from 'react';
import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '../../api/client';
import { PageHeaderProvider } from '../../app/PageHeader';
import { useRouteHeader } from '../../app/pageHeaderState';
import { ActorContextState } from '../auth/context';
import type { ActorContext } from '../auth/types';
import { renderWithProviders } from '../../test/test-utils';
import { fixIntelligenceApi } from './api';
import { ANALYST, TENANT_ADMIN, detail } from './fixtures';
import { FixDetailPage } from './FixDetailPage';

// Stands in for the shell, which renders the only route H1 from the page's registration.
function ShellTitle() {
  const { pathname } = useLocation();
  return <h1>{useRouteHeader(pathname, 'Fix Intelligence').title}</h1>;
}

function renderPage(actor: ActorContext = TENANT_ADMIN) {
  return renderWithProviders(
    <ActorContextState.Provider value={actor}>
      <PageHeaderProvider>
        <ShellTitle />
        <Routes>
          <Route path="/fix-intelligence/details/:fixId" element={<FixDetailPage />} />
        </Routes>
      </PageHeaderProvider>
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
    expect(await screen.findByText('Fix approved. Status: Active.')).toBeInTheDocument();
  });

  it('disables approval of your own proposal and hides it from analysts', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ proposedBy: 'admin-1' }));
    const { unmount } = renderPage();
    expect(await screen.findByRole('button', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Approve' })).toHaveAccessibleDescription(
      'You proposed this fix, so another tenant administrator must approve it.'
    );
    unmount();

    renderPage(ANALYST);
    await screen.findByRole('heading', { level: 1, name: 'Disable SMBv1' });
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.getByText(/Awaiting approval\. A tenant administrator other than the proposer/)).toBeInTheDocument();
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
    const activeNotice = screen.getByText(/Saving any change returns it to Proposed/);
    expect(activeNotice).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Submit for approval' })).toHaveAccessibleDescription(activeNotice.textContent ?? '');

    fireEvent.change(screen.getByPlaceholderText(/CVE-2024-21412/), { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('NOPE is not a CVE ID');
    expect(screen.getByPlaceholderText(/CVE-2024-21412/)).toHaveAttribute('aria-invalid', 'true');
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
    expect(await screen.findByRole('heading', { level: 1, name: 'Disable SMBv1' })).toBeInTheDocument();
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('registers the fix title as the route title and renders no feature H1', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    renderPage();
    expect(await screen.findByRole('heading', { level: 1, name: 'Disable SMBv1' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 2, name: 'Overview' })).toBeInTheDocument();
  });

  it('confirms before retiring, keeps the dialog on failure and reports the result', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ status: 'ACTIVE' }));
    const retire = vi.spyOn(fixIntelligenceApi, 'retire')
      .mockRejectedValueOnce(new Error('Fix was changed by someone else'))
      .mockResolvedValue(detail({ status: 'RETIRED' }));
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Retire' }));
    expect(retire).not.toHaveBeenCalled();
    const dialog = screen.getByRole('dialog', { name: 'Retire this fix?' });

    fireEvent.click(within(dialog).getByRole('button', { name: 'Retire fix' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Fix was changed by someone else');
    expect(screen.getByRole('dialog', { name: 'Retire this fix?' })).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole('button', { name: 'Retire fix' }));
    expect(await screen.findByText('Fix retired. Status: Retired.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Retire this fix?' })).not.toBeInTheDocument();
    expect(retire).toHaveBeenCalledTimes(2);
  });

  it('cancelling retirement makes no request', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ status: 'ACTIVE' }));
    const retire = vi.spyOn(fixIntelligenceApi, 'retire').mockResolvedValue(detail({ status: 'RETIRED' }));
    renderPage();
    fireEvent.click(await screen.findByRole('button', { name: 'Retire' }));
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Retire this fix?' })).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('dialog', { name: 'Retire this fix?' })).not.toBeInTheDocument();
    expect(retire).not.toHaveBeenCalled();
  });

  it('marks unsaved form changes and asks before discarding them', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    renderPage(ANALYST);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('region', { name: 'Edit fix' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText(/^Title/), { target: { value: 'Disable SMBv1 everywhere' } });
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    const dialog = screen.getByRole('dialog', { name: 'Discard unsaved changes?' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Keep editing' }));
    expect(screen.getByLabelText(/^Title/)).toHaveValue('Disable SMBv1 everywhere');

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    fireEvent.click(within(screen.getByRole('dialog', { name: 'Discard unsaved changes?' })).getByRole('button', { name: 'Discard changes' }));
    expect(screen.queryByRole('region', { name: 'Edit fix' })).not.toBeInTheDocument();
  });

  it('flags a missing title on the field and does not save', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail());
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    const update = vi.spyOn(fixIntelligenceApi, 'update').mockResolvedValue(detail());
    renderPage(ANALYST);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.change(screen.getByLabelText(/^Title/), { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('A title is required.');
    expect(screen.getByLabelText(/^Title/)).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText(/^Title/)).toHaveAccessibleDescription('A title is required.');
    expect(update).not.toHaveBeenCalled();
  });

  it('reports the saved status after an edit', async () => {
    vi.spyOn(fixIntelligenceApi, 'detail').mockResolvedValue(detail({ status: 'ACTIVE' }));
    vi.spyOn(api, 'listAssets').mockResolvedValue([]);
    vi.spyOn(fixIntelligenceApi, 'update').mockResolvedValue(detail({ status: 'PROPOSED' }));
    renderPage(ANALYST);
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    fireEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
    expect(await screen.findByText('Changes saved. Status: Proposed.')).toBeInTheDocument();
  });
});
