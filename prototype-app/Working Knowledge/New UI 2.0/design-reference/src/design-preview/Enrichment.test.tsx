import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DesignPreviewApp } from './DesignPreviewApp';
import { DEFAULT_PREVIEW, PreviewContext, type PreviewState } from './previewContext';
import { WorkbenchPage } from './pages/WorkbenchPage';
import { AiAssetPage } from './pages/AiAssetPage';
import { PolicyDistributionPage } from './pages/PolicyDistributionPage';
import { InventoryReferencePage } from './pages/InventoryReferencePage';
import { ConnectPage } from './pages/ConnectPage';
import { Modal } from './components/overlays';
import { Drawer, Popover } from './components/primitives';
import { Field, TextInput } from './components/forms';

function fixture(children: React.ReactNode, state: Partial<PreviewState> = {}) {
  return render(<PreviewContext.Provider value={{ ...DEFAULT_PREVIEW, ...state }}>{children}</PreviewContext.Provider>);
}

afterEach(() => { window.location.hash = ''; localStorage.clear(); });

describe('Enriched reference workflows', () => {
  it('starts at a review hub with the new compositions and baseline enhancements disabled', () => {
    render(<DesignPreviewApp />);
    expect(screen.getByRole('heading', { name: 'A clearer view of complex security work.' })).toBeInTheDocument();
    for (const name of ['CVE assessment workbench', 'AI asset detail', 'Policy distribution', 'Inventory & lifecycle', 'States & permissions']) {
      expect(screen.getByRole('button', { name: new RegExp(name) })).toBeInTheDocument();
    }
    fireEvent.keyDown(window, { key: 'k', metaKey: true });
    expect(screen.queryByPlaceholderText(/Search pages/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Toggle sidebar' })).not.toBeInTheDocument();
  });

  it('allows partial assessments and creates findings for eligible assets', async () => {
    fixture(<WorkbenchPage onNavigate={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Review Applicability' }));
    expect(screen.getByLabelText('Applicability for Legacy reporting')).toHaveValue('NEEDS_REVIEW');
    const proceed = screen.getByRole('button', { name: 'Proceed to Findings' });
    expect(proceed).toBeEnabled();
    fireEvent.click(proceed);
    await screen.findByText('Assessment saved in the mock.');
    fireEvent.click(screen.getByRole('button', { name: 'Create Findings' }));
    expect(screen.getByLabelText('Finding Creation Mode')).toHaveValue('ASSET_CVE');
    fireEvent.click(screen.getByRole('button', { name: 'Confirm creation' }));
    expect(await screen.findByRole('heading', { name: 'Impacted Assets' })).toBeInTheDocument();
    expect(await screen.findByText('Finding creation completed in the mock.')).toBeInTheDocument();
  });

  it('preserves separate decisions when an applicability save fails', async () => {
    fixture(<WorkbenchPage onNavigate={vi.fn()} />, { scenario: 'save-error' });
    fireEvent.click(screen.getByRole('button', { name: 'Review Applicability' }));
    fireEvent.change(screen.getByLabelText('Applicability for Legacy reporting'), { target: { value: 'APPLICABLE' } });
    fireEvent.change(screen.getByLabelText('Impact for Legacy reporting'), { target: { value: 'NOT_IMPACTED' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save Assessment' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Your edits are retained');
    expect(screen.getByLabelText('Applicability for Legacy reporting')).toHaveValue('APPLICABLE');
    expect(screen.getByLabelText('Impact for Legacy reporting')).toHaveValue('NOT_IMPACTED');
  });

  it('applies read-only controls to the workbench composition', () => {
    fixture(<WorkbenchPage onNavigate={vi.fn()} />, { role: 'READ_ONLY_AUDITOR' });
    fireEvent.click(screen.getByRole('button', { name: 'Review Applicability' }));
    expect(screen.getByLabelText('Applicability for Legacy reporting')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Proceed to Findings' })).toBeDisabled();
  });

  it('excludes asset details when the AI entitlement is unavailable', () => {
    fixture(<AiAssetPage onNavigate={vi.fn()} />, { aiEntitled: false });
    expect(screen.getByText('AI Security is unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'support-agent' })).not.toBeInTheDocument();
  });

  it('shows explicit unverified provenance in the AI evidence drawer', () => {
    fixture(<AiAssetPage onNavigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Evidence fixture'), { target: { value: 'unverified' } });
    fireEvent.click(screen.getByRole('button', { name: 'Inspect evidence' }));
    const drawer = screen.getByRole('dialog', { name: 'Source evidence' });
    expect(within(drawer).getByText('Unverified')).toBeInTheDocument();
    expect(within(drawer).getByText(/not runtime execution/)).toBeInTheDocument();
  });

  it('gates policy publication on dev/test and approval, and excludes suspended tenants', async () => {
    fixture(<PolicyDistributionPage route="/platform/ai-policies/tool-access" onNavigate={vi.fn()} />, { scope: 'platform' });
    expect(screen.getByRole('button', { name: 'Publish policy' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Approve with evidence' })).toBeDisabled();
    expect(screen.getByRole('option', { name: /Globex Industries/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Deploy to dev/test' }));
    await screen.findByText('Dev/test validation completed in the mock.');
    fireEvent.change(screen.getByLabelText('Approval evidence note'), { target: { value: 'Validated the selected cohort using static sample evidence.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Approve with evidence' }));
    await screen.findByText('Policy approval recorded in the mock.');
    fireEvent.click(screen.getByRole('radio', { name: 'All active tenants' }));
    fireEvent.click(screen.getByRole('button', { name: 'Publish policy' }));
    const modal = screen.getByRole('dialog', { name: 'Publish to all active tenants?' });
    expect(within(modal).getByText('Acme Corporation')).toBeInTheDocument();
    expect(within(modal).getByText('Initech Demo')).toBeInTheDocument();
    expect(within(modal).queryByText(/Globex/)).not.toBeInTheDocument();
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm publication' }));
    expect(await screen.findByText('Tenant rollout jobs')).toBeInTheDocument();
    expect(screen.getAllByText('SUCCEEDED')).toHaveLength(2);
  });

  it('retains policy notes and allows retry when saving fails', async () => {
    fixture(<PolicyDistributionPage route="/platform/ai-policies/tool-access" onNavigate={vi.fn()} />, { scope: 'platform', scenario: 'save-error' });
    fireEvent.change(screen.getByLabelText('Approval evidence note'), { target: { value: 'Keep this draft note.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Deploy to dev/test' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Your edits are retained');
    expect(screen.getByLabelText('Approval evidence note')).toHaveValue('Keep this draft note.');
    expect(screen.getByRole('button', { name: 'Deploy to dev/test' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Publish policy' })).toBeDisabled();
  });

  it('keeps successful context visible and retries a failed tenant rollout', async () => {
    fixture(<PolicyDistributionPage route="/platform/ai-policies/tool-access" onNavigate={vi.fn()} />, { scope: 'platform', scenario: 'partial-error' });
    fireEvent.click(screen.getByRole('button', { name: 'Deploy to dev/test' }));
    await screen.findByText('Dev/test validation completed in the mock.');
    fireEvent.change(screen.getByLabelText('Approval evidence note'), { target: { value: 'Static evidence reviewed.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Approve with evidence' }));
    await screen.findByText('Policy approval recorded in the mock.');
    fireEvent.click(screen.getByRole('button', { name: 'Publish policy' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm publication' }));
    const retry = await screen.findByRole('button', { name: 'Retry rollout' });
    expect(screen.getByText('FAILED')).toBeInTheDocument();
    fireEvent.click(retry);
    expect(await screen.findByText('SUCCEEDED')).toBeInTheDocument();
    expect(screen.queryByText('FAILED')).not.toBeInTheDocument();
  });

  it('withholds workspace records when blocked and lets the reviewer reset the fixture', () => {
    window.location.hash = '/inventory/overview';
    render(<DesignPreviewApp />);
    fireEvent.click(screen.getByRole('button', { name: 'Reference controls' }));
    fireEvent.change(screen.getByLabelText('Reference scenario'), { target: { value: 'blocked' } });
    expect(screen.getByText('Workspace access is blocked')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Reset preview' }));
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('retains full identifiers in a named lifecycle drawer and handles no matches', () => {
    fixture(<InventoryReferencePage onNavigate={vi.fn()} />);
    fireEvent.change(screen.getByLabelText('Search inventory'), { target: { value: 'openssl' } });
    fireEvent.click(screen.getByRole('button', { name: 'Open detail' }));
    const drawer = screen.getByRole('dialog', { name: 'OpenSSL' });
    expect(within(drawer).getByText('cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*')).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole('button', { name: 'Close detail' }));
    fireEvent.change(screen.getByLabelText('Search inventory'), { target: { value: 'no-match-for-this-value' } });
    expect(screen.getByText('No software matches these filters')).toBeInTheDocument();
  });

  it('does not expose configuration for contained connectors or retired patch entries', () => {
    const view = fixture(<ConnectPage route="/connect/azure-discovery" onNavigate={vi.fn()} />);
    expect(screen.getByText('Connector unavailable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Test Connection' })).not.toBeInTheDocument();
    view.rerender(<PreviewContext.Provider value={DEFAULT_PREVIEW}><ConnectPage route="/connect" onNavigate={vi.fn()} /></PreviewContext.Provider>);
    expect(screen.queryByRole('heading', { name: 'Patch Management' })).not.toBeInTheDocument();
  });
});

describe('Shared interaction contracts', () => {
  it('traps focus, keeps focus stable during edits, and restores the trigger', async () => {
    function Harness() {
      const [open, setOpen] = React.useState(false);
      const [value, setValue] = React.useState('');
      return <><button type="button" onClick={() => setOpen(true)}>Open dialog</button><Modal open={open} onClose={() => setOpen(false)} title="Focus fixture" footer={<button type="button" onClick={() => setOpen(false)}>Done</button>}><input aria-label="Editable note" value={value} onChange={e => setValue(e.target.value)} /><input aria-label="Second field" /></Modal></>;
    }
    render(<Harness />);
    const trigger = screen.getByRole('button', { name: 'Open dialog' });
    trigger.focus(); fireEvent.click(trigger);
    const dialog = screen.getByRole('dialog', { name: 'Focus fixture' });
    const last = within(dialog).getByRole('button', { name: 'Done' });
    last.focus(); fireEvent.keyDown(last, { key: 'Tab' });
    expect(within(dialog).getByRole('button', { name: 'Close' })).toHaveFocus();
    fireEvent.keyDown(document.activeElement!, { key: 'Tab', shiftKey: true });
    expect(last).toHaveFocus();
    const second = screen.getByLabelText('Second field'); second.focus();
    fireEvent.change(screen.getByLabelText('Editable note'), { target: { value: 'Retained' } });
    expect(second).toHaveFocus();
    fireEvent.keyDown(second, { key: 'Escape' });
    await waitFor(() => expect(trigger).toHaveFocus());
  });

  it('unmounts closed drawers so their controls are not keyboard targets', () => {
    render(<Drawer open={false} onClose={vi.fn()} title="Closed drawer"><button type="button">Hidden action</button></Drawer>);
    expect(screen.queryByText('Hidden action')).not.toBeInTheDocument();
  });

  it('renders popovers outside clipping containers and closes on Escape', () => {
    render(<div className="dp-table-card"><Popover trigger={({ toggle }) => <button type="button" onClick={toggle}>Filter fixture</button>}>{() => <button type="button">Critical fixture option</button>}</Popover></div>);
    const trigger = screen.getByRole('button', { name: 'Filter fixture' });
    fireEvent.click(trigger);
    expect(screen.getByRole('button', { name: 'Critical fixture option' }).closest('.dp-table-card')).toBeNull();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByText('Critical fixture option')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it('associates validation errors and required state with the native input', () => {
    render(<Field label="Tenant slug" error="Slug is already in use" required><TextInput /></Field>);
    const input = screen.getByRole('textbox', { name: 'Tenant slug' });
    expect(input).toBeRequired();
    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(input).toHaveAccessibleDescription('Slug is already in use');
  });
});
