import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { DesignPreviewApp } from './DesignPreviewApp';

// The design reference is the visual contract for the UI modernisation. These tests pin
// the behaviours it promises to keep (labels, roles, disabled rules, inline forms) so the
// reference cannot silently drift from the live app's interaction model.

function renderAt(route: string) {
  window.location.hash = route;
  return render(<DesignPreviewApp />);
}

function go(route: string) {
  act(() => {
    window.location.hash = route;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
  });
}

describe('DesignPreviewApp', () => {
  afterEach(() => {
    localStorage.clear();
    window.location.hash = '';
  });

  it('renders the Exposure Dashboard with the live KPI set and drills into Findings', async () => {
    renderAt('/exposure');
    expect(screen.getByRole('heading', { name: 'Exposure Dashboard' })).toBeInTheDocument();
    for (const label of ['Critical Findings', 'Open Findings', 'Impacted CVEs', 'CISA KEV Exposure', 'Needs Attention', 'EOL Software']) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getByText('Grid Exposure')).toBeInTheDocument();
    expect(screen.getByText('Where Attention Is Required')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Critical Findings/ }));
    expect(await screen.findByRole('heading', { name: 'Findings' })).toBeInTheDocument();
  });

  it('defaults to the dark theme like App.tsx and toggles with the same aria-labels', () => {
    renderAt('/exposure');
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    fireEvent.click(screen.getByRole('button', { name: 'Switch to light theme' }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('scoutai-theme')).toBe('light');
    expect(screen.getByRole('button', { name: 'Switch to dark theme' })).toBeInTheDocument();
  });

  it('keeps Findings bulk actions visible but disabled until a row is selected', () => {
    renderAt('/findings');
    const resolve = screen.getByRole('button', { name: 'Resolve' });
    expect(resolve).toBeDisabled();
    fireEvent.click(screen.getAllByRole('checkbox', { name: 'Select row' })[0]);
    expect(resolve).toBeEnabled();

    fireEvent.click(screen.getByTitle('More actions'));
    const menu = screen.getByRole('menu');
    for (const item of ['+ Create Incident', 'Defer', 'False Positive', 'Duplicate', 'Assign to…', 'Re-open', 'Delete']) {
      expect(within(menu).getByRole('menuitem', { name: item })).toBeEnabled();
    }
    fireEvent.click(within(menu).getByRole('menuitem', { name: '+ Create Incident' }));
    const dialog = screen.getByRole('dialog', { name: 'Create Incident' });
    expect(within(dialog).getByLabelText('Assigned To')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }));
    expect(screen.getByText('Create Incident: 1 finding updated.')).toBeInTheDocument();
  });

  it('applies header column filters as removable chips', () => {
    renderAt('/findings');
    fireEvent.click(screen.getByTitle('Filter Severity'));
    fireEvent.click(screen.getByRole('checkbox', { name: 'critical' }));
    expect(screen.getByText('Severity: critical')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Remove filter' }));
    expect(screen.queryByText('Severity: critical')).not.toBeInTheDocument();
  });

  it('groups findings and saves the current view as a queue', () => {
    renderAt('/findings');
    fireEvent.change(screen.getByLabelText('Group by'), { target: { value: 'status' } });
    fireEvent.click(screen.getByRole('button', { name: /^Closed/, pressed: false }));
    expect(screen.getByText('Status: Closed')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Save Current View' }));
    const dialog = screen.getByRole('dialog', { name: 'Save Current View' });
    const save = within(dialog).getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText('Title'), { target: { value: 'My critical queue' } });
    fireEvent.click(save);
    for (const label of ['Edit Queue', 'Duplicate Queue', 'Set Default', 'Delete Queue']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
    }
  });

  it('renders the record detail pattern with status-dependent actions and tabs', () => {
    renderAt('/findings/F-10420');
    expect(screen.getByRole('heading', { name: 'F-10420' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Under Investigation' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /^Unassigned|Priya Raman/ }));
    expect(screen.getByPlaceholderText('username or email')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('tab', { name: /Affected Assets/ }));
    expect(screen.getByRole('columnheader', { name: 'Asset' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
  });

  it('opens a connector and verifies the connection inline', async () => {
    renderAt('/connect');
    expect(screen.getByRole('heading', { name: 'Inventory' })).toBeInTheDocument();
    expect(screen.getAllByRole('img', { name: /Failing/ }).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: /AWS Discovery/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'Test Connection' }));
    expect(await screen.findByText(/Connection verified/, undefined, { timeout: 2000 })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('radio', { name: /Access keys/ }));
    expect(screen.getByText('Secret is required when using access keys.')).toBeInTheDocument();
    go('/connect/run-history');
    expect(screen.getByText('Inventory Integration Run History')).toBeInTheDocument();
  });

  it('blocks Save when Findings Score weights do not sum to 1.0', () => {
    renderAt('/configurations/findings-score');
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
    fireEvent.change(screen.getByLabelText('Weight 1'), { target: { value: '0.9' } });
    expect(screen.getByRole('alert')).toHaveTextContent('Weights must sum to 1.0');
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
  });

  it('keeps the triage sliders and policy sections reachable', () => {
    renderAt('/configurations/triage');
    const slider = screen.getByRole('slider', { name: 'Exploitability weight' });
    fireEvent.change(slider, { target: { value: '2' } });
    expect(screen.getAllByText('×2.0').length).toBeGreaterThan(0);
    go('/configurations/sla');
    expect(screen.getByRole('heading', { name: 'SLA & Remediation' })).toBeInTheDocument();
    go('/configurations/automation');
    expect(screen.getByRole('switch', { name: /Auto-close resolved findings/ })).toBeChecked();
    go('/configurations/suppress');
    fireEvent.click(screen.getAllByRole('button', { name: /Delete/ })[0]);
    expect(screen.getByRole('dialog', { name: 'Delete rule?' })).toBeInTheDocument();
  });

  it('keeps the create-tenant form inline with its existing accessible names', () => {
    renderAt('/platform/tenants');
    for (const label of ['Tenant name', 'Tenant slug', 'Billing reference', 'Demo owner email', 'Demo owner password']) {
      expect(screen.getByLabelText(label)).toBeInTheDocument();
    }
    expect(screen.getByRole('button', { name: 'Retry provisioning' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Delete' })[0]).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Create Tenant' }));
    expect(screen.getByRole('button', { name: 'Creating...' })).toBeDisabled();
  });

  it('gates the login button on both fields like LoginPage', () => {
    renderAt('/login');
    const signIn = screen.getByRole('button', { name: 'Sign in' });
    expect(signIn).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'analyst@acme.example' } });
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'hunter22' } });
    expect(signIn).toBeEnabled();
  });

  it('renders the component library including dialogs and the graph', async () => {
    renderAt('/components');
    expect(screen.getByRole('heading', { name: 'Component Library' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm (type-to-confirm)' }));
    const confirm = screen.getByRole('dialog', { name: 'Delete tenant?' });
    const del = within(confirm).getByRole('button', { name: 'Delete tenant' });
    expect(del).toBeDisabled();
    fireEvent.change(within(confirm).getByLabelText('Type acme to confirm'), { target: { value: 'acme' } });
    expect(del).toBeEnabled();
    expect(await screen.findByText('payments-api-key')).toBeInTheDocument();
  });

  it('exposes the account menu, persona preview and placeholder routes', () => {
    renderAt('/exposure');
    fireEvent.click(screen.getByRole('button', { name: 'Open account menu' }));
    fireEvent.click(screen.getByRole('menuitem', { name: /Impersonate User/ }));
    const dialog = screen.getByRole('dialog', { name: 'Impersonate User' });
    fireEvent.click(within(dialog).getAllByRole('button', { name: 'Preview UI' })[0]);
    expect(screen.getByText('UI preview only - backend authorization still uses the current real session.')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Expand Inventory sections' }));
    fireEvent.click(screen.getByRole('button', { name: 'Hosts' }));
    go('/x/inventory/hosts');
    expect(screen.getByRole('heading', { name: 'Hosts' })).toBeInTheDocument();
    expect(screen.getByText('/inventory/hosts')).toBeInTheDocument();
  });

  it('filters the command palette and runs the selected command', () => {
    renderAt('/exposure');
    fireEvent.click(screen.getByRole('button', { name: 'Reference controls' }));
    fireEvent.click(screen.getByRole('checkbox', { name: 'Optional UI enhancements' }));
    fireEvent.keyDown(window, { key: 'k', metaKey: true });
    const input = screen.getByPlaceholderText(/Search pages/);
    fireEvent.change(input, { target: { value: 'connectors' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(window.location.hash).toBe('#/connect');
  });
});
