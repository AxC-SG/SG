import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AiFindingsReferencePage } from './pages/AiFindingsReferencePage';
import { FindingsPage } from './pages/FindingsPage';
import { WorkbenchPage } from './pages/WorkbenchPage';
import { DesignPreviewApp } from './DesignPreviewApp';

afterEach(() => { localStorage.clear(); window.location.hash = ''; });

describe('Domain-preserving design parity', () => {
  it('renders AI Findings as its own route and combines its existing scope filters', () => {
    window.location.hash = '/findings/ai?severity=HIGH';
    render(<DesignPreviewApp />);
    expect(screen.getByRole('heading', { name: 'AI Findings' })).toBeInTheDocument();
    expect(screen.getByText('Severity: HIGH')).toBeInTheDocument();
    expect(screen.getByText('AIF-101B8AF0')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Cloud provider'), { target: { value: 'AWS' } });
    expect(screen.getByText('No matching AI findings')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Resolve' })).not.toBeInTheDocument();
  });

  it('keeps AI row navigation and return scope distinct from vulnerability row selection', () => {
    const navigate = vi.fn();
    render(<AiFindingsReferencePage route="/findings/ai?policyId=AZURE_RAI_POLICY_NON_BLOCKING_FILTER" onNavigate={navigate} />);
    fireEvent.click(screen.getByText('AIF-101B8AF0').closest('tr')!);
    expect(navigate).toHaveBeenCalledWith('/findings/ai/aif-1?returnTo=%2Ffindings%2Fai%3FpolicyId%3DAZURE_RAI_POLICY_NON_BLOCKING_FILTER');
    expect(screen.queryByRole('checkbox', { name: 'Select row' })).not.toBeInTheDocument();
  });

  it('uses the same Findings family presentation and toggles widget narrowing', () => {
    render(<FindingsPage onNavigate={vi.fn()} />);
    expect(within(screen.getByRole('navigation', { name: 'Findings family' })).getByRole('button', { name: 'Vulnerability Findings' })).toHaveAttribute('aria-current', 'page');
    const severity = screen.getByRole('button', { name: /^CRITICAL/ });
    fireEvent.click(severity);
    expect(screen.getByText('Severity: critical')).toBeInTheDocument();
    fireEvent.click(severity);
    expect(screen.queryByText('Severity: critical')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTitle('Filter Support Group'));
    fireEvent.change(screen.getByPlaceholderText('Search Support Group…'), { target: { value: 'no-such-team' } });
    expect(screen.getByText('No findings matched the current filters.')).toBeInTheDocument();
  });

  it('keeps computed impact visible when analyst disposition changes and guards unsaved rationale', () => {
    render(<WorkbenchPage onNavigate={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: 'Review Applicability' }));
    fireEvent.change(screen.getByLabelText('Impact for Public API gateway'), { target: { value: 'NOT_IMPACTED' } });
    expect(screen.getByText('Impacted', { selector: '.dp-badge' })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Analyst Rationale'), { target: { value: 'Keep this draft' } });
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Assessment workspace' })).getByRole('button', { name: 'Overview' }));
    expect(screen.getByRole('dialog', { name: 'Unsaved Changes' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Stay' }));
    expect(screen.getByLabelText('Analyst Rationale')).toHaveValue('Keep this draft');
  });

  it('does not offer email sending or an automatic generation mode in the workbench', () => {
    render(<WorkbenchPage onNavigate={vi.fn()} />);
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Assessment workspace' })).getByRole('button', { name: 'Notify Groups' }));
    expect(screen.getByText('Email delivery is not connected')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Download notification drafts' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Send email/ })).not.toBeInTheDocument();
  });
});
