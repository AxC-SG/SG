import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { EolSourcePanel } from './EolSourcePanel';

describe('EolSourcePanel', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders all five job trigger buttons', () => {
    renderWithProviders(<EolSourcePanel />);
    expect(screen.getByRole('button', { name: /run full eol refresh/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /refresh product catalog/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /refresh release cycles/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /resolve inventory mappings/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /denormalize eol status/i })).toBeInTheDocument();
  });

  it('renders an Open EOL Catalog link', () => {
    renderWithProviders(<EolSourcePanel />);
    expect(screen.getByRole('link', { name: /open eol catalog/i })).toBeInTheDocument();
  });

  it('renders a custom title', () => {
    renderWithProviders(<EolSourcePanel title="My EOL Source" />);
    expect(screen.getByText('My EOL Source')).toBeInTheDocument();
  });

  it('calls triggerEolFullRefresh when full refresh button is clicked', async () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockResolvedValue(undefined as never);
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /run full eol refresh/i }).click();
    await waitFor(() => expect(api.triggerEolFullRefresh).toHaveBeenCalledOnce());
  });

  it('calls triggerEolCatalogRefresh when catalog button is clicked', async () => {
    vi.spyOn(api, 'triggerEolCatalogRefresh').mockResolvedValue(undefined as never);
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /refresh product catalog/i }).click();
    await waitFor(() => expect(api.triggerEolCatalogRefresh).toHaveBeenCalledOnce());
  });

  it('calls triggerEolReleaseRefresh when releases button is clicked', async () => {
    vi.spyOn(api, 'triggerEolReleaseRefresh').mockResolvedValue(undefined as never);
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /refresh release cycles/i }).click();
    await waitFor(() => expect(api.triggerEolReleaseRefresh).toHaveBeenCalledOnce());
  });

  it('shows Running... on the clicked button while the job is in progress', () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<EolSourcePanel />);
    fireEvent.click(screen.getByRole('button', { name: /run full eol refresh/i }));
    expect(screen.getByText('Running...')).toBeInTheDocument();
  });

  it('disables all buttons while any job is running', () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockReturnValue(new Promise(() => {}));
    renderWithProviders(<EolSourcePanel />);
    fireEvent.click(screen.getByRole('button', { name: /run full eol refresh/i }));
    const buttons = screen.getAllByRole('button');
    buttons.forEach((btn) => expect(btn).toBeDisabled());
  });

  it('shows completed message after a successful job', async () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockResolvedValue(undefined as never);
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /run full eol refresh/i }).click();
    await waitFor(() =>
      expect(screen.getByText(/run full eol refresh completed/i)).toBeInTheDocument()
    );
  });

  it('shows queued message when response includes a runId', async () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockResolvedValue(
      { runId: 'abc-123', status: 'running', message: 'initializing' } as never
    );
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /run full eol refresh/i }).click();
    await waitFor(() =>
      expect(screen.getByText(/queued.*run abc-123/i)).toBeInTheDocument()
    );
  });

  it('shows error message when the trigger throws', async () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockRejectedValue(new Error('timeout'));
    renderWithProviders(<EolSourcePanel />);
    screen.getByRole('button', { name: /run full eol refresh/i }).click();
    await waitFor(() =>
      expect(screen.getByText(/run full eol refresh failed.*timeout/i)).toBeInTheDocument()
    );
  });

  it('re-enables buttons after a job completes', async () => {
    vi.spyOn(api, 'triggerEolFullRefresh').mockResolvedValue(undefined as never);
    renderWithProviders(<EolSourcePanel />);
    const btn = screen.getByRole('button', { name: /run full eol refresh/i });
    btn.click();
    await waitFor(() => expect(btn).not.toBeDisabled());
  });
});
