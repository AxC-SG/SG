import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityConnectorConfig } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiSecurityConnectorPage } from './AiSecurityConnectorPage';

const CONFIG: AiSecurityConnectorConfig = {
  id: 'aws-ai-1',
  accountId: '123456789012',
  roleArn: 'arn:aws:iam::123456789012:role/ScoutAiSecurity',
  authMode: 'CROSS_ACCOUNT_ROLE',
  externalId: 'ext-123',
  regions: ['us-east-1'],
  enabled: true,
  createdAt: '2026-07-01T00:00:00Z',
  updatedAt: '2026-07-01T00:00:00Z',
};

describe('AiSecurityConnectorPage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('shows the initial setup form when the real API client receives JSON null', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('null', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
    renderWithProviders(<AiSecurityConnectorPage />);

    expect(await screen.findByText('Not configured')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save connection' })).toBeEnabled();
    expect(screen.getByLabelText('AWS account ID')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('hides the form behind a retry when the saved connection fails to load', async () => {
    vi.spyOn(api, 'getAiSecurityConnector').mockRejectedValue(new Error('connector service down'));
    vi.spyOn(api, 'listAiSecurityRuns').mockResolvedValue([]);
    renderWithProviders(<AiSecurityConnectorPage />);

    expect(await screen.findByRole('alert')).toHaveTextContent('The saved AWS Bedrock settings could not be loaded (connector service down)');
    expect(screen.queryByText('Not configured')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save connection' })).not.toBeInTheDocument();
  });

  it('reports a failed run list as an error, and acknowledges a save and a queued run separately', async () => {
    vi.spyOn(api, 'getAiSecurityConnector').mockResolvedValue(CONFIG);
    vi.spyOn(api, 'listAiSecurityRuns').mockRejectedValue(new Error('runs offline'));
    vi.spyOn(api, 'saveAiSecurityConnector').mockResolvedValue(CONFIG);
    vi.spyOn(api, 'runAiSecurityConnector').mockRejectedValue(new Error('A discovery run is already queued'));
    renderWithProviders(<AiSecurityConnectorPage />);

    expect(await screen.findByText('Discovery runs could not be loaded: runs offline.')).toBeInTheDocument();
    expect(screen.queryByText('No AI Security discovery runs yet.')).not.toBeInTheDocument();

    fireEvent.click(await screen.findByRole('button', { name: 'Save connection' }));
    expect(await screen.findByText('Connection saved.')).toHaveAttribute('role', 'status');

    fireEvent.click(screen.getByRole('button', { name: 'Run discovery' }));
    const failure = await screen.findByText('A discovery run is already queued');
    expect(failure).toHaveAttribute('role', 'alert');
    expect(screen.queryByText('Connection saved.')).not.toBeInTheDocument();
    expect(within(screen.getByRole('link', { name: 'View AI Inventory' }).closest('section')!).getByRole('button', { name: 'Retry' })).toBeInTheDocument();
  });
});
