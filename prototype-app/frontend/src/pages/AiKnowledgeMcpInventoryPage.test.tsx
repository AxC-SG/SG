import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiSecurityArtifact } from '../features/ai-security/types';
import { renderWithProviders } from '../test/test-utils';
import { AiKnowledgeMcpInventoryPage } from './AiKnowledgeMcpInventoryPage';

function buildItem(overrides: Partial<AiSecurityArtifact> = {}): AiSecurityArtifact {
  return {
    id: 'kb-1',
    provider: 'AWS',
    providerResourceId: 'arn:aws:bedrock:us-east-1:123456789012:knowledge-base/kb-1',
    artifactType: 'KNOWLEDGE_BASE',
    nativeKind: 'AWS_BEDROCK_KNOWLEDGE_BASE',
    name: 'claims-kb',
    accountId: '123456789012',
    region: 'us-east-1',
    active: true,
    attributes: { sourceType: 'S3' },
    ownerName: null,
    ownerState: 'UNOWNED',
    ownerSource: null,
    ownerConfidence: null,
    ownerConfidenceMethod: null,
    ownerConfidenceMethodVersion: null,
    businessCriticality: null,
    environment: null,
    firstObservedAt: '2026-08-01T00:00:00Z',
    lastObservedAt: '2026-08-01T00:00:00Z',
    piiScanStatus: 'NOT_SCANNED',
    piiSource: null,
    piiInfoTypes: [],
    piiFindingCount: 0,
    piiLastScannedAt: null,
    attachmentState: 'ROOT',
    systemIds: [],
    ...overrides,
  };
}

describe('AiKnowledgeMcpInventoryPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('links each artifact name to its detail page and states the visible scope', async () => {
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({} as Awaited<ReturnType<typeof api.getAiSecuritySummary>>);
    vi.spyOn(api, 'listAiKnowledgeDataInventory').mockResolvedValue({ items: [buildItem()], page: 0, size: 50, total: 1 });

    renderWithProviders(<AiKnowledgeMcpInventoryPage kind="knowledge-data" />, { route: '/inventory/ai/knowledge-data' });

    const link = await screen.findByRole('link', { name: 'claims-kb' });
    expect(link).toHaveAttribute('href', '/inventory/ai/kb-1?returnTo=%2Finventory%2Fai%2Fknowledge-data');
    expect(screen.getByText('Showing 1–1 of 1 artifact')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Knowledge and data inventory pages' })).toHaveTextContent('Page 1 of 1');
  });

  it('offers retry on failure and separates a filtered-empty result from no discovered artifacts', async () => {
    vi.spyOn(api, 'getAiSecuritySummary').mockResolvedValue({} as Awaited<ReturnType<typeof api.getAiSecuritySummary>>);
    vi.spyOn(api, 'listAiMcpInventory')
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValue({ items: [], page: 0, size: 50, total: 0 });

    renderWithProviders(<AiKnowledgeMcpInventoryPage kind="mcp" />, { route: '/inventory/ai/mcp?artifactRole=MCP_SERVER' });

    expect(await screen.findByRole('alert')).toHaveTextContent('Inventory could not be loaded.');
    fireEvent.click(screen.getByRole('button', { name: 'Retry inventory' }));

    expect(await screen.findByText('No MCP artifacts match the current filters.')).toBeInTheDocument();
    expect(screen.queryByText('No MCP artifacts discovered')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByText('No MCP artifacts discovered')).toBeInTheDocument();
  });
});
