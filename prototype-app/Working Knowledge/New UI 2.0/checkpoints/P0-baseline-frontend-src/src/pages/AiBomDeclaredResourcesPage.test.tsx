import { screen, fireEvent, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiBomDeclaredResource, BomSetupAction } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { AiBomDeclaredResourcesPage } from './AiBomDeclaredResourcesPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

function buildResource(overrides: Partial<AiBomDeclaredResource> = {}): AiBomDeclaredResource {
  return {
    id: 'resource-1',
    sourceId: 'source-1',
    bomId: 'bom-1',
    bomComponentId: 'component-1',
    resourceKind: 'MODEL',
    name: 'llama-3',
    version: '3.1',
    identityKind: 'VERSIONED_IDENTIFIER',
    identityValue: 'llama-3@3.1',
    deploymentState: 'UNVERIFIED',
    linkedArtifactId: null,
    linkMethod: null,
    linkReviewedBy: null,
    linkReviewedAt: null,
    proposedArtifactId: null,
    proposedBy: null,
    proposedAt: null,
    firstDeclaredAt: '2026-08-01T00:00:00Z',
    lastDeclaredAt: '2026-08-01T00:00:00Z',
    ...overrides,
  };
}

function buildSetupAction(overrides: Partial<BomSetupAction> = {}): BomSetupAction {
  return {
    category: 'UNLINKED',
    priority: 'MEDIUM',
    title: 'Unverified declared resource: llama-3',
    detail: 'This declared resource has not been matched to a real deployment yet.',
    evidenceId: 'resource-1',
    ...overrides,
  };
}

describe('AiBomDeclaredResourcesPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('renders coverage setup actions and declared resources', async () => {
    vi.spyOn(api, 'listAiBomSetupActions').mockResolvedValue([buildSetupAction()]);
    vi.spyOn(api, 'listAiBomDeclaredResources').mockResolvedValue([buildResource()]);

    renderWithProviders(<AiBomDeclaredResourcesPage />, { route: '/inventory/ai/declared-resources' });

    expect(await screen.findByText('Unverified declared resource: llama-3')).toBeInTheDocument();
    expect(screen.getAllByText('llama-3').length).toBeGreaterThan(0);
  });

  it('navigates to the declared resource detail page when a setup action is clicked', async () => {
    vi.spyOn(api, 'listAiBomSetupActions').mockResolvedValue([buildSetupAction()]);
    vi.spyOn(api, 'listAiBomDeclaredResources').mockResolvedValue([]);

    renderWithProviders(<AiBomDeclaredResourcesPage />, { route: '/inventory/ai/declared-resources' });

    fireEvent.click(await screen.findByText('Unverified declared resource: llama-3'));

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith('/inventory/ai/declared-resources/resource-1'));
  });

  it('shows an empty state when nothing has been declared', async () => {
    vi.spyOn(api, 'listAiBomSetupActions').mockResolvedValue([]);
    vi.spyOn(api, 'listAiBomDeclaredResources').mockResolvedValue([]);

    renderWithProviders(<AiBomDeclaredResourcesPage />, { route: '/inventory/ai/declared-resources' });

    expect(await screen.findByText('No AI-BOM has declared a model or dataset yet.')).toBeInTheDocument();
    expect(screen.getByText('No outstanding AI-BOM coverage work.')).toBeInTheDocument();
  });
});
