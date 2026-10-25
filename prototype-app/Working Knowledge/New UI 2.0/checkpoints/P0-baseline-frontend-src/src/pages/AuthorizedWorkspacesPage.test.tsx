import { render, screen } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import { createTestQueryClient } from '../test/test-utils';
import { AuthorizedWorkspacesPage } from './AuthorizedWorkspacesPage';

afterEach(() => vi.restoreAllMocks());

it('shows only server-authorized workspaces and labels the bootstrap workspace as Open Playground', async () => {
  vi.spyOn(api, 'listAuthorizedWorkspaces').mockResolvedValue([{
    id: 'playground-id',
    name: 'Default Workspace',
    slug: 'default-workspace',
    role: 'TENANT_ADMIN',
    accessMode: 'DIRECT_PLAYGROUND_MEMBERSHIP',
    accessReferenceId: 'membership-id',
    expiresAt: null,
    revocable: false
  }]);
  vi.spyOn(api, 'listInvitedSupportGrants').mockResolvedValue([{
    id: 'grant-id',
    tenantId: 'customer-id',
    tenantName: 'Customer Approved Co',
    invitedPlatformSubject: 'owner-subject',
    reason: 'Incident response',
    scope: null,
    accessMode: 'READ_ONLY',
    status: 'PENDING',
    grantedBySubject: 'tenant-admin',
    acceptedBySubject: null,
    revokedBySubject: null,
    requestedAt: '2026-07-22T00:00:00Z',
    acceptedAt: null,
    expiresAt: '2026-07-23T00:00:00Z',
    revokedAt: null
  }]);

  render(
    <QueryClientProvider client={createTestQueryClient()}>
      <ActorContextState.Provider value={{
        creator: true,
        principal: 'owner@example.com',
        userId: 'owner-subject',
        tenantId: null,
        tenantName: null,
        roles: ['PLATFORM_OWNER'],
        platformScope: true
      }}>
        <MemoryRouter><AuthorizedWorkspacesPage /></MemoryRouter>
      </ActorContextState.Provider>
    </QueryClientProvider>
  );

  expect(await screen.findAllByText('Open Playground')).toHaveLength(2);
  expect(screen.getByText('Customer Approved Co')).toBeInTheDocument();
  expect(screen.queryByText('Inaccessible Customer')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Accept' })).toBeInTheDocument();
});
