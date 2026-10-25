import { screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AuditEvent, AuthContext, ServiceAccount, TenantMember } from '../features/admin/types';
import { renderWithProviders } from '../test/test-utils';
import { UserManagementPage } from './UserManagementPage';

const AUTH_CONTEXT: AuthContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-1',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_TENANT_ADMIN'],
};

function buildMember(overrides: Partial<TenantMember> = {}): TenantMember {
  return {
    id: 'member-1',
    userId: 'user-2',
    subject: 'jane.doe',
    email: 'jane.doe@example.com',
    displayName: 'Jane Doe',
    role: 'TENANT_ADMIN',
    status: 'ACTIVE',
    createdAt: '2026-04-01T00:00:00Z',
    ...overrides,
  };
}

function buildServiceAccount(overrides: Partial<ServiceAccount> = {}): ServiceAccount {
  return {
    id: 'svc-1',
    tenantId: 'tenant-1',
    name: 'CI Pipeline',
    keyId: 'svc-ci-pipeline',
    role: 'ANALYST',
    status: 'ACTIVE',
    createdAt: '2026-04-01T00:00:00Z',
    lastUsedAt: '2026-04-25T00:00:00Z',
    ...overrides,
  };
}

function buildAuditEvent(overrides: Partial<AuditEvent> = {}): AuditEvent {
  return {
    id: 'audit-1',
    occurredAt: '2026-04-25T00:00:00Z',
    tenantId: 'tenant-1',
    actorSubject: 'jane.doe',
    actorRole: 'TENANT_ADMIN',
    action: 'tenant_member.invite',
    targetType: 'tenant_member',
    targetId: 'member-2',
    outcome: 'success',
    detailsJson: null,
    ...overrides,
  };
}

describe('UserManagementPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders the default Users section and tenant caption when authed', async () => {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue(AUTH_CONTEXT);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([buildMember()]);
    vi.spyOn(api, 'listTenantInvites').mockResolvedValue([]);
    vi.spyOn(api, 'listServiceAccounts').mockResolvedValue([]);
    vi.spyOn(api, 'listAuditEvents').mockResolvedValue([]);

    renderWithProviders(<UserManagementPage />);

    // Section navigation (Users/Invites/Roles & Permissions/Service Accounts/Audit) now lives
    // in the primary sidebar rail (see App.tsx), not inside this page — this page renders only
    // the active section's content, driven by the :adminView route param.
    expect(await screen.findByRole('heading', { name: 'Members' })).toBeInTheDocument();

    // Caption shows tenant name + counts once auth + members resolve.
    // The caption is one concatenated string — match the whole expected shape.
    await waitFor(() => {
      expect(screen.getByText(/Acme Security.*1 member/)).toBeInTheDocument();
    });
  });

  it('renders a member row in the Users table when members are loaded', async () => {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue(AUTH_CONTEXT);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([
      buildMember({ displayName: 'Jane Doe', email: 'jane.doe@example.com', subject: 'jane.doe' }),
    ]);
    vi.spyOn(api, 'listTenantInvites').mockResolvedValue([]);
    vi.spyOn(api, 'listServiceAccounts').mockResolvedValue([]);
    vi.spyOn(api, 'listAuditEvents').mockResolvedValue([]);

    renderWithProviders(<UserManagementPage />);

    expect((await screen.findAllByText('Jane Doe')).length).toBeGreaterThan(0);
    expect(screen.getAllByText('jane.doe@example.com').length).toBeGreaterThan(0);
    expect(screen.getAllByText('jane.doe').length).toBeGreaterThan(0);
    expect(screen.getByRole('columnheader', { name: 'User' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Role' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Subject' })).toBeInTheDocument();
    expect(screen.getByLabelText('Filter members by role')).toBeInTheDocument();
    expect(screen.getByText('Suspend')).toBeInTheDocument();
  });

  it('shows the workspace-unavailable notice when no tenantId is resolved', async () => {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue({
      ...AUTH_CONTEXT,
      tenantId: null,
      tenantName: null,
    });
    // Members query is gated by tenantId, so it shouldn't fire — but stub for safety
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([]);
    vi.spyOn(api, 'listTenantInvites').mockResolvedValue([]);
    vi.spyOn(api, 'listServiceAccounts').mockResolvedValue([]);
    vi.spyOn(api, 'listAuditEvents').mockResolvedValue([]);

    renderWithProviders(<UserManagementPage />);

    await waitFor(() => {
      expect(screen.getByText(/Workspace unavailable/i)).toBeInTheDocument();
    });
    // The Invite user button should be hidden when actor lacks permission via missing tenant context;
    // even when shown, it should be disabled when tenantId is null. Validate at least one of those.
    const inviteButton = screen.queryByRole('button', { name: /Invite user/ });
    if (inviteButton) {
      expect(inviteButton).toBeDisabled();
    }
  });

  it('uses serviceAccounts data — switching to Service Accounts tab', async () => {
    vi.spyOn(api, 'getAuthContext').mockResolvedValue(AUTH_CONTEXT);
    vi.spyOn(api, 'listTenantMembers').mockResolvedValue([]);
    vi.spyOn(api, 'listTenantInvites').mockResolvedValue([]);
    vi.spyOn(api, 'listServiceAccounts').mockResolvedValue([buildServiceAccount()]);
    vi.spyOn(api, 'listAuditEvents').mockResolvedValue([buildAuditEvent()]);

    renderWithProviders(<UserManagementPage />);

    // Caption reflects fetched counts
    await waitFor(() => {
      expect(screen.getByText(/1 service account\b/)).toBeInTheDocument();
    });
    expect(screen.getByText(/1 event\b/)).toBeInTheDocument();
  });
});
