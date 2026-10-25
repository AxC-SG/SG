import { describe, expect, it } from 'vitest';
import type { ActorContext } from './types';
import {
  canAccessPlatformConsole,
  canManageInventorySources,
  canManageRiskPolicy,
  canManageServiceAccounts,
  canManageSourceFilters,
  canManageUsers,
  canRefreshTenantExposure,
  canRunSecurityWorkflow,
  canViewReadOnly
} from './roles';

function actor(roles: string[]): ActorContext {
  return {
    creator: false,
    principal: 'user@example.com',
    userId: 'user-1',
    tenantId: 'tenant-1',
    tenantName: 'Customer One',
    roles
  };
}

function platformScopeActor(roles: string[]): ActorContext {
  return {
    ...actor(roles),
    tenantId: null,
    tenantName: null,
    platformScope: true
  };
}

describe('role helpers', () => {
  it('keeps platform-owner operations separate from customer roles', () => {
    expect(canAccessPlatformConsole(actor(['PLATFORM_OWNER']))).toBe(true);
    expect(canAccessPlatformConsole(actor(['TENANT_ADMIN']))).toBe(false);
    expect(canAccessPlatformConsole(actor(['SECURITY_ANALYST']))).toBe(false);
  });

  it('maps tenant-owned configuration permissions by role', () => {
    expect(canManageUsers(actor(['PLATFORM_OWNER']))).toBe(false);
    expect(canManageUsers(actor(['TENANT_ADMIN']))).toBe(true);
    expect(canManageServiceAccounts(actor(['TENANT_ADMIN']))).toBe(true);
    expect(canManageServiceAccounts(actor(['PLATFORM_OWNER']))).toBe(false);
    expect(canManageRiskPolicy(actor(['INVENTORY_ADMIN']))).toBe(false);
    expect(canManageInventorySources(actor(['INVENTORY_ADMIN']))).toBe(true);
    expect(canManageUsers(actor(['INVENTORY_ADMIN']))).toBe(false);
    expect(canManageSourceFilters(actor(['SECURITY_ANALYST']))).toBe(true);
    expect(canRunSecurityWorkflow(actor(['SECURITY_ANALYST']))).toBe(true);
    expect(canRefreshTenantExposure(actor(['SECURITY_ANALYST']))).toBe(true);
    expect(canManageInventorySources(actor(['SECURITY_ANALYST']))).toBe(false);
    expect(canManageRiskPolicy(actor(['SECURITY_ANALYST']))).toBe(false);
  });

  it('allows platform-scope owners to manage vulnerability source filters', () => {
    expect(canManageSourceFilters(platformScopeActor(['PLATFORM_OWNER']))).toBe(true);
    expect(canManageRiskPolicy(platformScopeActor(['PLATFORM_OWNER']))).toBe(false);
  });

  it('allows read-only actors to view but not mutate', () => {
    const readOnly = actor(['READ_ONLY_AUDITOR']);
    expect(canViewReadOnly(readOnly)).toBe(true);
    expect(canManageUsers(readOnly)).toBe(false);
    expect(canManageInventorySources(readOnly)).toBe(false);
    expect(canRunSecurityWorkflow(readOnly)).toBe(false);
  });
});
