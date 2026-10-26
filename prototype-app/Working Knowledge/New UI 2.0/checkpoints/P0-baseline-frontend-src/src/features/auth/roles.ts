import type { ActorContext } from './types';

function isPlatformScopeOnly(actor: ActorContext | null): boolean {
  return hasRole(actor, 'PLATFORM_OWNER') && !!actor?.platformScope;
}

export function hasRole(actor: ActorContext | null, role: string): boolean {
  const normalized = normalizeRole(role);
  return (actor?.roles ?? []).some((candidate) => normalizeRole(candidate) === normalized);
}

export function hasAnyRole(actor: ActorContext | null, roles: string[]): boolean {
  return roles.some((role) => hasRole(actor, role));
}

export function canManageTenant(actor: ActorContext | null): boolean {
  return hasRole(actor, 'TENANT_ADMIN');
}

export function canAccessPlatformConsole(actor: ActorContext | null): boolean {
  return hasRole(actor, 'PLATFORM_OWNER');
}

export function canManageUsers(actor: ActorContext | null): boolean {
  return hasRole(actor, 'TENANT_ADMIN');
}

export function canManageServiceAccounts(actor: ActorContext | null): boolean {
  return hasRole(actor, 'TENANT_ADMIN');
}

export function canExportAudit(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN', 'READ_ONLY_AUDITOR']);
}

export function canManageInventorySources(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN', 'INVENTORY_ADMIN']);
}

export function canManageRiskPolicy(actor: ActorContext | null): boolean {
  return !isPlatformScopeOnly(actor) && hasAnyRole(actor, ['PLATFORM_OWNER', 'TENANT_ADMIN']);
}

export function canRunSecurityWorkflow(actor: ActorContext | null): boolean {
  return !isPlatformScopeOnly(actor) && hasAnyRole(actor, ['PLATFORM_OWNER', 'TENANT_ADMIN', 'SECURITY_ANALYST']);
}

export function canRefreshTenantExposure(actor: ActorContext | null): boolean {
  return !isPlatformScopeOnly(actor) && hasAnyRole(actor, ['PLATFORM_OWNER', 'TENANT_ADMIN', 'SECURITY_ANALYST']);
}

export function canManageSourceFilters(actor: ActorContext | null): boolean {
  return hasRole(actor, 'PLATFORM_OWNER')
    || (!isPlatformScopeOnly(actor) && hasAnyRole(actor, ['TENANT_ADMIN', 'SECURITY_ANALYST']));
}

export function canViewReadOnly(actor: ActorContext | null): boolean {
  return actor != null && actor.roles.length > 0 && !isPlatformScopeOnly(actor);
}

function normalizeRole(role: string): string {
  return role.replace(/^ROLE_/, '').trim().toUpperCase().replace(/[-\s]+/g, '_');
}
