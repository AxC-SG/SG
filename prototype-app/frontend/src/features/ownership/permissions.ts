import { hasAnyRole } from '../auth/roles';
import type { ActorContext } from '../auth/types';

// Visibility only, mirroring the backend OwnershipAuthorization matrix (plan §5). The server enforces every action;
// hiding a control here never grants or removes access.

const ADMINS = ['TENANT_ADMIN', 'INVENTORY_ADMIN'];

export function canViewDirectory(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, [...ADMINS, 'SECURITY_ANALYST']);
}

export function canWriteDirectory(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN']);
}

export function canImportDirectory(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN']);
}

export function canWriteTeams(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}

export function canResolveReview(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}

export function canManageOwnershipEncryption(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN']);
}

export function canManageOwnershipAuthority(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN']);
}
