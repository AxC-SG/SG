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

/** VIEW_IDENTITY_SOURCE: the Sources view. */
export function canViewIdentitySources(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}

/** CONFIGURE_IDENTITY_SOURCE: configure, test, preview, enable, sync now, resume and disable. */
export function canConfigureIdentitySource(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ['TENANT_ADMIN']);
}

/** PAUSE_SOURCE. */
export function canPauseIdentitySource(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}

/** MAP_GROUPS: preview, activate, retire and dismiss group-to-team mappings. Reading them needs VIEW_OWNERSHIP. */
export function canMapGroups(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}

/** CONFIGURE_OWNERSHIP_PRODUCER: the AWS/GCP producer's key and account-input switches. */
export function canConfigureOwnershipProducer(actor: ActorContext | null): boolean {
  return hasAnyRole(actor, ADMINS);
}
