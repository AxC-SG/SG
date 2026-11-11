import { api, ApiError, apiRequest } from '../../api/client';
import { getManagedWorkspace, managedBrowserAuthEnabled, setManagedWorkspace } from './managedSession';
import type { ActorContext } from './types';

async function getManagedActorContext(): Promise<ActorContext> {
  const workspace = getManagedWorkspace();
  let actor: ActorContext;
  try {
    actor = await api.getManagedAuthContext(workspace);
  } catch (error) {
    if (!workspace || !(error instanceof ApiError) || error.status !== 403 || getManagedWorkspace() !== workspace) {
      throw error;
    }
    actor = await api.getManagedAuthContext(null);
    if (getManagedWorkspace() === workspace) setManagedWorkspace(null);
  }
  if (actor.tenantId || actor.roles.includes('PLATFORM_OWNER') || actor.allowedTenants?.length !== 1) return actor;

  const tenantId = actor.allowedTenants[0].id;
  const scoped = await api.getManagedAuthContext(tenantId);
  if (scoped.tenantId !== tenantId) throw new Error('Could not open the authorized workspace.');
  setManagedWorkspace(tenantId);
  return scoped;
}

export const authApi = {
  getActorContext: () => managedBrowserAuthEnabled ? getManagedActorContext() : apiRequest<ActorContext>('/me')
};
