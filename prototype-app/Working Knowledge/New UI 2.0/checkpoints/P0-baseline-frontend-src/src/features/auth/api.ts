import { apiRequest } from '../../api/client';
import type { ActorContext } from './types';

export const authApi = {
  getActorContext: () => apiRequest<ActorContext>('/me')
};
