import React from 'react';
import type { ActorContext } from './types';

export const ActorContextState = React.createContext<ActorContext | null>(null);

export function useActor(): ActorContext | null {
  return React.useContext(ActorContextState);
}
