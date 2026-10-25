import React from 'react';
import { useActorQuery } from './queries';
import { ActorContextState } from './context';

export function ActorProvider({ children }: { children: React.ReactNode }) {
  const actorQuery = useActorQuery();

  return (
    <ActorContextState.Provider value={actorQuery.data ?? null}>
      {children}
    </ActorContextState.Provider>
  );
}
