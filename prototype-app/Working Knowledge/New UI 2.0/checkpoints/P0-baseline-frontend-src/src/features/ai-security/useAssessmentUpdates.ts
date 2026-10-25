import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { api } from '../../api/client';
import { invalidateAiAssessmentQueries, shouldPollAiRuns } from './assessment';

/** Collection completion keeps polling until assessment delivery also reaches a terminal state. */
export function useAssessmentUpdates() {
  const client = useQueryClient();
  const runs = useQuery({
    queryKey: ['ai-security-runs'],
    queryFn: () => api.listAiSecurityRuns(),
    refetchInterval: (query) => shouldPollAiRuns(query.state.data) ? 5000 : false,
  });
  const signature = (runs.data ?? []).map((run) => `${run.id}:${run.assessmentStatus}:${run.assessedSubjects}:${run.failedPolicies}`).join('|');
  const previous = useRef(signature);
  useEffect(() => {
    if (previous.current !== signature) {
      previous.current = signature;
      void invalidateAiAssessmentQueries(client);
    }
  }, [client, signature]);
  return runs;
}
