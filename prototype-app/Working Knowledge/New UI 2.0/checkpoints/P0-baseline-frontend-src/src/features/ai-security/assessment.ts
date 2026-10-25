import type { QueryClient } from '@tanstack/react-query';
import type { AiAssessmentProcessing } from './types';

export function assessmentPending(value: AiAssessmentProcessing | undefined): boolean {
  return value?.assessmentStatus === 'PENDING' || value?.assessmentStatus === 'RUNNING';
}

export function shouldPollAiRuns(runs: Array<AiAssessmentProcessing & { status: string }> | undefined): boolean {
  return (runs ?? []).some((run) => assessmentPending(run)
    || ['RUNNING', 'STARTED', 'QUEUED'].includes(run.status.trim().toUpperCase()));
}

export function assessmentMessage(value: AiAssessmentProcessing): string {
  const subjects = value.assessedSubjects ?? 0;
  switch (value.assessmentStatus) {
    case 'PENDING': return 'Configuration accepted. Assessment is pending.';
    case 'RUNNING': return 'Configuration accepted. Assessment is running.';
    case 'PARTIAL': return `Assessment partially completed: ${subjects} subjects assessed; ${value.failedPolicies ?? 0} policies failed.`;
    case 'FAILED': return `Assessment failed; ${value.failedPolicies ?? 0} policies need attention.`;
    case 'COMPLETE': return `Assessment completed: ${subjects} subjects assessed.`;
    default: return 'Configuration accepted. Assessment results will refresh shortly.';
  }
}

export function invalidateAiAssessmentQueries(client: QueryClient): Promise<void[]> {
  return Promise.all([
    'ai-grid-policies', 'ai-security-policies', 'ai-security-policy-configuration',
    'ai-security-runs', 'ai-security-findings', 'ai-security-findings-for-policy',
    'ai-assessment-states-latest', 'ai-grid-coverage', 'ai-framework-coverage',
    'ai-grid-exposures', 'ai-action-queue', 'findings',
  ].map((key) => client.invalidateQueries({ queryKey: [key] })));
}
