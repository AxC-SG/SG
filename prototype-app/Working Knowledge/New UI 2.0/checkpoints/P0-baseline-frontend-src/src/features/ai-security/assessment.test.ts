import { describe, expect, it } from 'vitest';
import { assessmentMessage, shouldPollAiRuns } from './assessment';

describe('AI assessment completion', () => {
  it('keeps polling after collection completes while assessment is pending or running', () => {
    expect(shouldPollAiRuns([{ status: 'COMPLETED', assessmentStatus: 'PENDING' }])).toBe(true);
    expect(shouldPollAiRuns([{ status: 'COMPLETED', assessmentStatus: 'RUNNING' }])).toBe(true);
    expect(shouldPollAiRuns([{ status: 'COMPLETED', assessmentStatus: 'PARTIAL' }])).toBe(false);
    expect(shouldPollAiRuns([{ status: 'COMPLETED', assessmentStatus: 'FAILED' }])).toBe(false);
  });
  it('reports actual assessed subjects and partial failures', () => {
    expect(assessmentMessage({ assessmentStatus: 'COMPLETE', assessedSubjects: 4 })).toContain('4 subjects assessed');
    expect(assessmentMessage({ assessmentStatus: 'PARTIAL', assessedSubjects: 3, failedPolicies: 2 })).toContain('3 subjects assessed; 2 policies failed');
    expect(assessmentMessage({ assessmentStatus: 'PENDING' })).toContain('pending');
  });
});
