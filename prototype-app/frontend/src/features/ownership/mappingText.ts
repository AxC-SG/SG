import type { GroupMappingChange } from './types';

const SKIP_REASONS: Record<string, string> = {
  LARGE_CHANGE_NEXT_CMDB_SYNC: 'More than 10,000 CIs are affected, so the next CMDB sync applies the change.',
  PRODUCER_DISABLED: 'The ServiceNow ownership producer is off, so claims update when it is enabled.',
  DOMAIN_LEGACY: 'Core ownership is still legacy, so claims are not published yet.',
  SOURCE_PAUSED: 'ServiceNow ownership is paused by the kill switch, so claims update when it is lifted.'
};

/** Explains a change result for the success message. */
export function describeMappingChange(result: GroupMappingChange): string {
  if (result.republishSkipped) return SKIP_REASONS[result.republishSkipped] ?? `Claims were not republished (${result.republishSkipped}).`;
  return result.republishedCis > 0 ? `${result.republishedCis.toLocaleString()} CI(s) republished.` : 'No CMDB CI references this group yet.';
}
