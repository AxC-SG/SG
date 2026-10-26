import type { ActorContext } from './types';

const AI_ENTITLEMENT_KEYS = [
  'ai.investigation_summary',
  'ai.solution_generation',
  'ai.required_actions',
  'ai.fix_generation',
  'ai.investigation_agent',
  'ai.upgrade_recommendation',
  'ai.security',
] as const;

/**
 * Fails closed: an entitlement is usable only when the backend snapshot explicitly enables it.
 * An absent snapshot (platform/null scope, or a fixture without entitlements) resolves to false.
 */
export function canUseEntitlement(actor: ActorContext | null, entitlementKey: string): boolean {
  return actor?.entitlements?.[entitlementKey] === true;
}

export function canUseAnyAiFeature(actor: ActorContext | null): boolean {
  return AI_ENTITLEMENT_KEYS.some((key) => actor?.entitlements?.[key] === true);
}
