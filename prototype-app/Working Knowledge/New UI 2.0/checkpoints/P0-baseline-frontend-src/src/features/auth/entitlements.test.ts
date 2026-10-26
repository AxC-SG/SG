import { describe, expect, it } from 'vitest';
import { canUseAnyAiFeature, canUseEntitlement } from './entitlements';
import type { ActorContext } from './types';

function actor(entitlements?: Record<string, boolean> | null): ActorContext {
  return {
    creator: false,
    principal: 'p',
    userId: 'u',
    tenantId: 't',
    tenantName: 'T',
    roles: [],
    entitlements: entitlements ?? undefined,
  };
}

describe('entitlements', () => {
  it('fails closed when the actor is null', () => {
    expect(canUseEntitlement(null, 'ai.security')).toBe(false);
    expect(canUseAnyAiFeature(null)).toBe(false);
  });

  it('fails closed when the entitlement snapshot is absent', () => {
    expect(canUseEntitlement(actor(), 'ai.security')).toBe(false);
    expect(canUseAnyAiFeature(actor())).toBe(false);
  });

  it('returns true only when the specific key is explicitly enabled', () => {
    expect(canUseEntitlement(actor({ 'ai.security': true }), 'ai.security')).toBe(true);
    expect(canUseEntitlement(actor({ 'ai.security': false }), 'ai.security')).toBe(false);
    expect(canUseEntitlement(actor({ 'ai.security': true }), 'ai.investigation_summary')).toBe(false);
  });

  it('canUseAnyAiFeature is true when any known AI key is enabled, false otherwise', () => {
    expect(canUseAnyAiFeature(actor({ 'ai.investigation_summary': true }))).toBe(true);
    expect(canUseAnyAiFeature(actor({ 'ai.security': true }))).toBe(true);
    expect(canUseAnyAiFeature(actor({ 'some.unrelated.key': true }))).toBe(false);
  });
});
