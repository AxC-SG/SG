import { describe, expect, it } from 'vitest';
import {
  isCanonicalOwnership,
  lacksResolvedOwner,
  ownershipAssignmentKind,
  resolvedOwnerLabel,
  type ResolvedOwnership
} from './resolvedOwnership';

const canonical = (overrides: Partial<ResolvedOwnership> = {}): ResolvedOwnership => ({
  objectId: 'a-1',
  authorityDomain: 'CORE',
  authorityState: 'CANONICAL',
  ownerTeamId: 't-1',
  ownerTeamName: 'Payments',
  ownershipStatus: 'OWNED',
  inheritanceDepth: 0,
  ...overrides
});

describe('resolved ownership helpers', () => {
  it('treats only CANONICAL envelopes as resolved', () => {
    expect(isCanonicalOwnership(canonical())).toBe(true);
    expect(isCanonicalOwnership(canonical({ authorityState: 'LEGACY_PENDING_MIGRATION' }))).toBe(false);
    expect(isCanonicalOwnership(null)).toBe(false);
    expect(isCanonicalOwnership(undefined)).toBe(false);
  });

  it('labels every resolver status without falling back to raw evidence', () => {
    expect(resolvedOwnerLabel(canonical())).toBe('Payments');
    expect(resolvedOwnerLabel(canonical({ ownershipStatus: 'UNOWNED', ownerTeamName: null }))).toBe('Unowned');
    expect(resolvedOwnerLabel(canonical({ ownershipStatus: 'CONFLICT', ownerTeamName: null }))).toBe('Ownership conflict');
    expect(resolvedOwnerLabel(canonical({ ownershipStatus: null, ownerTeamName: null, legacyOwnerLabel: 'raw' }))).toBe(
      'Refreshing ownership'
    );
  });

  it('flags missing owners and describes direct versus inherited assignment', () => {
    expect(lacksResolvedOwner(canonical())).toBe(false);
    expect(lacksResolvedOwner(canonical({ ownershipStatus: 'CONFLICT' }))).toBe(true);
    expect(ownershipAssignmentKind(canonical())).toBe('Direct');
    expect(ownershipAssignmentKind(canonical({ inheritanceDepth: 1 }))).toBe('Inherited (1 level up)');
    expect(ownershipAssignmentKind(canonical({ inheritanceDepth: 3 }))).toBe('Inherited (3 levels up)');
    expect(ownershipAssignmentKind(canonical({ ownershipStatus: 'UNOWNED' }))).toBeUndefined();
  });
});
