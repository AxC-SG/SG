import { describe, expect, it } from 'vitest';
import {
  defaultAssetTypeForView,
  normalizeHostReviewCategory
} from './helpers';

describe('inventory helpers', () => {
  it('maps views to scoped asset types', () => {
    expect(defaultAssetTypeForView('hosts')).toBe('HOST');
    expect(defaultAssetTypeForView('container-images')).toBe('CONTAINER_IMAGE');
    expect(defaultAssetTypeForView('software-identities')).toBe('ALL');
  });

  it('normalizes host review category aliases', () => {
    expect(normalizeHostReviewCategory('missing version')).toBe('MISSING_VERSION');
    expect(normalizeHostReviewCategory('low-confidence-alias')).toBe('LOW_CONFIDENCE_ALIAS');
    expect(normalizeHostReviewCategory('unknown')).toBeNull();
  });
});
